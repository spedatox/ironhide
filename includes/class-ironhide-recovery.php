<?php
/**
 * Lockout-recovery measures.
 *
 * The whole point of this class is to guarantee there is always a way back in.
 * The guard is fail-open (empty allowlist => nothing blocked), and on top of
 * that there are five independent recovery paths, any one of which is enough:
 *
 *   1. Monitor mode (observe without blocking)     — Settings screen
 *   2. IRONHIDE_DISABLE constant (full off)        — wp-config.php
 *   3. Emergency marker file                       — FTP/SSH/file manager
 *   4. IRONHIDE_BYPASS_KEY constant (URL + cookie) — wp-config.php + browser
 *   5. WP-CLI commands                             — shell access
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Recovery helpers.
 */
class Ironhide_Recovery {

	const QUERY_KEY    = 'ironhide_bypass';
	const COOKIE_NAME  = 'ironhide_bypass';
	const COOKIE_TTL   = 900; // 15 minutes.
	const DISABLE_FILE = 'ironhide-emergency-disable';

	/**
	 * Whether this request supplied a bypass value that did not match.
	 *
	 * Recorded so the block log can distinguish "wandered in" from "tried the
	 * recovery key and got it wrong", without ever writing the attempted value.
	 *
	 * @var bool
	 */
	private static $failed_attempt = false;

	/**
	 * Did this request present an incorrect bypass key?
	 *
	 * @return bool
	 */
	public static function had_failed_attempt() {
		return self::$failed_attempt;
	}

	/**
	 * Reset the failed-attempt flag (test helper).
	 *
	 * @return void
	 */
	public static function reset_failed_attempt() {
		self::$failed_attempt = false;
	}

	/**
	 * Hard disable: IRONHIDE_DISABLE constant or the emergency marker file.
	 *
	 * @return bool
	 */
	public static function hard_disabled() {
		if ( defined( 'IRONHIDE_DISABLE' ) && IRONHIDE_DISABLE ) {
			return true;
		}

		$file = self::disable_file_path();
		if ( '' !== $file && file_exists( $file ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Absolute path of the emergency marker file, or ''.
	 *
	 * @return string
	 */
	public static function disable_file_path() {
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			return '';
		}
		return trailingslashit( WP_CONTENT_DIR ) . self::DISABLE_FILE;
	}

	/**
	 * The configured bypass key (empty when none).
	 *
	 * @return string
	 */
	public static function bypass_key() {
		if ( defined( 'IRONHIDE_BYPASS_KEY' ) && is_string( IRONHIDE_BYPASS_KEY ) && '' !== IRONHIDE_BYPASS_KEY ) {
			return IRONHIDE_BYPASS_KEY;
		}
		return '';
	}

	/**
	 * Is the current request carrying a valid bypass?
	 *
	 * A valid URL key both lets this request through and drops a short-lived,
	 * signed cookie so subsequent admin navigation also passes while the
	 * operator fixes the allowlist.
	 *
	 * @return bool
	 */
	public static function is_bypassed() {
		$key = self::bypass_key();

		if ( '' !== $key && isset( $_GET[ self::QUERY_KEY ] ) && is_string( $_GET[ self::QUERY_KEY ] ) ) {
			// wp_unslash() undoes WP's magic-quotes so a key containing a quote
			// or backslash still compares equal to the constant.
			$provided = wp_unslash( $_GET[ self::QUERY_KEY ] );

			// Constant-time compare against the configured secret.
			if ( is_string( $provided ) && hash_equals( $key, $provided ) ) {
				self::set_bypass_cookie();
				return true;
			}

			self::$failed_attempt = true;
		}

		return self::has_valid_cookie();
	}

	/**
	 * Whether the browser carries a fresh, correctly-signed bypass cookie.
	 *
	 * @return bool
	 */
	public static function has_valid_cookie() {
		// Cookie recovery is only armed once an operator has configured a
		// bypass key. With no key, cookies are never accepted, so a missing or
		// placeholder AUTH_SALT cannot be turned into a forgeable cookie.
		if ( '' === self::bypass_key() ) {
			return false;
		}

		if ( empty( $_COOKIE[ self::COOKIE_NAME ] ) || ! is_string( $_COOKIE[ self::COOKIE_NAME ] ) ) {
			return false;
		}

		$parts = explode( '.', $_COOKIE[ self::COOKIE_NAME ] );
		if ( 3 !== count( $parts ) ) {
			return false;
		}

		list( $ts, $payload, $sig ) = $parts;

		if ( ! ctype_digit( $ts ) ) {
			return false;
		}
		$ts = (int) $ts;

		// Reject expired cookies and obviously future timestamps.
		if ( ( time() - $ts ) > self::COOKIE_TTL || $ts > ( time() + 60 ) ) {
			return false;
		}

		return hash_equals( self::cookie_signature( (string) $ts, $payload ), $sig );
	}

	/**
	 * Drop a signed bypass cookie for the current browser.
	 *
	 * @return bool
	 */
	public static function set_bypass_cookie() {
		$ts      = (string) time();
		$payload = wp_generate_password( 16, false, false );
		$value   = $ts . '.' . $payload . '.' . self::cookie_signature( $ts, $payload );

		// Populate the superglobal first so the rest of *this* request behaves
		// consistently even when the cookie cannot be persisted to the browser.
		$_COOKIE[ self::COOKIE_NAME ] = $value;

		if ( headers_sent() ) {
			return false;
		}

		setcookie( self::COOKIE_NAME, $value, self::cookie_options( time() + self::COOKIE_TTL ) );

		return true;
	}

	/**
	 * Shared cookie options.
	 *
	 * @param int $expires Expiry timestamp.
	 * @return array
	 */
	private static function cookie_options( $expires ) {
		return array(
			'expires'  => $expires,
			'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
			'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);
	}

	/**
	 * HMAC signature so a cookie cannot be forged without the site salts.
	 *
	 * @param string $ts      Timestamp.
	 * @param string $payload Random payload.
	 * @return string
	 */
	public static function cookie_signature( $ts, $payload ) {
		// wp_salt('auth') safely falls back when AUTH_SALT is undefined, empty
		// or left at the placeholder value — unlike reading AUTH_SALT directly.
		return hash_hmac( 'sha256', $ts . '.' . $payload, 'ironhide_bypass|' . wp_salt( 'auth' ) );
	}
}
