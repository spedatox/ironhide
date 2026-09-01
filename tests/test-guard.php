<?php
/**
 * Enforcement / recovery logic tests with a minimal WordPress stub.
 *
 * Does NOT test a live WordPress install — it stubs the handful of WP functions
 * the classes call and verifies the decision logic (fail open, monitor, bypass,
 * deny, ajax policy, anti-lockout) runs as designed.
 *
 * Run with:
 *   php tests/test-guard.php
 *
 * @package Ironhide
 */

if ( PHP_SAPI !== 'cli' ) {
	fwrite( STDERR, "CLI only.\n" );
	exit( 2 );
}

// --- scratch directories --------------------------------------------------
$ih_tmp = sys_get_temp_dir() . '/ironhide-tests-' . getmypid();

define( 'ABSPATH', __DIR__ . '/../../' );
define( 'WP_CONTENT_DIR', $ih_tmp . '/wp-content' );
define( 'COOKIEPATH', '/' );
define( 'COOKIE_DOMAIN', '' );

@mkdir( WP_CONTENT_DIR, 0777, true );
@mkdir( $ih_tmp . '/uploads', 0777, true );

$GLOBALS['ih_uploads']    = $ih_tmp . '/uploads';
$GLOBALS['ih_option']     = array();
$GLOBALS['ih_transients'] = array();
$GLOBALS['ih_is_admin']   = false;
$GLOBALS['ih_logged_in']  = false;
$GLOBALS['ih_user_id']    = 0;
$GLOBALS['ih_can_manage'] = true;
$GLOBALS['ih_status']     = null;
$GLOBALS['ih_died']       = null;

// Swallow the harmless CLI "headers already sent" warning from real setcookie().
set_error_handler(
	function ( $errno, $errstr ) {
		if ( false !== stripos( $errstr, 'Cannot modify header information' )
			|| false !== stripos( $errstr, 'headers already sent' ) ) {
			return true;
		}
		return false;
	}
);

// --- minimal WordPress stubs ---------------------------------------------
function add_action() {}
function add_filter() {}
function apply_filters( $tag, $value ) {
	return $value;
}
function get_option( $key, $default_value = null ) {
	return array_key_exists( $key, $GLOBALS['ih_option'] ) ? $GLOBALS['ih_option'][ $key ] : $default_value;
}
function update_option( $key, $value ) {
	$GLOBALS['ih_option'][ $key ] = $value;
	return true;
}
function wp_parse_args( $args, $defaults = array() ) {
	if ( is_object( $args ) ) {
		$args = get_object_vars( $args );
	}
	if ( ! is_array( $args ) ) {
		$args = array();
	}
	return array_merge( $defaults, $args );
}
function is_admin() {
	return (bool) $GLOBALS['ih_is_admin'];
}
function is_user_logged_in() {
	return (bool) $GLOBALS['ih_logged_in'];
}
function get_current_user_id() {
	return (int) $GLOBALS['ih_user_id'];
}
function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}
function status_header( $code ) {
	$GLOBALS['ih_status'] = $code;
}
function nocache_headers() {}
function esc_html( $s ) {
	return $s;
}
function esc_html__( $s, $domain = null ) {
	return $s;
}
function __( $s, $domain = null ) {
	return $s;
}
function _n( $single, $plural, $number, $domain = null ) {
	return ( 1 === (int) $number ) ? $single : $plural;
}
function current_user_can( $cap ) {
	return (bool) $GLOBALS['ih_can_manage'];
}
function wp_die( $message, $title = '', $args = array() ) {
	$GLOBALS['ih_died'] = array(
		'message' => $message,
		'title'   => $title,
		'args'    => $args,
	);
}
function trailingslashit( $s ) {
	return rtrim( $s, '/\\' ) . '/';
}
function wp_generate_password( $len, $special, $extra ) {
	return 'randompayload';
}
function wp_salt( $scheme = 'auth' ) {
	return 'test-wp-salt-' . $scheme;
}
function is_ssl() {
	return false;
}
function wp_upload_dir() {
	return array( 'basedir' => $GLOBALS['ih_uploads'] );
}
function wp_mkdir_p( $dir ) {
	return @mkdir( $dir, 0777, true ) || is_dir( $dir );
}
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['ih_transients'][ $key ] = $value;
	return true;
}
function get_transient( $key ) {
	return array_key_exists( $key, $GLOBALS['ih_transients'] ) ? $GLOBALS['ih_transients'][ $key ] : false;
}
function delete_transient( $key ) {
	unset( $GLOBALS['ih_transients'][ $key ] );
	return true;
}

// --- load the classes under test -----------------------------------------
require_once __DIR__ . '/../includes/class-ironhide-core.php';
require_once __DIR__ . '/../includes/class-ironhide-recovery.php';
require_once __DIR__ . '/../includes/class-ironhide-logger.php';
require_once __DIR__ . '/../includes/class-ironhide-guard.php';
require_once __DIR__ . '/../includes/class-ironhide-settings.php';

// --- helpers -------------------------------------------------------------
$failures = 0;
$count    = 0;

/**
 * Assert two values are strictly equal.
 *
 * @param mixed  $expected Expected value.
 * @param mixed  $actual   Actual value.
 * @param string $label    Test description.
 * @return void
 */
function ih_assert( $expected, $actual, $label ) {
	global $failures, $count;
	$count++;
	if ( $expected === $actual ) {
		fwrite( STDOUT, "ok   - $label\n" );
		return;
	}
	$failures++;
	fwrite(
		STDOUT,
		"FAIL - $label\n       expected: " . var_export( $expected, true ) .
		"\n       actual:   " . var_export( $actual, true ) . "\n"
	);
}

/**
 * Reset all mutable test state.
 *
 * @return void
 */
function ih_reset() {
	$GLOBALS['ih_option']    = array();
	$GLOBALS['ih_is_admin']  = false;
	$GLOBALS['ih_logged_in'] = false;
	$GLOBALS['ih_user_id']   = 0;
	$GLOBALS['ih_can_manage'] = true;
	$GLOBALS['ih_status']    = null;
	$GLOBALS['ih_died']      = null;
	$GLOBALS['pagenow']      = 'index.php';

	$_GET     = array();
	$_COOKIE  = array();
	$_REQUEST = array();

	$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
	unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );

	Ironhide_Recovery::reset_failed_attempt();
	ih_clear_log();
}

/**
 * Empty the block log.
 *
 * @return void
 */
function ih_clear_log() {
	$file = Ironhide_Logger::file_path();
	if ( '' !== $file && is_file( $file ) ) {
		@unlink( $file );
	}
}

/**
 * Raw contents of the block log.
 *
 * @return string
 */
function ih_log_contents() {
	$file = Ironhide_Logger::file_path();
	if ( '' === $file || ! is_file( $file ) ) {
		return '';
	}
	return (string) file_get_contents( $file );
}

/**
 * Store a settings array as the saved option.
 *
 * @param array $settings Partial settings.
 * @return void
 */
function ih_set_option( $settings ) {
	$GLOBALS['ih_option'][ Ironhide_Guard::OPTION ] = $settings;
}

// =========================================================================
// Fail-open / active_mode
// =========================================================================
ih_reset();

ih_assert(
	Ironhide_Guard::MODE_OFF,
	Ironhide_Guard::active_mode( array( 'mode' => 'off', 'allowed_ips' => array( '198.51.100.99' ) ) ),
	'active_mode: off stays off'
);
ih_assert(
	Ironhide_Guard::MODE_OFF,
	Ironhide_Guard::active_mode( array( 'mode' => 'enforce', 'allowed_ips' => array() ) ),
	'active_mode: empty allowlist fails open'
);
ih_assert(
	Ironhide_Guard::MODE_ENFORCE,
	Ironhide_Guard::active_mode( array( 'mode' => 'enforce', 'allowed_ips' => array( '198.51.100.99' ) ) ),
	'active_mode: enforce with a list enforces'
);
ih_assert(
	Ironhide_Guard::MODE_MONITOR,
	Ironhide_Guard::active_mode( array( 'mode' => 'monitor', 'allowed_ips' => array( '198.51.100.99' ) ) ),
	'active_mode: monitor with a list monitors'
);
ih_assert(
	Ironhide_Guard::MODE_OFF,
	Ironhide_Guard::active_mode( array( 'mode' => 'nonsense', 'allowed_ips' => array( '198.51.100.99' ) ) ),
	'active_mode: unknown mode falls back to off'
);

// --- hard disable via marker file ----------------------------------------
ih_reset();
$marker = Ironhide_Recovery::disable_file_path();
@unlink( $marker );
ih_assert( false, Ironhide_Recovery::hard_disabled(), 'not hard-disabled with no marker' );

@file_put_contents( $marker, '' );
ih_assert( true, Ironhide_Recovery::hard_disabled(), 'hard-disabled when marker file present' );
ih_assert(
	Ironhide_Guard::MODE_OFF,
	Ironhide_Guard::active_mode( array( 'mode' => 'enforce', 'allowed_ips' => array( '198.51.100.99' ) ) ),
	'active_mode: marker file forces off'
);
@unlink( $marker );

// =========================================================================
// Settings normalisation
// =========================================================================
ih_reset();
ih_set_option(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => array( ' 198.51.100.7 ', '', array( 'nested' ), 42 ),
		'ajax_policy' => 'bogus',
	)
);
$normalised = Ironhide_Guard::get_settings();
ih_assert( array( '198.51.100.7', '42' ), $normalised['allowed_ips'], 'get_settings: trims, drops empties and non-scalars' );
ih_assert( Ironhide_Guard::AJAX_PUBLIC_ONLY, $normalised['ajax_policy'], 'get_settings: invalid ajax policy falls back to default' );

ih_reset();
ih_set_option( 'not-an-array' );
ih_assert( Ironhide_Guard::MODE_OFF, Ironhide_Guard::get_settings()['mode'], 'get_settings: corrupt option falls back to defaults' );

// =========================================================================
// is_allowed
// =========================================================================
ih_reset();
$settings = array(
	'mode'            => 'enforce',
	'allowed_ips'     => array( '198.51.100.99' ),
	'trusted_proxies' => array(),
	'trust_headers'   => false,
);
ih_assert( true, Ironhide_Guard::is_allowed( $settings ), 'allowed when REMOTE_ADDR in list' );

$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
ih_assert( false, Ironhide_Guard::is_allowed( $settings ), 'denied when REMOTE_ADDR not in list' );

$_SERVER['REMOTE_ADDR'] = '';
ih_assert( false, Ironhide_Guard::is_allowed( $settings ), 'denied when the IP cannot be determined' );

ih_reset();
$_SERVER['REMOTE_ADDR']  = '203.0.113.42';
$settings['allowed_ips'] = array( '203.0.113.0/24' );
ih_assert( true, Ironhide_Guard::is_allowed( $settings ), 'allowed via CIDR /24' );

// =========================================================================
// Scope: wp-admin and nothing else
// =========================================================================
ih_reset();
$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
ih_set_option(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => array( '198.51.100.0/24' ),
	)
);

// Frontend (is_admin() false) — e.g. wp-login.php, the REST API, XML-RPC.
$GLOBALS['ih_is_admin'] = false;
$GLOBALS['pagenow']     = 'wp-login.php';
Ironhide_Guard::maybe_block();
ih_assert( null, $GLOBALS['ih_died'], 'wp-login.php is never gated' );

$GLOBALS['pagenow'] = 'index.php';
Ironhide_Guard::maybe_block();
ih_assert( null, $GLOBALS['ih_died'], 'frontend requests are never gated' );

// Dashboard.
$GLOBALS['ih_is_admin'] = true;
$GLOBALS['pagenow']     = 'index.php';
Ironhide_Guard::maybe_block();
ih_assert( 403, $GLOBALS['ih_status'], 'wp-admin denied: 403 status' );
ih_assert(
	true,
	is_array( $GLOBALS['ih_died'] ) && 'Access Denied' === $GLOBALS['ih_died']['title'],
	'wp-admin denied: wp_die with Access Denied'
);
// The 403 body is served to an unauthenticated stranger: it must give away
// neither an allowlist entry nor which address the guard actually evaluated.
ih_assert(
	false,
	false !== strpos( $GLOBALS['ih_died']['message'], '203.0.113.99' ),
	'deny page does not echo the detected IP'
);
ih_assert(
	false,
	false !== strpos( $GLOBALS['ih_died']['message'], '198.51.100' ),
	'deny page does not echo any allowlist entry'
);

// Allowed visitor.
ih_reset();
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
ih_set_option(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => array( '198.51.100.0/24' ),
	)
);
$GLOBALS['ih_is_admin'] = true;
Ironhide_Guard::maybe_block();
ih_assert( null, $GLOBALS['ih_status'], 'no status set when allowed' );
ih_assert( null, $GLOBALS['ih_died'], 'no deny when allowed' );

// =========================================================================
// Monitor mode
// =========================================================================
ih_reset();
$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
ih_set_option(
	array(
		'mode'        => 'monitor',
		'allowed_ips' => array( '198.51.100.0/24' ),
		'log_blocks'  => true,
	)
);
$GLOBALS['ih_is_admin'] = true;
Ironhide_Guard::maybe_block();
ih_assert( null, $GLOBALS['ih_died'], 'monitor mode never blocks' );
ih_assert( null, $GLOBALS['ih_status'], 'monitor mode sets no status' );
ih_assert( true, false !== strpos( ih_log_contents(), 'would_block' ), 'monitor mode records a would_block' );
ih_assert( true, false !== strpos( ih_log_contents(), '203.0.113.99' ), 'monitor record carries the IP' );

// Logging off means monitor records nothing.
ih_reset();
$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
ih_set_option(
	array(
		'mode'        => 'monitor',
		'allowed_ips' => array( '198.51.100.0/24' ),
		'log_blocks'  => false,
	)
);
$GLOBALS['ih_is_admin'] = true;
Ironhide_Guard::maybe_block();
ih_assert( '', ih_log_contents(), 'log_blocks off suppresses the record' );

// =========================================================================
// admin-ajax.php / admin-post.php policy
// =========================================================================
foreach ( array( 'admin-ajax.php', 'admin-post.php' ) as $endpoint ) {

	// open: never gated, logged in or not.
	ih_reset();
	$GLOBALS['ih_is_admin'] = true;
	$GLOBALS['pagenow']     = $endpoint;
	$GLOBALS['ih_logged_in'] = true;
	$_SERVER['REMOTE_ADDR']  = '203.0.113.99';
	ih_set_option(
		array(
			'mode'        => 'enforce',
			'allowed_ips' => array( '198.51.100.0/24' ),
			'ajax_policy' => Ironhide_Guard::AJAX_OPEN,
			'log_blocks'  => false,
		)
	);
	Ironhide_Guard::maybe_block();
	ih_assert( null, $GLOBALS['ih_died'], "$endpoint: open policy never gates" );

	// public_only: anonymous passes.
	ih_reset();
	$GLOBALS['ih_is_admin']  = true;
	$GLOBALS['pagenow']      = $endpoint;
	$GLOBALS['ih_logged_in'] = false;
	$_SERVER['REMOTE_ADDR']  = '203.0.113.99';
	ih_set_option(
		array(
			'mode'        => 'enforce',
			'allowed_ips' => array( '198.51.100.0/24' ),
			'ajax_policy' => Ironhide_Guard::AJAX_PUBLIC_ONLY,
			'log_blocks'  => false,
		)
	);
	Ironhide_Guard::maybe_block();
	ih_assert( null, $GLOBALS['ih_died'], "$endpoint: public_only lets anonymous requests through" );

	// public_only: authenticated is gated.
	$GLOBALS['ih_logged_in'] = true;
	$GLOBALS['ih_user_id']   = 7;
	Ironhide_Guard::maybe_block();
	ih_assert( 403, $GLOBALS['ih_status'], "$endpoint: public_only gates authenticated requests" );

	// gated: anonymous is gated too.
	ih_reset();
	$GLOBALS['ih_is_admin']  = true;
	$GLOBALS['pagenow']      = $endpoint;
	$GLOBALS['ih_logged_in'] = false;
	$_SERVER['REMOTE_ADDR']  = '203.0.113.99';
	ih_set_option(
		array(
			'mode'        => 'enforce',
			'allowed_ips' => array( '198.51.100.0/24' ),
			'ajax_policy' => Ironhide_Guard::AJAX_GATED,
			'log_blocks'  => false,
		)
	);
	Ironhide_Guard::maybe_block();
	ih_assert( 403, $GLOBALS['ih_status'], "$endpoint: gated policy blocks anonymous requests too" );
}

// The default policy is public_only.
ih_assert( Ironhide_Guard::AJAX_PUBLIC_ONLY, Ironhide_Guard::defaults()['ajax_policy'], 'default ajax policy is public_only' );
ih_assert( Ironhide_Guard::MODE_OFF, Ironhide_Guard::defaults()['mode'], 'default mode is off' );

// =========================================================================
// Bypass key and cookie
// =========================================================================
ih_reset();
if ( ! defined( 'IRONHIDE_BYPASS_KEY' ) ) {
	define( 'IRONHIDE_BYPASS_KEY', 'correct-horse-battery-staple' );
}
$settings = array(
	'mode'            => 'enforce',
	'allowed_ips'     => array( '203.0.113.0/24' ),
	'trusted_proxies' => array(),
	'trust_headers'   => false,
);
$_SERVER['REMOTE_ADDR'] = '6.6.6.6';

$_GET[ Ironhide_Recovery::QUERY_KEY ] = 'wrong';
ih_assert( false, Ironhide_Guard::is_allowed( $settings ), 'bypass key rejected when wrong' );
ih_assert( true, Ironhide_Recovery::had_failed_attempt(), 'wrong bypass key is recorded as a failed attempt' );

ih_reset();
$_SERVER['REMOTE_ADDR']               = '6.6.6.6';
$_GET[ Ironhide_Recovery::QUERY_KEY ] = 'correct-horse-battery-staple';
ih_assert( true, Ironhide_Guard::is_allowed( $settings ), 'bypass key accepted when correct' );
ih_assert( false, Ironhide_Recovery::had_failed_attempt(), 'correct key is not a failed attempt' );
ih_assert( true, Ironhide_Recovery::has_valid_cookie(), 'bypass cookie dropped after a valid key' );

ih_reset();
$ts      = (string) time();
$payload = 'abcd';
$_COOKIE[ Ironhide_Recovery::COOKIE_NAME ] = $ts . '.' . $payload . '.' . Ironhide_Recovery::cookie_signature( $ts, $payload );
ih_assert( true, Ironhide_Recovery::has_valid_cookie(), 'valid signed cookie accepted' );

$_COOKIE[ Ironhide_Recovery::COOKIE_NAME ] = $ts . '.abcd.' . Ironhide_Recovery::cookie_signature( $ts, 'tampered' );
ih_assert( false, Ironhide_Recovery::has_valid_cookie(), 'tampered cookie rejected' );

$old = (int) $ts - ( Ironhide_Recovery::COOKIE_TTL + 10 );
$_COOKIE[ Ironhide_Recovery::COOKIE_NAME ] = $old . '.abcd.' . Ironhide_Recovery::cookie_signature( (string) $old, 'abcd' );
ih_assert( false, Ironhide_Recovery::has_valid_cookie(), 'expired cookie rejected' );

$future = (int) $ts + 3600;
$_COOKIE[ Ironhide_Recovery::COOKIE_NAME ] = $future . '.abcd.' . Ironhide_Recovery::cookie_signature( (string) $future, 'abcd' );
ih_assert( false, Ironhide_Recovery::has_valid_cookie(), 'far-future cookie rejected' );

$_COOKIE[ Ironhide_Recovery::COOKIE_NAME ] = 'not.a.valid.cookie.at.all';
ih_assert( false, Ironhide_Recovery::has_valid_cookie(), 'malformed cookie rejected' );

// =========================================================================
// Trusted proxies
// =========================================================================
ih_reset();
$_SERVER['REMOTE_ADDR']          = '6.6.6.6'; // Not a trusted proxy.
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1';
$proxy_settings                  = array(
	'trusted_proxies' => array( '10.0.0.1' ),
	'trust_headers'   => true,
);
ih_assert( '6.6.6.6', Ironhide_Core::get_effective_ip( $proxy_settings ), 'XFF ignored when the peer is not a trusted proxy' );

ih_reset();
$_SERVER['REMOTE_ADDR']          = '10.0.0.1'; // Trusted proxy.
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1, 10.0.0.1';
ih_assert( '198.51.100.1', Ironhide_Core::get_effective_ip( $proxy_settings ), 'real client taken from XFF behind a trusted proxy' );

ih_reset();
$_SERVER['REMOTE_ADDR']    = '10.0.0.1';
$_SERVER['HTTP_X_REAL_IP'] = '198.51.100.2';
ih_assert( '198.51.100.2', Ironhide_Core::get_effective_ip( $proxy_settings ), 'X-Real-IP used when there is no XFF' );

// =========================================================================
// sanitize_settings
// =========================================================================
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '203.0.113.77';

$out = Ironhide_Settings::sanitize_settings(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => "198.51.100.0/24\n",
		'log_blocks'  => '1',
	)
);
ih_assert( true, in_array( '203.0.113.77', $out['allowed_ips'], true ), 'sanitize auto-adds the current IP on save' );
ih_assert( true, in_array( '198.51.100.0/24', $out['allowed_ips'], true ), 'sanitize keeps a valid CIDR' );
ih_assert( 'enforce', $out['mode'], 'sanitize preserves a valid mode' );

// Unknown keys must not survive.
$out = Ironhide_Settings::sanitize_settings(
	array(
		'mode'          => 'monitor',
		'allowed_ips'   => '198.51.100.7',
		'evil_key'      => 'payload',
		'allowed_users' => array( 'root' ),
	)
);
ih_assert( false, array_key_exists( 'evil_key', $out ), 'sanitize drops unknown submitted keys' );
ih_assert( false, array_key_exists( 'allowed_users', $out ), 'sanitize drops unknown array keys' );
ih_assert(
	array( 'mode', 'allowed_ips', 'trusted_proxies', 'trust_headers', 'ajax_policy', 'log_blocks' ),
	array_keys( $out ),
	'sanitize returns exactly the known key set'
);

// Invalid mode / policy fall back to defaults.
$out = Ironhide_Settings::sanitize_settings(
	array(
		'mode'        => 'obliterate',
		'ajax_policy' => 'whatever',
		'allowed_ips' => '198.51.100.7',
	)
);
ih_assert( Ironhide_Guard::MODE_OFF, $out['mode'], 'sanitize rejects an unknown mode' );
ih_assert( Ironhide_Guard::AJAX_PUBLIC_ONLY, $out['ajax_policy'], 'sanitize rejects an unknown ajax policy' );

// Invalid entries dropped.
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '203.0.113.77';
$out = Ironhide_Settings::sanitize_settings( array( 'allowed_ips' => "999.999.999.999\nhello\n198.51.100.7\n" ) );
ih_assert( false, in_array( '999.999.999.999', $out['allowed_ips'], true ), 'sanitize drops an invalid octet IP' );
ih_assert( false, in_array( 'hello', $out['allowed_ips'], true ), 'sanitize drops a junk entry' );
ih_assert( true, in_array( '198.51.100.7', $out['allowed_ips'], true ), 'sanitize keeps a valid exact IP' );

// Unknown IP refuses to enforce.
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '';
$out = Ironhide_Settings::sanitize_settings(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => "198.51.100.7\n",
	)
);
ih_assert( Ironhide_Guard::MODE_OFF, $out['mode'], 'sanitize refuses to enforce when the current IP is unknown' );

// Monitor mode is still allowed with an unknown IP: it blocks nothing.
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '';
$out = Ironhide_Settings::sanitize_settings(
	array(
		'mode'        => 'monitor',
		'allowed_ips' => "198.51.100.7\n",
	)
);
ih_assert( Ironhide_Guard::MODE_MONITOR, $out['mode'], 'sanitize leaves monitor mode alone when the IP is unknown' );

// A universal entry warns.
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '203.0.113.77';
Ironhide_Settings::sanitize_settings(
	array(
		'mode'        => 'enforce',
		'allowed_ips' => "0.0.0.0/0\n",
	)
);
$notices = get_transient( 'ironhide_notices_1' );
ih_assert(
	true,
	is_array( $notices ) && (bool) preg_grep( '/every address/', $notices ),
	'sanitize warns about an allow-everything entry'
);

// Trusting headers without a matching proxy warns.
ih_reset();
$GLOBALS['ih_user_id']  = 1;
$_SERVER['REMOTE_ADDR'] = '203.0.113.77';
Ironhide_Settings::sanitize_settings(
	array(
		'mode'          => 'enforce',
		'allowed_ips'   => '198.51.100.7',
		'trust_headers' => '1',
	)
);
$notices = get_transient( 'ironhide_notices_1' );
ih_assert(
	true,
	is_array( $notices ) && (bool) preg_grep( '/spoofing/', $notices ),
	'sanitize warns when headers are trusted but the peer is not a listed proxy'
);

// =========================================================================
// Logger
// =========================================================================
ih_assert(
	'/wp-admin/?ironhide_bypass=[redacted]&x=1',
	Ironhide_Logger::redact_uri( '/wp-admin/?ironhide_bypass=secret&x=1' ),
	'logger redacts the bypass key value'
);
ih_assert(
	'/wp-admin/?a=1&ironhide_bypass=[redacted]',
	Ironhide_Logger::redact_uri( '/wp-admin/?a=1&ironhide_bypass=secret' ),
	'logger redacts the bypass key in any position'
);
ih_assert(
	'evil UA newline here',
	Ironhide_Logger::field( "evil\r\nUA\tnewline\x00here" ),
	'logger strips control characters (CR, LF and TAB) from fields'
);
ih_assert( 200, strlen( Ironhide_Logger::field( str_repeat( 'x', 500 ) ) ), 'logger caps field length' );
ih_assert( '-', Ironhide_Logger::field( '' ), 'logger renders an empty field as a placeholder' );
ih_assert( '-', Ironhide_Logger::field( array( 'x' ) ), 'logger tolerates a non-scalar field' );

ih_reset();
Ironhide_Logger::log( 'block', array( 'ip' => '203.0.113.1', 'where' => 'index.php', 'ua' => 'curl/8' ) );
$recent = Ironhide_Logger::recent( 5 );
ih_assert( 1, count( $recent ), 'logger reads back one record' );
ih_assert( 'block', $recent[0]['event'], 'record round-trips the event' );
ih_assert( '203.0.113.1', $recent[0]['ip'], 'record round-trips the IP' );
ih_assert( 'index.php', $recent[0]['where'], 'record round-trips the context' );
ih_assert( 'curl/8', $recent[0]['ua'], 'record round-trips the user agent' );

// Newest first, and the limit is honoured.
ih_clear_log();
for ( $i = 1; $i <= 5; $i++ ) {
	Ironhide_Logger::log( 'block', array( 'ip' => '203.0.113.' . $i ) );
}
$recent = Ironhide_Logger::recent( 3 );
ih_assert( 3, count( $recent ), 'recent() honours the limit' );
ih_assert( '203.0.113.5', $recent[0]['ip'], 'recent() returns newest first' );

ih_clear_log();
ih_assert( array(), Ironhide_Logger::recent( 5 ), 'recent() copes with a missing log file' );

// The log holds security telemetry under a web-readable uploads directory, so
// its name must not be guessable when no server-level deny rule is in place.
ih_assert( false, 'blocked.log' === Ironhide_Logger::file_name(), 'log filename is not the guessable default' );
ih_assert(
	1,
	preg_match( '/^blocked-[0-9a-f]{16}\.log$/', Ironhide_Logger::file_name() ),
	'log filename carries a salt-derived component'
);
ih_assert(
	false,
	false !== strpos( Ironhide_Logger::file_name(), wp_salt( 'auth' ) ),
	'log filename does not contain the salt itself'
);

// The directory guards are (re)created.
$log_dir = Ironhide_Logger::dir();
foreach ( array( 'index.php', '.htaccess', 'web.config' ) as $guard ) {
	ih_assert( true, is_file( $log_dir . '/' . $guard ), "log directory is protected by $guard" );
	@unlink( $log_dir . '/' . $guard );
}
Ironhide_Logger::dir();
foreach ( array( 'index.php', '.htaccess', 'web.config' ) as $guard ) {
	ih_assert( true, is_file( $log_dir . '/' . $guard ), "$guard is restored when deleted" );
}

// uninstall.php must know about every file we create.
$owned   = Ironhide_Logger::owned_files();
$on_disk = array_values( array_diff( scandir( $log_dir ), array( '.', '..' ) ) );
ih_assert( array(), array_diff( $on_disk, $owned ), 'every file in the log directory is listed in owned_files()' );

// --- cleanup --------------------------------------------------------------
// glob() skips dotfiles, so walk owned_files() to catch .htaccess as well.
foreach ( Ironhide_Logger::owned_files() as $leftover ) {
	@unlink( $log_dir . '/' . $leftover );
}
@rmdir( $log_dir );
@rmdir( $GLOBALS['ih_uploads'] );
@rmdir( WP_CONTENT_DIR );
@rmdir( $ih_tmp );

// --- summary --------------------------------------------------------------
fwrite( STDOUT, "\n$count tests, $failures failure(s)\n" );
exit( $failures > 0 ? 1 : 0 );
