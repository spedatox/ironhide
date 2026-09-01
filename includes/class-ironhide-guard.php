<?php
/**
 * Enforcement: gate the wp-admin area.
 *
 * Scope: wp-admin and nothing else.
 *
 *  - `wp-admin/admin.php` (and the network / user admin equivalents) define
 *    `WP_ADMIN` *before* loading wp-load.php, so `is_admin()` is already true by
 *    the time `init` fires. `init` at priority 1 is the earliest point at which a
 *    normal plugin can act with `$pagenow`, request slashing and the current user
 *    all in their documented state.
 *  - `admin-ajax.php` and `admin-post.php` live in wp-admin and also define
 *    `WP_ADMIN`, but they are the public frontend utility endpoints. They get
 *    their own policy (see `ajax_policy`) rather than the dashboard rule.
 *  - `wp-login.php` is NOT gated. It is not part of wp-admin, and gating it locks
 *    out every non-staff account on membership and commerce sites. Login stays a
 *    core / WAF concern.
 *  - The REST API, XML-RPC and static files are likewise out of scope.
 *
 * Fail-open invariant: if the mode is `off` OR the allowlist is empty, nothing is
 * ever blocked. This is the primary anti-lockout guarantee.
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Guard.
 */
class Ironhide_Guard {

	const OPTION = 'ironhide_settings';

	/** Protection modes. */
	const MODE_OFF     = 'off';
	const MODE_MONITOR = 'monitor';
	const MODE_ENFORCE = 'enforce';

	/** admin-ajax.php / admin-post.php policies. */
	const AJAX_OPEN        = 'open';
	const AJAX_PUBLIC_ONLY = 'public_only';
	const AJAX_GATED       = 'gated';

	/**
	 * Frontend utility endpoints that live in wp-admin but serve the public site.
	 *
	 * @var string[]
	 */
	private static $frontend_endpoints = array( 'admin-ajax.php', 'admin-post.php' );

	/**
	 * Default settings.
	 *
	 * A method rather than a public property so runtime code cannot mutate the
	 * defaults out from under the anti-lockout logic.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'mode'            => self::MODE_OFF,
			'allowed_ips'     => array(),
			'trusted_proxies' => array(),
			'trust_headers'   => false,
			'ajax_policy'     => self::AJAX_PUBLIC_ONLY,
			'log_blocks'      => true,
		);
	}

	/**
	 * Valid protection modes.
	 *
	 * @return string[]
	 */
	public static function modes() {
		return array( self::MODE_OFF, self::MODE_MONITOR, self::MODE_ENFORCE );
	}

	/**
	 * Valid admin-ajax / admin-post policies.
	 *
	 * @return string[]
	 */
	public static function ajax_policies() {
		return array( self::AJAX_OPEN, self::AJAX_PUBLIC_ONLY, self::AJAX_GATED );
	}

	/**
	 * Register the single enforcement hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'maybe_block' ), 1 );
	}

	/**
	 * Merge saved settings over defaults and normalise every value.
	 *
	 * Nothing downstream re-checks types, so this is the one place that
	 * guarantees the shape of the settings array.
	 *
	 * @return array
	 */
	public static function get_settings() {
		$saved = get_option( self::OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}

		$settings = wp_parse_args( $saved, self::defaults() );

		foreach ( array( 'allowed_ips', 'trusted_proxies' ) as $key ) {
			if ( ! is_array( $settings[ $key ] ) ) {
				$settings[ $key ] = array();
			}
			$settings[ $key ] = array_values(
				array_filter(
					array_map(
						'trim',
						array_map( 'strval', array_filter( $settings[ $key ], 'is_scalar' ) )
					)
				)
			);
		}

		if ( ! in_array( $settings['mode'], self::modes(), true ) ) {
			$settings['mode'] = self::MODE_OFF;
		}
		if ( ! in_array( $settings['ajax_policy'], self::ajax_policies(), true ) ) {
			$settings['ajax_policy'] = self::AJAX_PUBLIC_ONLY;
		}

		$settings['trust_headers'] = ! empty( $settings['trust_headers'] );
		$settings['log_blocks']    = ! empty( $settings['log_blocks'] );

		return $settings;
	}

	/**
	 * The mode actually in force for this request.
	 *
	 * Collapses to MODE_OFF (fail open) for: mode off, empty allowlist, CLI,
	 * cron, WordPress install/upgrade, and the hard-disable recovery paths.
	 *
	 * @param array $settings Merged settings.
	 * @return string One of the MODE_* constants.
	 */
	public static function active_mode( $settings ) {
		$mode = isset( $settings['mode'] ) ? $settings['mode'] : self::MODE_OFF;

		if ( ! in_array( $mode, array( self::MODE_MONITOR, self::MODE_ENFORCE ), true ) ) {
			return self::MODE_OFF;
		}
		if ( empty( $settings['allowed_ips'] ) ) {
			return self::MODE_OFF; // Fail open: an empty list blocks nobody.
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return self::MODE_OFF;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return self::MODE_OFF;
		}
		if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) {
			return self::MODE_OFF; // Covers install.php and the DB upgrade screen.
		}
		if ( Ironhide_Recovery::hard_disabled() ) {
			return self::MODE_OFF;
		}

		return $mode;
	}

	/**
	 * Is the current visitor allowed through?
	 *
	 * @param array $settings Merged settings.
	 * @return bool
	 */
	public static function is_allowed( $settings ) {
		if ( Ironhide_Recovery::is_bypassed() ) {
			return true;
		}

		$ip = Ironhide_Core::get_effective_ip( $settings );
		if ( '' === $ip ) {
			// Cannot determine the peer: deny rather than silently allow.
			return false;
		}

		return Ironhide_Core::ip_in_list( $ip, $settings['allowed_ips'] );
	}

	/**
	 * Entry point on `init`. Routes wp-admin requests to the right rule.
	 *
	 * @return void
	 */
	public static function maybe_block() {
		// Everything this plugin gates lives behind WP_ADMIN. Frontend requests,
		// REST, XML-RPC and wp-login.php all return here.
		if ( ! is_admin() ) {
			return;
		}

		$script = self::current_script();

		if ( in_array( $script, self::$frontend_endpoints, true ) ) {
			self::evaluate_frontend_endpoint( $script );
			return;
		}

		self::evaluate( $script );
	}

	/**
	 * admin-ajax.php / admin-post.php.
	 *
	 * Default policy is `public_only`: logged-out requests always pass (that is
	 * what public contact forms, search-as-you-type and payment callbacks need),
	 * while authenticated requests are gated like the rest of wp-admin. That
	 * closes the hole where someone holding valid credentials drives the site
	 * through admin-ajax from an address that may not touch the dashboard.
	 *
	 * @param string $script Script name.
	 * @return void
	 */
	public static function evaluate_frontend_endpoint( $script ) {
		$settings = self::get_settings();

		if ( self::AJAX_OPEN === $settings['ajax_policy'] ) {
			return;
		}

		if ( self::AJAX_PUBLIC_ONLY === $settings['ajax_policy'] && ! is_user_logged_in() ) {
			return;
		}

		self::evaluate( $script, $settings );
	}

	/**
	 * Apply the allowlist to the current request.
	 *
	 * @param string     $where    Context for the log / deny page.
	 * @param array|null $settings Pre-loaded settings, or null to load them.
	 * @return void
	 */
	public static function evaluate( $where, $settings = null ) {
		if ( ! is_array( $settings ) ) {
			$settings = self::get_settings();
		}

		$mode = self::active_mode( $settings );
		if ( self::MODE_OFF === $mode ) {
			return;
		}

		$allowed = self::is_allowed( $settings );

		/**
		 * Filter the final allow/deny decision for a wp-admin request.
		 *
		 * Returning true lets the request through; false blocks it (or records a
		 * would-be block, in monitor mode).
		 *
		 * The settings array is deliberately NOT passed: handing the allowlist to
		 * every registered callback spreads it further than it needs to go. A
		 * callback that genuinely needs it can call get_settings() itself.
		 *
		 * @param bool   $allowed Decision from the allowlist.
		 * @param string $where   Script being evaluated.
		 */
		$allowed = (bool) apply_filters( 'ironhide_request_is_allowed', $allowed, $where );

		if ( $allowed ) {
			return;
		}

		if ( self::MODE_MONITOR === $mode ) {
			self::record( $settings, 'would_block', $where );
			return;
		}

		self::deny( $settings, $where );
	}

	/**
	 * Name of the PHP script handling the current request.
	 *
	 * Uses `$pagenow` (set in wp-includes/vars.php, long before `init`) and falls
	 * back to SCRIPT_NAME. basename() keeps the network/user admin path prefixes
	 * from confusing the comparison.
	 *
	 * @return string
	 */
	public static function current_script() {
		if ( isset( $GLOBALS['pagenow'] ) && is_string( $GLOBALS['pagenow'] ) && '' !== $GLOBALS['pagenow'] ) {
			return basename( $GLOBALS['pagenow'] );
		}
		return basename( Ironhide_Core::server_var( 'SCRIPT_NAME' ) );
	}

	/**
	 * Write one record to the block log, honouring the log_blocks setting.
	 *
	 * @param array  $settings Merged settings.
	 * @param string $event    'block' or 'would_block'.
	 * @param string $where    Script being evaluated.
	 * @return void
	 */
	public static function record( $settings, $event, $where ) {
		if ( empty( $settings['log_blocks'] ) ) {
			return;
		}

		Ironhide_Logger::log(
			$event,
			array(
				'ip'          => Ironhide_Core::get_effective_ip( $settings ),
				'remote_addr' => Ironhide_Core::get_remote_addr(),
				'where'       => $where,
				'user'        => self::current_user_label(),
				'bypass'      => Ironhide_Recovery::had_failed_attempt() ? 'failed' : '-',
				'uri'         => Ironhide_Logger::redact_uri( Ironhide_Core::server_var( 'REQUEST_URI' ) ),
				'ua'          => Ironhide_Core::server_var( 'HTTP_USER_AGENT' ),
			)
		);
	}

	/**
	 * A short identifier for the acting user, for the log only.
	 *
	 * @return string
	 */
	public static function current_user_label() {
		if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
			return '-';
		}
		return '#' . get_current_user_id();
	}

	/**
	 * Log and refuse the request.
	 *
	 * @param array  $settings Merged settings.
	 * @param string $where    Human-readable context for the log.
	 * @return void
	 */
	public static function deny( $settings, $where ) {
		self::record( $settings, 'block', $where );

		status_header( 403 );
		nocache_headers();

		// The refusal is deliberately uninformative. It must never reveal an
		// allowlist entry, and it does not echo the visitor's own detected IP
		// either: under a proxy configuration that would tell an attacker which
		// header the guard actually evaluated, which is the first thing needed
		// to probe the list. Operators read the detected IP from the log, which
		// never leaves the server.
		$message = __( 'You do not have permission to access this area.', 'ironhide' );

		/**
		 * Filter the message shown to a blocked visitor.
		 *
		 * Anything added here is served to an unauthenticated stranger. Do not
		 * include allowlist entries, and think twice before including the
		 * visitor's detected IP.
		 *
		 * @param string $message Default message.
		 * @param string $where   Context that was blocked.
		 */
		$message = apply_filters( 'ironhide_deny_message', $message, $where );

		wp_die(
			esc_html( $message ),
			esc_html__( 'Access Denied', 'ironhide' ),
			array(
				'response'  => 403,
				'back_link' => false,
			)
		);
	}
}
