<?php
/**
 * WP-CLI commands.
 *
 * These are a recovery channel in their own right: when the dashboard is locked,
 * `wp ironhide off` or `wp ironhide allow <ip>` from the shell still works,
 * because CLI requests are never subject to the gate.
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WP-CLI integration.
 */
class Ironhide_CLI {

	/**
	 * Register commands when running under WP-CLI.
	 *
	 * @return void
	 */
	public static function register() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}

		$commands = array(
			'status'  => 'cmd_status',
			'allow'   => 'cmd_allow',
			'remove'  => 'cmd_remove',
			'list'    => 'cmd_list',
			'mode'    => 'cmd_mode',
			'monitor' => 'cmd_monitor',
			'enforce' => 'cmd_enforce',
			'off'     => 'cmd_off',
			'log'     => 'cmd_log',
		);

		foreach ( $commands as $name => $method ) {
			WP_CLI::add_command(
				'ironhide ' . $name,
				array( __CLASS__, $method ),
				array( 'when' => 'after_wp_load' )
			);
		}
	}

	/**
	 * Persist a settings array.
	 *
	 * @param array $settings Settings to store.
	 * @return void
	 */
	private static function save( $settings ) {
		// Explicit autoload=false: the allowlist is only ever read inside
		// wp-admin and must not ride along in the front-end alloptions blob.
		update_option( Ironhide_Guard::OPTION, $settings, false );
	}

	/**
	 * Set the mode and report the result.
	 *
	 * @param string $mode One of the Ironhide_Guard::MODE_* constants.
	 * @return void
	 */
	private static function set_mode( $mode ) {
		$settings         = Ironhide_Guard::get_settings();
		$settings['mode'] = $mode;
		self::save( $settings );

		if ( Ironhide_Guard::MODE_OFF !== $mode && empty( $settings['allowed_ips'] ) ) {
			WP_CLI::warning(
				sprintf(
					'Mode set to %s, but the allowlist is empty — nothing is blocked until you add an entry (wp ironhide allow <ip>).',
					$mode
				)
			);
			return;
		}

		WP_CLI::success( sprintf( 'Mode set to %s.', $mode ) );
	}

	/**
	 * Show the current configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ironhide status
	 *
	 * @return void
	 */
	public static function cmd_status() {
		$settings = Ironhide_Guard::get_settings();
		$active   = Ironhide_Guard::active_mode( $settings );

		WP_CLI::line( sprintf( 'Configured mode:  %s', $settings['mode'] ) );
		WP_CLI::line( sprintf( 'Effective mode:   %s', $active ) );
		WP_CLI::line( sprintf( 'Allowed entries:  %d', count( $settings['allowed_ips'] ) ) );
		WP_CLI::line( sprintf( 'Trusted proxies:  %d', count( $settings['trusted_proxies'] ) ) );
		WP_CLI::line( sprintf( 'Trust headers:    %s', $settings['trust_headers'] ? 'yes' : 'no' ) );
		WP_CLI::line( sprintf( 'admin-ajax policy: %s', $settings['ajax_policy'] ) );
		WP_CLI::line( sprintf( 'Logging:          %s', $settings['log_blocks'] ? 'on' : 'off' ) );
		WP_CLI::line( sprintf( 'Hard disabled:    %s', Ironhide_Recovery::hard_disabled() ? 'yes (constant or marker file)' : 'no' ) );

		if ( $settings['mode'] !== $active ) {
			WP_CLI::warning( 'The effective mode differs from the configured mode: the allowlist is empty, or a recovery path is active.' );
		}
	}

	/**
	 * Add an entry to the allowlist.
	 *
	 * ## OPTIONS
	 *
	 * <entry>
	 * : An IP address, CIDR range, or IPv4 wildcard.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ironhide allow 203.0.113.10
	 *     wp ironhide allow 203.0.113.0/24
	 *
	 * @param array $args Positional args.
	 * @return void
	 */
	public static function cmd_allow( $args ) {
		if ( empty( $args[0] ) ) {
			WP_CLI::error( 'Usage: wp ironhide allow <ip|CIDR|wildcard>' );
		}

		$entry = Ironhide_Core::sanitize_ip_entry( $args[0] );
		if ( false === $entry ) {
			WP_CLI::error( 'Invalid IP/CIDR/wildcard: ' . $args[0] );
		}

		$settings                = Ironhide_Guard::get_settings();
		$settings['allowed_ips'] = array_values( array_unique( array_merge( $settings['allowed_ips'], array( $entry ) ) ) );
		self::save( $settings );

		if ( Ironhide_Core::entry_is_universal( $entry ) ) {
			WP_CLI::warning( sprintf( '%s matches every address — nothing will be blocked.', $entry ) );
		}

		WP_CLI::success( sprintf( 'Allowed: %s', $entry ) );
	}

	/**
	 * Remove an entry from the allowlist.
	 *
	 * ## OPTIONS
	 *
	 * <entry>
	 * : An IP address, CIDR range, or IPv4 wildcard.
	 *
	 * @param array $args Positional args.
	 * @return void
	 */
	public static function cmd_remove( $args ) {
		if ( empty( $args[0] ) ) {
			WP_CLI::error( 'Usage: wp ironhide remove <ip|CIDR|wildcard>' );
		}

		$entry = Ironhide_Core::sanitize_ip_entry( $args[0] );
		if ( false === $entry ) {
			WP_CLI::error( 'Invalid IP/CIDR/wildcard: ' . $args[0] );
		}

		$settings = Ironhide_Guard::get_settings();
		$before   = count( $settings['allowed_ips'] );

		$settings['allowed_ips'] = array_values( array_diff( $settings['allowed_ips'], array( $entry ) ) );
		self::save( $settings );

		if ( count( $settings['allowed_ips'] ) === $before ) {
			WP_CLI::warning( sprintf( 'Entry was not in the list: %s', $entry ) );
			return;
		}

		if ( empty( $settings['allowed_ips'] ) && Ironhide_Guard::MODE_OFF !== $settings['mode'] ) {
			WP_CLI::warning( 'The allowlist is now empty, so nothing is blocked (fail open).' );
		}

		WP_CLI::success( sprintf( 'Removed: %s', $entry ) );
	}

	/**
	 * Print the allowlist.
	 *
	 * @return void
	 */
	public static function cmd_list() {
		$settings = Ironhide_Guard::get_settings();

		if ( empty( $settings['allowed_ips'] ) ) {
			WP_CLI::line( '(allowlist is empty — nothing is blocked)' );
			return;
		}

		foreach ( $settings['allowed_ips'] as $entry ) {
			WP_CLI::line( $entry );
		}
	}

	/**
	 * Set the protection mode.
	 *
	 * ## OPTIONS
	 *
	 * <mode>
	 * : One of off, monitor, enforce.
	 *
	 * @param array $args Positional args.
	 * @return void
	 */
	public static function cmd_mode( $args ) {
		$mode = isset( $args[0] ) ? strtolower( trim( (string) $args[0] ) ) : '';

		if ( ! in_array( $mode, Ironhide_Guard::modes(), true ) ) {
			WP_CLI::error( 'Usage: wp ironhide mode <' . implode( '|', Ironhide_Guard::modes() ) . '>' );
		}

		self::set_mode( $mode );
	}

	/**
	 * Switch to monitor mode (log would-be blocks, block nothing).
	 *
	 * @return void
	 */
	public static function cmd_monitor() {
		self::set_mode( Ironhide_Guard::MODE_MONITOR );
	}

	/**
	 * Switch to enforce mode.
	 *
	 * @return void
	 */
	public static function cmd_enforce() {
		self::set_mode( Ironhide_Guard::MODE_ENFORCE );
	}

	/**
	 * Switch protection off (recovery command; the allowlist is preserved).
	 *
	 * @return void
	 */
	public static function cmd_off() {
		self::set_mode( Ironhide_Guard::MODE_OFF );
	}

	/**
	 * Show recent block / would-block activity.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<number>]
	 * : How many records to show. Default 20.
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Associative args.
	 * @return void
	 */
	public static function cmd_log( $args, $assoc_args = array() ) {
		$limit   = isset( $assoc_args['limit'] ) ? max( 1, (int) $assoc_args['limit'] ) : 20;
		$records = Ironhide_Logger::recent( $limit );

		if ( empty( $records ) ) {
			WP_CLI::line( '(no entries)' );
			return;
		}

		WP_CLI\Utils\format_items(
			'table',
			$records,
			array( 'time', 'event', 'ip', 'where', 'user', 'uri' )
		);
	}
}
