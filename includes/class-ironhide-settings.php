<?php
/**
 * Admin settings screen and option sanitisation.
 *
 * The critical safety behaviour lives in sanitize_settings(): whatever the guard
 * would evaluate as "this visitor's IP" is appended to the allowlist on save, so
 * the person configuring the plugin can never lock themselves out in the moment
 * they save.
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings.
 */
class Ironhide_Settings {

	const PAGE       = 'ironhide';
	const GROUP      = 'ironhide_group';
	const LOG_LIMIT  = 25;
	const CAPABILITY = 'manage_options';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_notices' ) );

		add_filter(
			'plugin_action_links_' . plugin_basename( IRONHIDE_PLUGIN_FILE ),
			array( __CLASS__, 'action_links' )
		);
	}

	/**
	 * Add the options page under Settings.
	 *
	 * @return void
	 */
	public static function add_menu() {
		add_options_page(
			__( 'Ironhide', 'ironhide' ),
			__( 'Ironhide', 'ironhide' ),
			self::CAPABILITY,
			self::PAGE,
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * URL of the settings page.
	 *
	 * @return string
	 */
	public static function page_url() {
		return admin_url( 'options-general.php?page=' . self::PAGE );
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public static function action_links( $links ) {
		return array_merge(
			array( '<a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Settings', 'ironhide' ) . '</a>' ),
			(array) $links
		);
	}

	/**
	 * Register the single settings option with a sanitise callback.
	 *
	 * @return void
	 */
	public static function register_settings() {
		register_setting(
			self::GROUP,
			Ironhide_Guard::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize_settings' ),
				// Explicit, not merely default: exposing this through
				// /wp-json/wp/v2/settings would publish the allowlist to every
				// caller the endpoint authorises. It must stay off.
				'show_in_rest'      => false,
			)
		);

		add_settings_section(
			'ironhide_main',
			__( 'Access control', 'ironhide' ),
			array( __CLASS__, 'render_section_intro' ),
			self::PAGE
		);

		$fields = array(
			'mode'            => __( 'Protection', 'ironhide' ),
			'allowed_ips'     => __( 'Allowed IP addresses', 'ironhide' ),
			'trust_headers'   => __( 'Forwarding headers', 'ironhide' ),
			'trusted_proxies' => __( 'Trusted proxies', 'ironhide' ),
			'ajax_policy'     => __( 'admin-ajax / admin-post', 'ironhide' ),
			'log_blocks'      => __( 'Logging', 'ironhide' ),
		);

		foreach ( $fields as $key => $label ) {
			add_settings_field(
				$key,
				$label,
				array( __CLASS__, 'field_' . $key ),
				self::PAGE,
				'ironhide_main'
			);
		}
	}

	/**
	 * Section intro text.
	 *
	 * @return void
	 */
	public static function render_section_intro() {
		echo '<p class="description">';
		esc_html_e( 'Ironhide gates the WordPress admin area (wp-admin) only. The login page, REST API and XML-RPC are deliberately out of scope.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * "Protection" field: off / monitor / enforce.
	 *
	 * @return void
	 */
	public static function field_mode() {
		$settings = Ironhide_Guard::get_settings();

		$choices = array(
			Ironhide_Guard::MODE_OFF     => array(
				__( 'Off', 'ironhide' ),
				__( 'Nothing is checked and nothing is blocked.', 'ironhide' ),
			),
			Ironhide_Guard::MODE_MONITOR => array(
				__( 'Monitor', 'ironhide' ),
				__( 'Nothing is blocked, but every request that would have been blocked is written to the log. Run this for a day before enforcing.', 'ironhide' ),
			),
			Ironhide_Guard::MODE_ENFORCE => array(
				__( 'Enforce', 'ironhide' ),
				__( 'Requests from addresses outside the allowlist are refused with a 403.', 'ironhide' ),
			),
		);

		foreach ( $choices as $value => $choice ) {
			printf(
				'<p><label><input type="radio" name="%1$s[mode]" value="%2$s" %3$s /> <strong>%4$s</strong></label><br /><span class="description" style="margin-left:1.8em;display:inline-block">%5$s</span></p>',
				esc_attr( Ironhide_Guard::OPTION ),
				esc_attr( $value ),
				checked( $settings['mode'], $value, false ),
				esc_html( $choice[0] ),
				esc_html( $choice[1] )
			);
		}
	}

	/**
	 * "Allowed IP addresses" field.
	 *
	 * @return void
	 */
	public static function field_allowed_ips() {
		$settings = Ironhide_Guard::get_settings();

		printf(
			'<textarea name="%1$s[allowed_ips]" rows="6" cols="50" class="large-text code">%2$s</textarea>',
			esc_attr( Ironhide_Guard::OPTION ),
			esc_textarea( implode( "\n", $settings['allowed_ips'] ) )
		);
		echo '<p class="description">';
		esc_html_e( 'One entry per line. Accepts single IPs, CIDR ranges (203.0.113.0/24, 2001:db8::/48) and IPv4 wildcards (192.168.1.*). Your current IP is added automatically on save.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * "Forwarding headers" field.
	 *
	 * @return void
	 */
	public static function field_trust_headers() {
		$settings = Ironhide_Guard::get_settings();

		printf(
			'<label><input type="checkbox" name="%1$s[trust_headers]" value="1" %2$s /> %3$s</label>',
			esc_attr( Ironhide_Guard::OPTION ),
			checked( $settings['trust_headers'], true, false ),
			esc_html__( 'Trust X-Forwarded-For / X-Real-IP headers', 'ironhide' )
		);
		echo '<p class="description">';
		esc_html_e( 'Only enable behind a reverse proxy or CDN (Cloudflare, nginx, load balancer), and list that proxy below. Otherwise the header is spoofable and the allowlist is worthless.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * "Trusted proxies" field.
	 *
	 * @return void
	 */
	public static function field_trusted_proxies() {
		$settings = Ironhide_Guard::get_settings();

		printf(
			'<textarea name="%1$s[trusted_proxies]" rows="4" cols="50" class="large-text code">%2$s</textarea>',
			esc_attr( Ironhide_Guard::OPTION ),
			esc_textarea( implode( "\n", $settings['trusted_proxies'] ) )
		);
		echo '<p class="description">';
		esc_html_e( 'One entry per line, same formats as above. Only consulted when forwarding headers are trusted.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * "admin-ajax / admin-post" policy field.
	 *
	 * @return void
	 */
	public static function field_ajax_policy() {
		$settings = Ironhide_Guard::get_settings();

		$choices = array(
			Ironhide_Guard::AJAX_PUBLIC_ONLY => __( 'Gate logged-in requests only (recommended)', 'ironhide' ),
			Ironhide_Guard::AJAX_OPEN        => __( 'Never gate these endpoints', 'ironhide' ),
			Ironhide_Guard::AJAX_GATED       => __( 'Always gate these endpoints', 'ironhide' ),
		);

		printf( '<select name="%s[ajax_policy]">', esc_attr( Ironhide_Guard::OPTION ) );
		foreach ( $choices as $value => $label ) {
			printf(
				'<option value="%1$s" %2$s>%3$s</option>',
				esc_attr( $value ),
				selected( $settings['ajax_policy'], $value, false ),
				esc_html( $label )
			);
		}
		echo '</select>';

		echo '<p class="description">';
		esc_html_e( 'These two files live in wp-admin but serve the public site. The recommended setting lets anonymous requests through — which is what public contact forms and payment callbacks need — while holding authenticated requests to the same allowlist as the dashboard. Choose "always gate" only if no public form depends on them.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * "Logging" field.
	 *
	 * @return void
	 */
	public static function field_log_blocks() {
		$settings = Ironhide_Guard::get_settings();

		printf(
			'<label><input type="checkbox" name="%1$s[log_blocks]" value="1" %2$s /> %3$s</label>',
			esc_attr( Ironhide_Guard::OPTION ),
			checked( $settings['log_blocks'], true, false ),
			esc_html__( 'Record blocked (and would-be blocked) requests', 'ironhide' )
		);
		echo '<p class="description">';
		esc_html_e( 'Required for monitor mode to tell you anything.', 'ironhide' );
		echo '</p>';
	}

	/**
	 * Sanitise and normalise the submitted settings.
	 *
	 * Builds the result from a known key set, so a crafted POST cannot smuggle
	 * extra keys into the stored option.
	 *
	 * @param array|mixed $input Raw submitted value.
	 * @return array
	 */
	public static function sanitize_settings( $input ) {
		$input = is_array( $input ) ? $input : array();
		$out   = Ironhide_Guard::defaults();

		$mode = isset( $input['mode'] ) && is_scalar( $input['mode'] ) ? (string) $input['mode'] : '';
		if ( in_array( $mode, Ironhide_Guard::modes(), true ) ) {
			$out['mode'] = $mode;
		}

		$policy = isset( $input['ajax_policy'] ) && is_scalar( $input['ajax_policy'] ) ? (string) $input['ajax_policy'] : '';
		if ( in_array( $policy, Ironhide_Guard::ajax_policies(), true ) ) {
			$out['ajax_policy'] = $policy;
		}

		$out['trust_headers'] = ! empty( $input['trust_headers'] );
		$out['log_blocks']    = ! empty( $input['log_blocks'] );

		$allowed = self::parse_ip_list( isset( $input['allowed_ips'] ) ? $input['allowed_ips'] : '' );
		$proxies = self::parse_ip_list( isset( $input['trusted_proxies'] ) ? $input['trusted_proxies'] : '' );

		$out['allowed_ips']     = $allowed['valid'];
		$out['trusted_proxies'] = $proxies['valid'];

		$notices = array();

		if ( ! empty( $allowed['invalid'] ) ) {
			$notices[] = sprintf(
				/* translators: %s: comma-separated list of rejected entries. */
				__( 'Ignored invalid allowlist entries: %s.', 'ironhide' ),
				implode( ', ', array_slice( $allowed['invalid'], 0, 10 ) )
			);
		}
		if ( ! empty( $proxies['invalid'] ) ) {
			$notices[] = sprintf(
				/* translators: %s: comma-separated list of rejected entries. */
				__( 'Ignored invalid proxy entries: %s.', 'ironhide' ),
				implode( ', ', array_slice( $proxies['invalid'], 0, 10 ) )
			);
		}

		// Anti-lockout invariant: the IP the guard would evaluate right now is
		// always added, so saving can never immediately block the saver.
		$current = Ironhide_Core::get_effective_ip( $out );

		if ( '' === $current ) {
			// Cannot determine the saver's IP: refuse to enforce, rather than
			// risk blocking everyone including the saver.
			if ( Ironhide_Guard::MODE_ENFORCE === $out['mode'] ) {
				$out['mode'] = Ironhide_Guard::MODE_OFF;
				$notices[]   = __( 'Your IP address could not be determined, so protection was left off to avoid a lockout. Check your server or proxy configuration.', 'ironhide' );
			}
		} elseif ( ! Ironhide_Core::ip_in_list( $current, $out['allowed_ips'] ) ) {
			$out['allowed_ips'][] = $current;
			$notices[]            = sprintf(
				/* translators: %s: the IP address that was auto-added. */
				__( 'Your current IP (%s) was added to the allowlist so you are not locked out.', 'ironhide' ),
				$current
			);
		}

		// An entry that matches everything silently turns protection off.
		// Reported as a count rather than a list: the entries are visible in the
		// form directly above, and a notice is stored in a transient, so echoing
		// them would copy allowlist content into a second place for no gain.
		$universal = count( array_filter( $out['allowed_ips'], array( 'Ironhide_Core', 'entry_is_universal' ) ) );
		if ( $universal > 0 ) {
			$notices[] = sprintf(
				/* translators: %d: how many entries match every address. */
				_n(
					'Warning: %d entry in your allowlist matches every address, so nothing will be blocked.',
					'Warning: %d entries in your allowlist match every address, so nothing will be blocked.',
					$universal,
					'ironhide'
				),
				$universal
			);
		}

		// Warn about the one proxy configuration that is silently wrong.
		if ( $out['trust_headers'] && ! Ironhide_Core::ip_in_list( Ironhide_Core::get_remote_addr(), $out['trusted_proxies'] ) ) {
			$notices[] = __( 'Warning: forwarding headers are trusted, but your immediate peer is not in the trusted proxy list. Header spoofing is possible — anyone could claim an allowlisted address.', 'ironhide' );
		}

		if ( Ironhide_Guard::MODE_ENFORCE === $out['mode'] && ! $out['log_blocks'] ) {
			$notices[] = __( 'Enforcing with logging off: you will have no record of who was refused.', 'ironhide' );
		}

		$out['allowed_ips']     = array_values( array_unique( $out['allowed_ips'] ) );
		$out['trusted_proxies'] = array_values( array_unique( $out['trusted_proxies'] ) );

		self::set_notices( $notices );

		return $out;
	}

	/**
	 * Split a raw textarea value into validated entries.
	 *
	 * @param string|array $raw Raw value.
	 * @return array{valid:string[], invalid:string[]}
	 */
	private static function parse_ip_list( $raw ) {
		if ( is_array( $raw ) ) {
			$raw = implode( "\n", array_filter( $raw, 'is_scalar' ) );
		}
		if ( ! is_scalar( $raw ) ) {
			$raw = '';
		}

		$entries = preg_split( '/[\r\n,\s]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY );

		$valid   = array();
		$invalid = array();

		foreach ( (array) $entries as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry ) {
				continue;
			}
			$normalised = Ironhide_Core::sanitize_ip_entry( $entry );
			if ( false === $normalised ) {
				$invalid[] = $entry;
			} else {
				$valid[] = $normalised;
			}
		}

		return array(
			'valid'   => array_values( array_unique( $valid ) ),
			'invalid' => array_values( array_unique( $invalid ) ),
		);
	}

	/**
	 * Store admin notices for the next page load.
	 *
	 * @param array $notices Notice strings.
	 * @return void
	 */
	private static function set_notices( $notices ) {
		$notices = array_values( array_filter( array_map( 'strval', $notices ) ) );
		if ( empty( $notices ) ) {
			return;
		}
		set_transient( self::notice_key(), $notices, 60 );
	}

	/**
	 * Transient key for the current user's queued notices.
	 *
	 * @return string
	 */
	private static function notice_key() {
		return 'ironhide_notices_' . get_current_user_id();
	}

	/**
	 * Print and clear any queued notices.
	 *
	 * @return void
	 */
	public static function render_notices() {
		// Queued notices can name the address that was auto-added to the
		// allowlist, so they are held to the same capability as the settings
		// screen rather than shown to whoever happens to load an admin page.
		if ( ! get_current_user_id() || ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$notices = get_transient( self::notice_key() );
		if ( ! is_array( $notices ) || empty( $notices ) ) {
			return;
		}
		delete_transient( self::notice_key() );

		foreach ( $notices as $notice ) {
			echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html( $notice ) . '</p></div>';
		}
	}

	/**
	 * Render the options page.
	 *
	 * @return void
	 */
	public static function render_page() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$settings = Ironhide_Guard::get_settings();
		$current  = Ironhide_Core::get_effective_ip( $settings );
		$remote   = Ironhide_Core::get_remote_addr();
		$mode     = Ironhide_Guard::active_mode( $settings );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Ironhide', 'ironhide' ); ?></h1>
			<p class="description"><?php esc_html_e( 'IP allowlist for the WordPress admin area.', 'ironhide' ); ?></p>

			<?php if ( Ironhide_Recovery::hard_disabled() ) : ?>
				<div class="notice notice-warning">
					<p><?php esc_html_e( 'Protection is currently bypassed: the IRONHIDE_DISABLE constant or the emergency marker file is present. Remove it to resume enforcement.', 'ironhide' ); ?></p>
				</div>
			<?php endif; ?>

			<div class="notice notice-info">
				<p>
					<?php
					printf(
						/* translators: 1: effective IP, 2: server-reported IP. */
						esc_html__( 'Detected IP: %1$s (server-reported: %2$s).', 'ironhide' ),
						'<strong>' . esc_html( '' !== $current ? $current : __( 'unknown', 'ironhide' ) ) . '</strong>',
						'<strong>' . esc_html( '' !== $remote ? $remote : __( 'unknown', 'ironhide' ) ) . '</strong>'
					);
					?>
					<br />
					<?php if ( Ironhide_Guard::MODE_ENFORCE === $mode ) : ?>
						<strong><?php esc_html_e( 'Enforcing.', 'ironhide' ); ?></strong>
						<?php esc_html_e( 'Only listed IP addresses can reach wp-admin.', 'ironhide' ); ?>
					<?php elseif ( Ironhide_Guard::MODE_MONITOR === $mode ) : ?>
						<strong><?php esc_html_e( 'Monitoring.', 'ironhide' ); ?></strong>
						<?php esc_html_e( 'Nothing is blocked; would-be blocks are being logged below.', 'ironhide' ); ?>
					<?php else : ?>
						<strong><?php esc_html_e( 'Not enforcing anything.', 'ironhide' ); ?></strong>
						<?php esc_html_e( 'Protection stays inert until the mode is set and the allowlist has at least one entry.', 'ironhide' ); ?>
					<?php endif; ?>
				</p>
			</div>

			<form method="post" action="options.php">
				<?php
				settings_fields( self::GROUP );
				do_settings_sections( self::PAGE );
				submit_button();
				?>
			</form>

			<hr />

			<?php self::render_activity( $settings ); ?>

			<hr />

			<h2><?php esc_html_e( 'Recovery (if you ever lock yourself out)', 'ironhide' ); ?></h2>
			<ol>
				<li>
					<strong><?php esc_html_e( 'Ironhide fails open.', 'ironhide' ); ?></strong>
					<?php esc_html_e( 'With the mode off, or the allowlist empty, nothing is blocked.', 'ironhide' ); ?>
				</li>
				<li>
					<strong><?php esc_html_e( 'Emergency disable constant.', 'ironhide' ); ?></strong>
					<?php esc_html_e( 'Add to wp-config.php:', 'ironhide' ); ?>
					<code>define( 'IRONHIDE_DISABLE', true );</code>
				</li>
				<li>
					<strong><?php esc_html_e( 'Emergency marker file.', 'ironhide' ); ?></strong>
					<?php esc_html_e( 'Create an empty file at:', 'ironhide' ); ?>
					<code><?php echo esc_html( Ironhide_Recovery::disable_file_path() ); ?></code>
				</li>
				<li>
					<strong><?php esc_html_e( 'URL bypass key.', 'ironhide' ); ?></strong>
					<?php esc_html_e( 'Define a secret in wp-config.php:', 'ironhide' ); ?>
					<code>define( 'IRONHIDE_BYPASS_KEY', 'your-long-random-secret' );</code>
					<?php esc_html_e( 'then visit:', 'ironhide' ); ?>
					<code><?php echo esc_html( admin_url( '?' . Ironhide_Recovery::QUERY_KEY . '=your-long-random-secret' ) ); ?></code>
				</li>
				<li>
					<strong><?php esc_html_e( 'WP-CLI.', 'ironhide' ); ?></strong>
					<code>wp ironhide off</code> <?php esc_html_e( 'or', 'ironhide' ); ?>
					<code>wp ironhide allow 203.0.113.10</code>
				</li>
			</ol>
		</div>
		<?php
	}

	/**
	 * Recent block / would-block activity.
	 *
	 * @param array $settings Merged settings.
	 * @return void
	 */
	public static function render_activity( $settings ) {
		$records = Ironhide_Logger::recent( self::LOG_LIMIT );
		?>
		<h2><?php esc_html_e( 'Recent activity', 'ironhide' ); ?></h2>

		<?php if ( empty( $settings['log_blocks'] ) ) : ?>
			<p class="description"><?php esc_html_e( 'Logging is switched off, so nothing is being recorded.', 'ironhide' ); ?></p>
		<?php endif; ?>

		<?php if ( empty( $records ) ) : ?>
			<p class="description"><?php esc_html_e( 'No entries yet.', 'ironhide' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Time (UTC)', 'ironhide' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Event', 'ironhide' ); ?></th>
						<th scope="col"><?php esc_html_e( 'IP', 'ironhide' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Where', 'ironhide' ); ?></th>
						<th scope="col"><?php esc_html_e( 'User', 'ironhide' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Request', 'ironhide' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $records as $record ) : ?>
						<tr>
							<td><?php echo esc_html( $record['time'] ); ?></td>
							<td>
								<?php
								echo esc_html(
									'would_block' === $record['event']
										? __( 'would block', 'ironhide' )
										: $record['event']
								);
								?>
							</td>
							<td><code><?php echo esc_html( $record['ip'] ); ?></code></td>
							<td><?php echo esc_html( $record['where'] ); ?></td>
							<td><?php echo esc_html( $record['user'] ); ?></td>
							<td><code><?php echo esc_html( $record['uri'] ); ?></code></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<p class="description">
			<?php
			printf(
				/* translators: %s: absolute path of the log file. */
				esc_html__( 'Full log: %s', 'ironhide' ),
				'<code>' . esc_html( Ironhide_Logger::file_path() ) . '</code>'
			);
			?>
			<br />
			<?php esc_html_e( 'The directory is protected by .htaccess (Apache) and web.config (IIS). On nginx you must add an equivalent deny rule yourself — see README.md.', 'ironhide' ); ?>
		</p>
		<?php
	}
}
