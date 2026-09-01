<?php
/**
 * Plugin Name:       Ironhide
 * Description:       Restrict the WordPress admin area (wp-admin) to an allowlist of IP addresses / CIDR ranges, with a monitor mode and built-in lockout recovery.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Optimus (Forge)
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ironhide
 * Domain Path:       /languages
 *
 * @package Ironhide
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // No direct access.
}

define( 'IRONHIDE_VERSION', '1.0.0' );
define( 'IRONHIDE_PLUGIN_FILE', __FILE__ );
define( 'IRONHIDE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-core.php';
require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-recovery.php';
require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-logger.php';
require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-guard.php';
require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-settings.php';
require_once IRONHIDE_PLUGIN_DIR . 'includes/class-ironhide-cli.php';

/**
 * Load translations.
 *
 * Hooked to `init` at priority 0 rather than `plugins_loaded`: WordPress 6.7+
 * emits a _doing_it_wrong() notice for textdomains loaded before `init`, and
 * priority 0 still lands before the guard runs at priority 1, so a 403 page is
 * translated.
 *
 * @return void
 */
function ironhide_load_textdomain() {
	load_plugin_textdomain(
		'ironhide',
		false,
		dirname( plugin_basename( IRONHIDE_PLUGIN_FILE ) ) . '/languages'
	);
}
add_action( 'init', 'ironhide_load_textdomain', 0 );

/**
 * Bootstrap: wire the plugin together.
 *
 * Registration happens on `plugins_loaded` so every class file is loaded first.
 * Enforcement itself runs later, on `init` at priority 1 — see Ironhide_Guard.
 *
 * @return void
 */
function ironhide_bootstrap() {
	Ironhide_Guard::init();
	Ironhide_Settings::init();
	Ironhide_CLI::register();
}
add_action( 'plugins_loaded', 'ironhide_bootstrap' );

/**
 * Create the option with autoload disabled.
 *
 * WordPress autoloads newly created options by default, which would put the
 * allowlist into the alloptions blob loaded on *every* front-end request. It is
 * only ever needed inside wp-admin, so it is created with autoload off and read
 * with a dedicated query. Any future update_option() preserves that.
 *
 * @return void
 */
function ironhide_activate() {
	if ( false === get_option( Ironhide_Guard::OPTION, false ) ) {
		add_option( Ironhide_Guard::OPTION, Ironhide_Guard::defaults(), '', false );
	}
}
register_activation_hook( __FILE__, 'ironhide_activate' );
