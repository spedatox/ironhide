<?php
/**
 * Uninstall: remove the option, the log directory, and any queued notices.
 *
 * Runs only on a full plugin deletion (WordPress invokes uninstall.php when the
 * plugin is deleted, not merely deactivated).
 *
 * @package Ironhide
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// The logger owns the log filename, which is salt-derived and therefore not
// knowable from here. Load it rather than duplicating the derivation.
require_once __DIR__ . '/includes/class-ironhide-logger.php';

delete_option( 'ironhide_settings' );

// Queued admin notices can name the address that was auto-added to the
// allowlist. They are short-lived transients, but an expired transient survives
// in the options table until something asks for it, so clear them explicitly.
global $wpdb;

if ( isset( $wpdb ) ) {
	$ironhide_like = $wpdb->esc_like( '_transient_ironhide_notices_' ) . '%';
	$ironhide_tmo  = $wpdb->esc_like( '_transient_timeout_ironhide_notices_' ) . '%';

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$ironhide_like,
			$ironhide_tmo
		)
	);
}

// Remove the log directory. Every file the plugin writes must go first,
// including the .htaccess / web.config guards, or rmdir() silently fails and
// leaves the directory — and the log — behind.
$ironhide_dir = Ironhide_Logger::dir_path();

if ( '' !== $ironhide_dir && is_dir( $ironhide_dir ) ) {

	foreach ( Ironhide_Logger::owned_files() as $ironhide_file ) {
		$ironhide_path = $ironhide_dir . '/' . $ironhide_file;
		if ( is_file( $ironhide_path ) ) {
			@unlink( $ironhide_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
	}

	// Rotating the site salts changes the log filename, so older logs may be
	// orphaned under a name owned_files() no longer knows. Sweep the pattern.
	$ironhide_orphans = glob(
		$ironhide_dir . '/' . Ironhide_Logger::FILE_PREFIX . '*' . Ironhide_Logger::FILE_SUFFIX . '*'
	);

	if ( is_array( $ironhide_orphans ) ) {
		foreach ( $ironhide_orphans as $ironhide_orphan ) {
			if ( is_file( $ironhide_orphan ) ) {
				@unlink( $ironhide_orphan ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			}
		}
	}

	// Only removes the directory when nothing unexpected is left in it.
	@rmdir( $ironhide_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
}
