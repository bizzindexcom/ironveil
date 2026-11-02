<?php
/**
 * Uninstall: remove every table, option, user meta, cron event, rule block
 * and file IronVeil created. Define IRONVEIL_KEEP_DATA to keep data.
 *
 * @package IronVeil
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( defined( 'IRONVEIL_KEEP_DATA' ) && IRONVEIL_KEEP_DATA ) {
	return;
}

/**
 * Remove data for the current site.
 */
function ironveil_uninstall_site() {
	global $wpdb;
	foreach ( array( 'ironveil_log', 'ironveil_blocks', 'ironveil_files', 'ironveil_issues' ) as $t ) {
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . $t ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange
	}
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", 'ironveil%', '_transient_ironveil%', '_transient_timeout_ironveil%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	foreach ( array( 'ironveil_hourly', 'ironveil_daily', 'ironveil_scheduled_scan', 'ironveil_scan_step', 'ironveil_server_scan' ) as $hook ) {
		wp_clear_scheduled_hook( $hook );
	}
	require_once ABSPATH . 'wp-admin/includes/misc.php';
	$up = wp_upload_dir( null, false );
	if ( ! empty( $up['basedir'] ) && is_file( $up['basedir'] . '/.htaccess' ) ) {
		insert_with_markers( $up['basedir'] . '/.htaccess', 'IronVeil Security', array() );
	}
	if ( is_file( ABSPATH . '.htaccess' ) && false !== strpos( (string) file_get_contents( ABSPATH . '.htaccess' ), 'BEGIN IronVeil Server Protection' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		insert_with_markers( ABSPATH . '.htaccess', 'IronVeil Server Protection', array() );
	}
}


if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $ironveil_blog ) {
		switch_to_blog( $ironveil_blog );
		ironveil_uninstall_site();
		restore_current_blog();
	}
} else {
	ironveil_uninstall_site();
}

global $wpdb;
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", 'ironveil%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

$ironveil_mu = trailingslashit( WPMU_PLUGIN_DIR ) . '0-ironveil-firewall.php';
if ( is_file( $ironveil_mu ) ) {
	wp_delete_file( $ironveil_mu );
}

// Quarantine folders: uploads/ironveil-quarantine-<random> (1.3.2+) and the legacy wp-content/ironveil-quarantine.
$ironveil_up      = wp_upload_dir( null, false );
$ironveil_folders = array( trailingslashit( WP_CONTENT_DIR ) . 'ironveil-quarantine' );
if ( ! empty( $ironveil_up['basedir'] ) && is_dir( $ironveil_up['basedir'] ) ) {
	foreach ( (array) scandir( $ironveil_up['basedir'] ) as $ironveil_d ) {
		if ( preg_match( '/^ironveil-quarantine-[a-f0-9]{16}$/', (string) $ironveil_d ) ) {
			$ironveil_folders[] = trailingslashit( $ironveil_up['basedir'] ) . $ironveil_d;
		}
	}
}
foreach ( $ironveil_folders as $ironveil_q ) {
	if ( ! is_dir( $ironveil_q ) ) {
		continue;
	}
	foreach ( (array) scandir( $ironveil_q ) as $ironveil_f ) {
		if ( is_file( $ironveil_q . '/' . $ironveil_f ) ) {
			wp_delete_file( $ironveil_q . '/' . $ironveil_f );
		}
	}
	@rmdir( $ironveil_q ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
}
