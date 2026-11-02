<?php
/**
 * Activation / deactivation / schema upgrades, the optional early-loading
 * MU loader ("extended protection") and web-server rule snippets.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Installer {

	const MU_FILE       = '0-ironveil-firewall.php';
	const HT_MARKER     = 'IronVeil Security';
	const CRON_HOURLY   = 'ironveil_hourly';
	const CRON_DAILY    = 'ironveil_daily';
	const CRON_SCAN     = 'ironveil_scheduled_scan';
	const CRON_SCANSTEP = 'ironveil_scan_step';

	/**
	 * @param bool $network_wide Network activation.
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			foreach ( get_sites( array( 'fields' => 'ids', 'number' => 500 ) ) as $blog_id ) {
				switch_to_blog( $blog_id );
				self::install_site();
				restore_current_blog();
			}
		} else {
			self::install_site();
		}
	}

	/**
	 * Install for the current site.
	 */
	public static function install_site() {
		self::create_tables();
		if ( false === get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, array(), '', true );
		}
		if ( false === get_option( Blocklist::CACHE_OPTION ) ) {
			add_option( Blocklist::CACHE_OPTION, array( 'n' => 0, 'e' => array(), 'r' => array() ), '', true );
		}
		update_option( 'ironveil_db_version', IRONVEIL_DB_VERSION, true );
		Blocklist::rebuild_cache();
		self::schedule();
		Hardening::sync_server_rules();
		Log::add( 'plugin_activated', 'IronVeil Security activated', Log::NOTICE );
	}

	/**
	 * Deactivate: remove cron + MU loader, keep data.
	 */
	public static function deactivate() {
		foreach ( array( self::CRON_HOURLY, self::CRON_DAILY, self::CRON_SCAN, self::CRON_SCANSTEP, Server_Scan::CRON ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
		self::remove_mu_loader();
		Hardening::remove_server_rules();
		Server_Scan::remove_root_rules();
	}

	/**
	 * Run dbDelta if schema version changed; migrate settings once per release.
	 */
	public static function maybe_upgrade() {
		if ( (int) get_option( 'ironveil_db_version' ) < IRONVEIL_DB_VERSION ) {
			self::install_site();
		}
		if ( version_compare( (string) get_option( 'ironveil_version', '0' ), IRONVEIL_VERSION, '<' ) ) {
			if ( version_compare( (string) get_option( 'ironveil_version', '0' ), '1.3.1', '<' ) ) {
				self::remove_two_factor_data();
			}
			self::migrate( (string) get_option( 'ironveil_version', '0' ) );

			update_option( 'ironveil_version', IRONVEIL_VERSION, true );
		}
	}

	/**
	 * One-time settings migration: turn on protections added in a release for
	 * sites that saved their settings before those options existed.
	 *
	 * @param string $from Previously installed version ('0' = unknown / fresh).
	 */
	private static function migrate( $from ) {
		$stored = get_option( Settings::OPTION );
		if ( ! is_array( $stored ) || ! $stored ) {
			self::schedule();
			return; // Fresh install or defaults only: new defaults already apply.
		}
		if ( version_compare( $from, '1.3.0', '<' ) ) {
			if ( isset( $stored['fw_rules'] ) && is_array( $stored['fw_rules'] ) ) {
				$stored['fw_rules'] = array_values( array_unique( array_merge( $stored['fw_rules'], array( 'ssrf', 'xxe', 'crlf', 'protocol' ) ) ) );
			}
			if ( isset( $stored['notify_events'] ) && is_array( $stored['notify_events'] ) ) {
				$stored['notify_events'] = array_values( array_unique( array_merge( $stored['notify_events'], array( 'verify', 'server' ) ) ) );
			}
			update_option( Settings::OPTION, $stored, true );
			Settings::flush();
		}
		self::schedule();
	}

	/**
	 * 1.3.1 removed two-factor authentication: delete the stored secrets,
	 * recovery codes and pending challenges, and the settings that went with it.
	 */
	private static function remove_two_factor_data() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'ironveil_2fa_' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$stored = get_option( Settings::OPTION );
		if ( is_array( $stored ) ) {
			unset( $stored['twofa_roles'], $stored['twofa_remember_days'], $stored['verify_email'] );
			update_option( Settings::OPTION, $stored, true );
			Settings::flush();
		}
	}

	/**
	 * Create / update tables.
	 */
	public static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$c = $wpdb->get_charset_collate();
		$p = $wpdb->prefix;

		dbDelta(
			"CREATE TABLE {$p}ironveil_log (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created int(10) unsigned NOT NULL DEFAULT 0,
  event varchar(40) NOT NULL DEFAULT '',
  severity tinyint(3) unsigned NOT NULL DEFAULT 1,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  ip varchar(45) NOT NULL DEFAULT '',
  uri varchar(255) NOT NULL DEFAULT '',
  message varchar(255) NOT NULL DEFAULT '',
  context text NULL,
  chain char(64) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY created (created),
  KEY event_created (event,created),
  KEY ip (ip)
) {$c};"
		);
		dbDelta(
			"CREATE TABLE {$p}ironveil_blocks (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ip_from char(32) NOT NULL DEFAULT '',
  ip_to char(32) NOT NULL DEFAULT '',
  label varchar(64) NOT NULL DEFAULT '',
  reason varchar(190) NOT NULL DEFAULT '',
  source varchar(20) NOT NULL DEFAULT 'manual',
  created int(10) unsigned NOT NULL DEFAULT 0,
  expires int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY range_idx (ip_from,ip_to),
  KEY expires (expires)
) {$c};"
		);
		dbDelta(
			"CREATE TABLE {$p}ironveil_files (
  path_hash char(32) NOT NULL DEFAULT '',
  path text NOT NULL,
  size bigint(20) unsigned NOT NULL DEFAULT 0,
  mtime int(10) unsigned NOT NULL DEFAULT 0,
  md5 char(32) NOT NULL DEFAULT '',
  sig_ver int(10) unsigned NOT NULL DEFAULT 0,
  verdict tinyint(3) unsigned NOT NULL DEFAULT 0,
  first_scan int(10) unsigned NOT NULL DEFAULT 0,
  seen_scan int(10) unsigned NOT NULL DEFAULT 0,
  checked_scan int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (path_hash),
  KEY seen_checked (seen_scan,checked_scan)
) {$c};"
		);
		dbDelta(
			"CREATE TABLE {$p}ironveil_issues (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  ikey char(32) NOT NULL DEFAULT '',
  type varchar(40) NOT NULL DEFAULT '',
  severity tinyint(3) unsigned NOT NULL DEFAULT 1,
  path text NULL,
  detail varchar(255) NOT NULL DEFAULT '',
  status varchar(12) NOT NULL DEFAULT 'open',
  data text NULL,
  scan_id int(10) unsigned NOT NULL DEFAULT 0,
  created int(10) unsigned NOT NULL DEFAULT 0,
  updated int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  UNIQUE KEY ikey (ikey),
  KEY status_sev (status,severity)
) {$c};"
		);
	}

	/**
	 * (Re)schedule cron events according to settings.
	 */
	public static function schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOURLY ) ) {
			wp_schedule_event( time() + 300, 'hourly', self::CRON_HOURLY );
		}
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + 900, 'daily', self::CRON_DAILY );
		}
		Server_Scan::schedule();
		$want = Settings::get( 'scan_schedule' );
		$next = wp_get_scheduled_event( self::CRON_SCAN );
		if ( 'off' === $want ) {
			wp_clear_scheduled_hook( self::CRON_SCAN );
			return;
		}

		if ( ! $next || $next->schedule !== $want ) {
			wp_clear_scheduled_hook( self::CRON_SCAN );
			// Spread load: start at a random time in the next few hours (off-peak-ish).
			wp_schedule_event( time() + wp_rand( HOUR_IN_SECONDS, 6 * HOUR_IN_SECONDS ), $want, self::CRON_SCAN );
		}
	}

	/**
	 * Path of the MU loader.
	 *
	 * @return string
	 */
	public static function mu_path() {
		return trailingslashit( WPMU_PLUGIN_DIR ) . self::MU_FILE;
	}

	/**
	 * Install the MU loader so the firewall runs before every other plugin.
	 *
	 * @return true|\WP_Error
	 */
	public static function install_mu_loader() {
		if ( ! License::is_pro() ) {
			return new \WP_Error( 'ironveil_pro', __( 'Extended protection is a Pro feature.', 'ironveil-security' ) );
		}
		$dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'ironveil_mu', __( 'Could not create the mu-plugins directory.', 'ironveil-security' ) );
		}
		$autoload = wp_normalize_path( IRONVEIL_DIR . 'includes/autoload.php' );
		$code     = "<?php\n"
			. "/**\n * Plugin Name: IronVeil Security – early firewall loader\n * Description: Runs the IronVeil firewall before other plugins. Managed by IronVeil Security; delete this file to disable.\n */\n"
			. "defined( 'ABSPATH' ) || exit;\n"
			. "if ( defined( 'IRONVEIL_DISABLE_FIREWALL' ) && IRONVEIL_DISABLE_FIREWALL ) { return; }\n"
			. '$ironveil_active = (array) get_option( \'active_plugins\', array() );' . "\n"
			. 'if ( is_multisite() ) { $ironveil_active = array_merge( $ironveil_active, array_keys( (array) get_site_option( \'active_sitewide_plugins\', array() ) ) ); }' . "\n"
			. 'if ( in_array( ' . var_export( IRONVEIL_BASENAME, true ) . ', $ironveil_active, true ) && is_readable( ' . var_export( $autoload, true ) . " ) ) {\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
			. '	require_once ' . var_export( $autoload, true ) . ";\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
			. "	\\IronVeil\\Firewall::boot();\n"
			. "}\n"
			. "unset( \$ironveil_active );\n";
		$ok = false !== file_put_contents( self::mu_path(), $code, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( ! $ok ) {
			return new \WP_Error( 'ironveil_mu', __( 'Could not write the MU loader (check permissions).', 'ironveil-security' ) );
		}
		Log::add( 'extended_protection', 'Extended protection (early loader) enabled', Log::NOTICE );
		return true;
	}

	/**
	 * Remove the MU loader if it is ours.
	 */
	public static function remove_mu_loader() {
		$f = self::mu_path();
		if ( is_file( $f ) && false !== strpos( (string) file_get_contents( $f, false, null, 0, 400 ), 'IronVeil' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			wp_delete_file( $f );
		}
	}

	/**
	 * @return bool
	 */
	public static function mu_loader_active() {
		return is_file( self::mu_path() );
	}
}
