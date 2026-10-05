<?php
/**
 * Main plugin orchestrator.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Plugin {

	/** @var Plugin|null */
	private static $instance = null;

	/**
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Capability required to manage IronVeil.
	 *
	 * @return string
	 */
	public static function cap() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	private function __construct() {
		load_plugin_textdomain( 'ironveil-security', false, dirname( IRONVEIL_BASENAME ) . '/languages' );
		Installer::maybe_upgrade();

		Login_Guard::init();
		Two_Factor::init();
		Hardening::init();
		Audit::init();
		Notifier::init();

		add_action( Installer::CRON_HOURLY, array( '\IronVeil\Blocklist', 'prune' ) );
		add_action( Installer::CRON_DAILY, array( __CLASS__, 'daily' ) );
		add_action( Installer::CRON_SCAN, array( '\IronVeil\Scanner', 'scheduled' ) );
		add_action( Installer::CRON_SCANSTEP, array( '\IronVeil\Scanner', 'cron_step' ) );
		add_action( 'ironveil_settings_saved', array( __CLASS__, 'settings_saved' ) );
		add_action( 'template_redirect', array( __CLASS__, 'track_404' ), 999 );

		if ( is_admin() ) {
			Admin::init();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			Cli::register();
		}
	}

	/**
	 * Daily maintenance.
	 */
	public static function daily() {
		Log::prune();
		Scanner::cleanup();
		if ( ! License::is_pro() && Installer::mu_loader_active() ) {
			Installer::remove_mu_loader(); // License lapsed: extended protection is Pro.
		}
		if ( '' !== Signature_Feed::url() ) {
			Signature_Feed::update();
		}
	}

	/**
	 * Re-apply scheduling and server rules after settings change.
	 */
	public static function settings_saved() {
		delete_transient( 'ironveil_clamd_ep' );
		Signatures::flush();
		Installer::schedule();
		Hardening::sync_server_rules();
	}

	/**
	 * Count 404s by anonymous visitors; block scanners that exceed the limit.
	 * Writes happen only on 404 responses, never on normal page views.
	 */
	public static function track_404() {
		$limit = (int) Settings::get( 'fw_404_limit' );
		if ( $limit < 1 || ! is_404() || is_user_logged_in() || 'off' === Settings::get( 'fw_mode' ) ) {
			return;
		}
		$ip = IP::client();
		if ( IP::is_self( $ip ) ) {
			return;
		}
		$allow = Settings::lines( 'fw_allowlist' );
		if ( $allow && IP::in_ranges( $ip, IP::parse_list( $allow ) ) ) {
			return;
		}
		$key = 'ironveil_404_' . md5( $ip );
		$n   = (int) get_transient( $key ) + 1;
		set_transient( $key, $n, 5 * MINUTE_IN_SECONDS );
		if ( $n >= $limit && 'block' === Settings::get( 'fw_mode' ) ) {
			delete_transient( $key );
			Blocklist::add( $ip, sprintf( '404 flood (%d not-found hits in 5 min)', $n ), '404', HOUR_IN_SECONDS * (int) Settings::get( 'fw_autoblock_hours' ) );
			do_action( 'ironveil_ip_autoblocked', $ip, '404' );
		}
	}
}
