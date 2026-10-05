<?php
/**
 * Email alerts with per-type throttling (no inbox floods during attacks).
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Notifier {

	/**
	 * Hooks.
	 */
	public static function init() {
		$events = (array) Settings::get( 'notify_events' );
		if ( in_array( 'lockout', $events, true ) ) {
			add_action( 'ironveil_lockout', array( __CLASS__, 'lockout' ), 10, 2 );
			add_action( 'ironveil_ip_autoblocked', array( __CLASS__, 'autoblocked' ), 10, 2 );
		}
		if ( in_array( 'admin_login', $events, true ) ) {
			add_action( 'ironveil_login_complete', array( __CLASS__, 'admin_login' ) );
		}
		if ( in_array( 'plugin', $events, true ) ) {
			add_action( 'ironveil_component_change', array( __CLASS__, 'component' ), 10, 2 );
		}
		if ( in_array( 'new_admin', $events, true ) ) {
			add_action( 'ironveil_new_admin', array( __CLASS__, 'new_admin' ) );
		}
		if ( in_array( 'scan', $events, true ) ) {
			add_action( 'ironveil_scan_complete', array( __CLASS__, 'scan' ), 10, 2 );
		}
		if ( in_array( 'verify', $events, true ) ) {
			add_action( 'ironveil_verify_locked', array( __CLASS__, 'verify_locked' ), 10, 2 );
		}
		if ( in_array( 'server', $events, true ) ) {
			add_action( 'ironveil_server_scan_complete', array( __CLASS__, 'server_scan' ), 10, 2 );
		}
	}

	/**
	 * @param int    $user_id User.
	 * @param string $context Where.
	 */
	public static function verify_locked( $user_id, $context ) {
		$u = get_userdata( $user_id );
		self::send( 'verify_' . $user_id, 'Identity verification locked', sprintf( "Five invalid verification codes were entered for administrator \"%1\$s\" (%2\$s) from %3\$s.\nCode checks for this account are paused for 15 minutes.\n\nIf this was not you, someone may know the password or hold a session cookie: change the password and use IronVeil → Alerts & Tools → \"Log out ALL users everywhere\".", $u ? $u->user_login : '#' . $user_id, $context, IP::client() ), 600 );
	}

	/**
	 * @param int   $id      Server scan id.
	 * @param array $summary new, items.
	 */
	public static function server_scan( $id, $summary ) {
		if ( empty( $summary['new'] ) ) {
			return;
		}
		$lines = array();
		foreach ( (array) $summary['items'] as $item ) {
			$lines[] = '- [' . $item['sev'] . '] ' . $item['detail'];
		}
		self::send( 'server_scan', sprintf( 'Server scan: %d new problem(s)', $summary['new'] ), "The server scan found new problems:\n\n" . implode( "\n", array_slice( $lines, 0, 30 ) ) . "\n\nReview them in IronVeil → Server Scan.", 0 );
	}


	/**
	 * @return string
	 */
	private static function to() {
		$e = (string) Settings::get( 'notify_email' );
		return $e ? $e : (string) get_option( 'admin_email' );
	}

	/**
	 * Send an alert.
	 *
	 * @param string $type     Throttle bucket.
	 * @param string $subject  Subject.
	 * @param string $body     Body.
	 * @param int    $throttle Seconds (0 = none).
	 * @return bool
	 */
	public static function send( $type, $subject, $body, $throttle = 900 ) {
		if ( $throttle ) {
			$key = 'ironveil_mail_' . sanitize_key( $type );
			if ( get_transient( $key ) ) {
				return false;
			}
			set_transient( $key, 1, $throttle );
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = $body . "\n\n—\n" . sprintf( 'IronVeil Security on %s', home_url() ) . "\n" . admin_url( 'admin.php?page=ironveil' );
		return wp_mail( self::to(), sprintf( '[%1$s] IronVeil: %2$s', $site, $subject ), $body );
	}

	public static function lockout( $ip, $duration ) {
		self::send( 'lockout', 'Login lockout', sprintf( "IP %s was locked out of the login page for %d minutes after repeated failed logins.\n(Further lockouts in the next 15 minutes are not emailed.)", $ip, $duration / 60 ) );
	}

	public static function autoblocked( $ip, $why ) {
		self::send( 'autoblock', 'IP auto-blocked', sprintf( "IP %1\$s was blocked by the firewall (%2\$s).\n(Further blocks in the next 15 minutes are not emailed.)", $ip, $why ) );
	}

	public static function admin_login( $user ) {
		if ( user_can( $user, 'manage_options' ) ) {
			self::send( 'admin_login_' . $user->ID, 'Administrator login', sprintf( "Administrator \"%1\$s\" logged in from %2\$s at %3\$s (UTC).\nIf this wasn't you, change the password and review Users.", $user->user_login, IP::client(), gmdate( 'Y-m-d H:i:s' ) ), 300 );
		}
	}

	public static function component( $what, $name ) {
		self::send( 'component', 'Plugin/theme change', sprintf( 'Change detected: %1$s – %2$s', $what, $name ), 300 );
	}

	public static function new_admin( $user_id ) {
		$u = get_userdata( $user_id );
		self::send( 'new_admin_' . $user_id, 'New administrator', sprintf( "User \"%s\" now has the administrator role.\nIf you did not do this, your site may be compromised.", $u ? $u->user_login : '#' . $user_id ), 0 );
	}

	/**
	 * @param int   $scan_id Scan id.
	 * @param array $summary new_issues, by_severity.
	 */
	public static function scan( $scan_id, $summary ) {
		if ( empty( $summary['new'] ) ) {
			return;
		}
		$lines = array();
		foreach ( (array) $summary['items'] as $item ) {
			$lines[] = '- [' . $item['sev'] . '] ' . $item['detail'] . ( $item['path'] ? ' — ' . $item['path'] : '' );
		}
		self::send( 'scan', sprintf( '%d new security finding(s)', $summary['new'] ), "The scheduled scan found new issues:\n\n" . implode( "\n", array_slice( $lines, 0, 30 ) ), 0 );
	}
}
