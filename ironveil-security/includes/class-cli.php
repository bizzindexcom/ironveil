<?php
/**
 * WP-CLI commands – also the emergency toolkit when locked out.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Cli {

	/**
	 * Register commands.
	 */
	public static function register() {
		\WP_CLI::add_command( 'ironveil', __CLASS__ );
	}

	/**
	 * Show security status.
	 *
	 * ## EXAMPLES
	 *     wp ironveil status
	 */
	public function status() {
		$checks = Hardening::audit();
		\WP_CLI::log( sprintf( 'Security score: %d/100', Hardening::score( $checks ) ) );
		foreach ( $checks as $c ) {
			\WP_CLI::log( sprintf( '[%s] %s %s', strtoupper( $c[1] ), $c[0], $c[2] ? '– ' . $c[2] : '' ) );
		}
	}

	/**
	 * Run a full scan synchronously.
	 *
	 * ## OPTIONS
	 * [--deep]
	 * : Re-check every file, ignoring the incremental cache.
	 *
	 * ## EXAMPLES
	 *     wp ironveil scan
	 *     wp ironveil scan --deep
	 */
	public function scan( $args = array(), $assoc = array() ) {
		add_filter(
			'ironveil_scan_step_seconds',
			static function () {
				return 30;
			}
		);
		Scanner::cancel();
		$s = Scanner::start( 'cli', ! empty( $assoc['deep'] ) );
		\WP_CLI::log( sprintf( 'Scan #%d%s%s', $s['id'], $s['deep'] ? ' (deep)' : '', $s['clam'] ? ' with ClamAV' : '' ) );
		while ( $s && 'done' !== $s['stage'] ) {
			$s = Scanner::step();
			\WP_CLI::log( sprintf( 'Stage: %s · files %d · analysed %d · ClamAV %d (errors %d)', $s['stage'], $s['counts']['files'], $s['counts']['analyzed'], $s['counts']['clamav'], $s['counts']['clam_err'] ) );
		}
		foreach ( Scanner::issues( 'open' ) as $i ) {
			\WP_CLI::log( sprintf( '[%s] %s — %s', Scanner::severity_label( $i->severity ), $i->detail, $i->path ) );
		}
		\WP_CLI::success( sprintf( '%d open findings.', Scanner::count_open( 1 ) ) );
	}

	/**
	 * Check that ClamAV works (EICAR self-test).
	 *
	 * @subcommand clamav-test
	 */
	public function clamav_test() {
		$r = ClamAV::self_test();
		$r['ok'] ? \WP_CLI::success( $r['message'] ) : \WP_CLI::error( $r['message'] );
	}

	/**
	 * Download and verify the signed signature feed now.
	 *
	 * @subcommand update-signatures
	 */
	public function update_signatures() {
		$r = Signature_Feed::update( true );
		if ( is_wp_error( $r ) ) {
			\WP_CLI::error( $r->get_error_message() );
		}
		$st = Signature_Feed::state();
		$c  = Signatures::counts();
		\WP_CLI::success( sprintf( 'Feed version %d installed. Rules: %d built-in, %d feed, %d custom.', $st['version'], $c['builtin'], $c['feed'], $c['custom'] ) );
	}

	/**
	 * Manage the Pro license.
	 *
	 * ## OPTIONS
	 * <action>
	 * : status | activate | deactivate
	 * [<key>]
	 * : License key (for activate).
	 */
	public function license( $args ) {
		$action = $args[0] ?? 'status';
		if ( 'activate' === $action ) {
			$st = License::activate( $args[1] ?? '' );
			$st['valid'] ? \WP_CLI::success( 'Pro activated for ' . License::site_host() ) : \WP_CLI::error( License::reason_text( $st['reason'] ) );
			return;
		}
		if ( 'deactivate' === $action ) {
			License::deactivate();
			\WP_CLI::success( 'License removed (Free edition).' );
			return;
		}
		$st = License::status();
		if ( $st['valid'] ) {
			\WP_CLI::log( sprintf( 'PRO · %s license · %s · domains: %s · expires: %s', $st['type'], $st['name'], implode( ', ', $st['domains'] ), $st['expires'] ? gmdate( 'Y-m-d', $st['expires'] ) : 'never' ) );
		} else {
			\WP_CLI::log( 'FREE · ' . License::reason_text( $st['reason'] ) );
		}
	}

	/**
	 * Unblock an IP (or everything).
	 *
	 * ## OPTIONS
	 * <ip>
	 * : IP address, or "all".
	 */
	public function unblock( $args ) {
		global $wpdb;
		if ( 'all' === $args[0] ) {
			$wpdb->query( 'DELETE FROM ' . Blocklist::table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
			Blocklist::rebuild_cache();
		} else {
			Blocklist::remove_ip( $args[0] );
		}
		\WP_CLI::success( 'Unblocked.' );
	}

	/**
	 * Block an IP or CIDR.
	 *
	 * ## OPTIONS
	 * <ip>
	 * : IP or CIDR.
	 * [--hours=<hours>]
	 * : Duration (0 = permanent).
	 */
	public function block( $args, $assoc ) {
		$ok = Blocklist::add( $args[0], 'Blocked via WP-CLI', 'manual', HOUR_IN_SECONDS * (int) ( $assoc['hours'] ?? 0 ) );
		$ok ? \WP_CLI::success( 'Blocked.' ) : \WP_CLI::error( 'Invalid IP.' );
	}

	/**
	 * Reset two-factor authentication for a user.
	 *
	 * ## OPTIONS
	 * <user>
	 * : User login, email or ID.
	 */
	public function reset_2fa( $args ) {
		$u = is_numeric( $args[0] ) ? get_user_by( 'id', (int) $args[0] ) : ( get_user_by( 'login', $args[0] ) ? get_user_by( 'login', $args[0] ) : get_user_by( 'email', $args[0] ) );
		if ( ! $u ) {
			\WP_CLI::error( 'User not found.' );
		}
		Two_Factor::reset( $u->ID );
		Log::add( '2fa_reset', sprintf( '2FA reset via WP-CLI for %s', $u->user_login ), Log::WARNING );
		\WP_CLI::success( '2FA reset for ' . $u->user_login );
	}

	/**
	 * Set the firewall mode.
	 *
	 * ## OPTIONS
	 * <mode>
	 * : block|monitor|off
	 */
	public function firewall( $args ) {
		if ( ! in_array( $args[0], array( 'block', 'monitor', 'off' ), true ) ) {
			\WP_CLI::error( 'Mode must be block, monitor or off.' );
		}
		Settings::import( array( 'fw_mode' => $args[0] ) );
		\WP_CLI::success( 'Firewall mode: ' . $args[0] );
	}

	/**
	 * Clear the custom login URL (if you forgot it).
	 */
	public function reset_login_url() {
		Settings::import( array( 'login_slug' => '' ) );
		\WP_CLI::success( 'Custom login URL removed; wp-login.php works again.' );
	}
}
