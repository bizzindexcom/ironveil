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
			\WP_CLI::log( sprintf( '#%d [%s] %s — %s', $i->id, Scanner::severity_label( $i->severity ), $i->detail, $i->path ) );
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

	/**
	 * Run the server security scan and print the report.
	 *
	 * @subcommand server-scan
	 */
	public function server_scan() {
		$r = Server_Scan::run( 'cli' );
		foreach ( $r['checks'] as $c ) {
			\WP_CLI::log( sprintf( '[%-4s] %-9s %s%s', strtoupper( $c['status'] ), $c['section'], $c['label'], '' !== $c['detail'] ? ' – ' . $c['detail'] : '' ) );
		}
		\WP_CLI::success( sprintf( '%d checks, %d new findings (%.1fs).', count( $r['checks'] ), $r['new'], $r['duration'] ) );
	}

	/**
	 * Clean, quarantine or ignore open findings.
	 *
	 * ## OPTIONS
	 * [<id>...]
	 * : Finding ids (see "wp ironveil scan").
	 * [--action=<action>]
	 * : clean | quarantine | ignore. Default: clean.
	 * [--min-severity=<n>]
	 * : Instead of ids, act on every open finding with at least this severity (1-4).
	 * [--fallback]
	 * : Quarantine files that cannot be cleaned safely.
	 *
	 * ## EXAMPLES
	 *     wp ironveil clean 12 15
	 *     wp ironveil clean --min-severity=4 --fallback
	 */
	public function clean( $args, $assoc ) {
		$action = $assoc['action'] ?? 'clean';
		if ( ! in_array( $action, array( 'clean', 'quarantine', 'ignore' ), true ) ) {
			\WP_CLI::error( 'Action must be clean, quarantine or ignore.' );
		}
		$ids = array_map( 'absint', $args );
		if ( ! $ids && isset( $assoc['min-severity'] ) ) {
			foreach ( Scanner::issues( 'open', 1000 ) as $i ) {
				if ( (int) $i->severity >= (int) $assoc['min-severity'] ) {
					$ids[] = (int) $i->id;
				}
			}
		}
		if ( ! $ids ) {
			\WP_CLI::error( 'Give finding ids or --min-severity.' );
		}
		$r = Cleaner::bulk( $ids, $action, ! empty( $assoc['fallback'] ) );
		foreach ( $r['failed'] as $f ) {
			\WP_CLI::warning( $f[0] . ' – ' . $f[1] );
		}
		foreach ( $r['skipped'] as $f ) {
			\WP_CLI::log( 'Manual: ' . $f[0] . ' – ' . $f[1] );
		}
		\WP_CLI::success( sprintf( '%d done, %d failed, %d manual, %d left.', $r['done'], count( $r['failed'] ), count( $r['skipped'] ), $r['left'] ) );
	}

	/**
	 * Clear a verification lockout (after too many invalid codes) for a user.
	 *
	 * ## OPTIONS
	 * <user>
	 * : User login, email or ID.
	 *
	 * @subcommand unlock-verify
	 */
	public function unlock_verify( $args ) {
		$u = is_numeric( $args[0] ) ? get_user_by( 'id', (int) $args[0] ) : ( get_user_by( 'login', $args[0] ) ? get_user_by( 'login', $args[0] ) : get_user_by( 'email', $args[0] ) );
		if ( ! $u ) {
			\WP_CLI::error( 'User not found.' );
		}
		delete_user_meta( $u->ID, Verify::FAIL_META );
		delete_user_meta( $u->ID, Verify::EMAIL_META );
		Log::add( 'verify_unlocked', sprintf( 'Verification lockout cleared via WP-CLI for %s', $u->user_login ), Log::WARNING );
		\WP_CLI::success( 'Verification unlocked for ' . $u->user_login );
	}

	/**
	 * Refresh the threat-intelligence IP feeds now.
	 *
	 * @subcommand update-feeds
	 */
	public function update_feeds() {
		foreach ( Threat_Feeds::update() as $k => $s ) {
			\WP_CLI::log( sprintf( '%s: %d networks%s', $k, (int) ( $s['count'] ?? 0 ), ! empty( $s['error'] ) ? ' – ' . $s['error'] : '' ) );
		}
		\WP_CLI::success( 'Done.' );
	}

}
