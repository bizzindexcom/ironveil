<?php
/**
 * Activity / security event log (custom table, bounded by retention cron).
 * Each row carries an HMAC keyed with wp-config secrets, and ids are
 * sequential, so editing or deleting past records directly in the database
 * is detectable (without the lock contention of a strict hash chain).
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Log {

	const INFO     = 1;
	const NOTICE   = 2;
	const WARNING  = 3;
	const CRITICAL = 4;

	/** @var bool Prevent recursion / writes before install. */
	private static $writing = false;

	/**
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'ironveil_log';
	}

	/**
	 * Record an event.
	 *
	 * @param string $event    Machine event key.
	 * @param string $message  Human message (stored as plain text, escaped on output).
	 * @param int    $severity Severity constant.
	 * @param array  $context  Extra data (JSON).
	 * @param int    $user_id  Acting user (defaults to current user when known).
	 */
	public static function add( $event, $message, $severity = self::INFO, array $context = array(), $user_id = null ) {
		global $wpdb;
		if ( self::$writing || ! get_option( 'ironveil_db_version' ) ) {
			return;
		}
		self::$writing = true;
		if ( null === $user_id ) {
			$user_id = did_action( 'set_current_user' ) ? get_current_user_id() : 0;
		}
		$table   = self::table();
		$created = time();
		$ip      = IP::client();
		$uri     = isset( $_SERVER['REQUEST_URI'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 255 ) : '';
		$json    = $context ? wp_json_encode( $context ) : '';
		$message = substr( preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $message ), 0, 255 ); // Stored raw; always escaped on output.
		$event   = substr( sanitize_key( $event ), 0, 40 );
		$chain   = self::sign( $created, $event, $severity, $user_id, $ip, $message, $json );

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$table,
			array(
				'created'  => $created,
				'event'    => $event,
				'severity' => (int) $severity,
				'user_id'  => (int) $user_id,
				'ip'       => $ip,
				'uri'      => $uri,
				'message'  => $message,
				'context'  => $json,
				'chain'    => $chain,
			),
			array( '%d', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s' )
		);
		self::$writing = false;
		do_action( 'ironveil_logged', $event, $message, $severity, $context );
	}

	/**
	 * Row signature.
	 *
	 * @return string
	 */
	private static function sign( $created, $event, $severity, $user_id, $ip, $message, $json ) {
		return hash_hmac( 'sha256', implode( '|', array( (int) $created, (string) $event, (int) $severity, (int) $user_id, (string) $ip, (string) $message, (string) $json ) ), self::chain_key() );
	}

	/**
	 * Key for the integrity chain, derived from wp-config salts.
	 *
	 * @return string
	 */
	private static function chain_key() {
		return hash( 'sha256', 'ironveil-log|' . ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' ) . ( defined( 'AUTH_SALT' ) ? AUTH_SALT : '' ) );
	}

	/**
	 * Verify signatures and sequence of the most recent N rows.
	 *
	 * @param int $limit Rows.
	 * @return array { ok: bool, checked: int, broken_id: int|null, gaps: int }
	 */
	public static function verify_chain( $limit = 5000 ) {
		global $wpdb;
		$table  = self::table();
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", (int) $limit ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$count  = 0;
		$gaps   = 0;
		$prev   = null;
		$broken = null;
		foreach ( $rows as $r ) {
			$calc = self::sign( $r->created, $r->event, $r->severity, $r->user_id, $r->ip, $r->message, $r->context );
			if ( ! hash_equals( $calc, (string) $r->chain ) && null === $broken ) {
				$broken = (int) $r->id;
			}
			if ( null !== $prev && (int) $r->id !== $prev - 1 ) {
				++$gaps;
			}
			$prev = (int) $r->id;
			++$count;
		}
		return array(
			'ok'        => null === $broken,
			'checked'   => $count,
			'broken_id' => $broken,
			'gaps'      => $gaps,
		);
	}

	/**
	 * Query log entries.
	 *
	 * @param array $args page, per_page, event, severity, search.
	 * @return array { rows, total }
	 */
	public static function query( array $args ) {
		global $wpdb;
		$table    = self::table();
		$where    = array( '1=1' );
		$params   = array();
		$per_page = max( 1, min( 500, (int) ( $args['per_page'] ?? 50 ) ) );
		$page     = max( 1, (int) ( $args['page'] ?? 1 ) );
		if ( ! empty( $args['event'] ) ) {
			$where[]  = 'event = %s';
			$params[] = sanitize_key( $args['event'] );
		}
		if ( ! empty( $args['severity'] ) ) {
			$where[]  = 'severity >= %d';
			$params[] = (int) $args['severity'];
		}
		if ( ! empty( $args['search'] ) ) {
			$like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[]  = '(message LIKE %s OR ip LIKE %s)';
			$params[] = $like;
			$params[] = $like;
		}
		$sql_where = implode( ' AND ', $where );
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$sql_where}";
		$rows_sql  = "SELECT * FROM {$table} WHERE {$sql_where} ORDER BY id DESC LIMIT %d OFFSET %d";
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
		$total = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );
		$rows  = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( $per_page, ( $page - 1 ) * $per_page ) ) ) );
		// phpcs:enable
		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Count events since a timestamp (dashboard).
	 *
	 * @param string $event Event key.
	 * @param int    $since Timestamp.
	 * @return int
	 */
	public static function count_since( $event, $since ) {
		global $wpdb;
		$table = self::table();
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event = %s AND created >= %d", $event, (int) $since ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Retention (daily cron): age and row-count bounds.
	 */
	public static function prune() {
		global $wpdb;
		$table = self::table();
		$days  = (int) Settings::get( 'log_retention_days' );
		$max   = (int) Settings::get( 'log_max_rows' );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created < %d", time() - DAY_IN_SECONDS * $days ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$cutoff = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", $max ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( $cutoff ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", (int) $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		}
	}
}
