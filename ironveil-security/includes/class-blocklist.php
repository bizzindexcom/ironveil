<?php
/**
 * IP blocklist. The database table is the source of truth; the firewall only
 * reads a compact, autoloaded cache option, so checking a visitor costs zero
 * additional database queries.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Blocklist {

	const CACHE_OPTION = 'ironveil_block_cache';
	const MAX_CACHED   = 20000;

	/**
	 * @return string Table name.
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'ironveil_blocks';
	}

	/**
	 * Is the IP blocked? Returns the block record or null.
	 *
	 * @param string $ip Valid IP.
	 * @return array|null { reason, expires }
	 */
	public static function match( $ip ) {
		$hex = IP::to_hex( $ip );
		if ( '' === $hex ) {
			return null;
		}
		$cache = get_option( self::CACHE_OPTION );
		if ( ! is_array( $cache ) || empty( $cache['n'] ) ) {
			return Threat_Feeds::match( $hex ) ? array(
				'reason'  => 'threat feed',
				'expires' => 0,
			) : null;
		}
		$now = time();
		if ( isset( $cache['e'][ $hex ] ) ) {
			list( $exp, $reason ) = $cache['e'][ $hex ];
			if ( 0 === $exp || $exp > $now ) {
				return array(
					'reason'  => $reason,
					'expires' => $exp,
				);
			}
		}
		if ( ! empty( $cache['r'] ) ) {
			foreach ( $cache['r'] as $r ) {
				if ( ( 0 === $r[2] || $r[2] > $now ) && strcmp( $hex, $r[0] ) >= 0 && strcmp( $hex, $r[1] ) <= 0 ) {
					return array(
						'reason'  => $r[3],
						'expires' => $r[2],
					);
				}
			}
		}
		if ( Threat_Feeds::match( $hex ) ) {
			return array(
				'reason'  => 'threat feed',
				'expires' => 0,
			);
		}
		return null;
	}

	/**
	 * Add (or extend) a block.
	 *
	 * @param string $entry    IP or CIDR.
	 * @param string $reason   Human reason.
	 * @param string $source   manual|waf|login|404|rate|bot.
	 * @param int    $duration Seconds; 0 = permanent.
	 * @return bool
	 */
	public static function add( $entry, $reason, $source = 'manual', $duration = 0 ) {
		global $wpdb;
		$range = IP::range( $entry );
		if ( ! $range ) {
			return false;
		}
		// Never block the current administrator's own IP by accident from auto rules.
		if ( 'manual' !== $source && $range[0] === $range[1] && IP::is_self( IP::from_hex( $range[0] ) ) ) {
			return false;
		}
		$now     = time();
		$expires = $duration > 0 ? $now + (int) $duration : 0;
		$label   = substr( sanitize_text_field( $entry ), 0, 64 );
		$table   = self::table();

		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT id, expires FROM {$table} WHERE ip_from = %s AND ip_to = %s", $range[0], $range[1] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( $existing ) {
			$new_exp = ( 0 === (int) $existing->expires || 0 === $expires ) ? 0 : max( (int) $existing->expires, $expires );
			$wpdb->update( $table, array( 'expires' => $new_exp, 'reason' => substr( $reason, 0, 190 ), 'source' => $source ), array( 'id' => (int) $existing->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		} else {
			$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$table,
				array(
					'ip_from' => $range[0],
					'ip_to'   => $range[1],
					'label'   => $label,
					'reason'  => substr( $reason, 0, 190 ),
					'source'  => $source,
					'created' => $now,
					'expires' => $expires,
				)
			);
		}
		self::rebuild_cache();
		Log::add( 'ip_blocked', sprintf( 'Blocked %1$s (%2$s)', $label, $reason ), Log::WARNING, array( 'source' => $source, 'expires' => $expires ) );
		return true;
	}

	/**
	 * @param int $id Row id.
	 */
	public static function remove( $id ) {
		global $wpdb;
		$wpdb->delete( self::table(), array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		self::rebuild_cache();
	}

	/**
	 * Remove every block covering an IP (used by "unblock me").
	 *
	 * @param string $ip IP.
	 */
	public static function remove_ip( $ip ) {
		global $wpdb;
		$hex = IP::to_hex( $ip );
		if ( ! $hex ) {
			return;
		}
		$table = self::table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE ip_from <= %s AND ip_to >= %s", $hex, $hex ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		self::rebuild_cache();
	}

	/**
	 * Remove expired rows and rebuild the cache (hourly cron).
	 */
	public static function prune() {
		global $wpdb;
		$table = self::table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE expires > 0 AND expires < %d", time() ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		self::rebuild_cache();
		Threat_Feeds::rebuild_cache();
	}


	/**
	 * Rebuild the compact autoloaded cache from the table.
	 */
	public static function rebuild_cache() {
		global $wpdb;
		$table = self::table();
		// Threat-feed networks live in their own compact cache (Threat_Feeds::rebuild_cache()).
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT ip_from, ip_to, reason, expires FROM {$table} WHERE ( expires = 0 OR expires > %d ) AND SUBSTR(source, 1, 5) <> 'feed:' ORDER BY expires = 0 DESC, expires DESC LIMIT %d", time(), self::MAX_CACHED ), ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$cache = array(
			'n' => 0,
			'e' => array(),
			'r' => array(),
		);
		foreach ( (array) $rows as $row ) {
			$reason = substr( (string) $row[2], 0, 60 );
			$exp    = (int) $row[3];
			if ( $row[0] === $row[1] ) {
				$cache['e'][ $row[0] ] = array( $exp, $reason );
			} else {
				$cache['r'][] = array( $row[0], $row[1], $exp, $reason );
			}
			++$cache['n'];
		}
		update_option( self::CACHE_OPTION, $cache, true );
	}

	/**
	 * Paginated listing for the admin screen.
	 *
	 * @param int $page     Page.
	 * @param int $per_page Per page.
	 * @return array { rows, total }
	 */
	public static function list_blocks( $page = 1, $per_page = 50 ) {
		global $wpdb;
		$table  = self::table();
		$offset = max( 0, ( (int) $page - 1 ) * $per_page );
		// Threat-feed networks are summarised separately (thousands of rows).
		$total  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE ( expires = 0 OR expires > %d ) AND SUBSTR(source, 1, 5) <> 'feed:'", time() ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE ( expires = 0 OR expires > %d ) AND SUBSTR(source, 1, 5) <> 'feed:' ORDER BY created DESC LIMIT %d OFFSET %d", time(), (int) $per_page, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}
}
