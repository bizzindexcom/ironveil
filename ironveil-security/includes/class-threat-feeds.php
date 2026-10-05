<?php
/**
 * Threat-intelligence IP feeds merged into the blocklist.
 *
 *  - Spamhaus DROP / DROPv6: netblocks hijacked or leased by spammers and
 *    cyber-criminals ("Don't Route Or Peer"). Industry standard, very low
 *    false-positive rate.
 *  - Tor exit nodes (optional): blocks anonymised traffic.
 *
 * Lists are downloaded once a day (only when enabled), validated, and stored
 * in the blocklist table with a 3-day expiry so a stale list ages out if
 * updates stop. The firewall keeps reading only its autoloaded cache, so a
 * feed adds no database query per request. The allowlist always wins, and
 * private / loopback / this server's addresses are never imported.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Threat_Feeds {

	const OPTION  = 'ironveil_threat_feeds';
	const CACHE   = 'ironveil_feed_cache';
	const TTL     = 259200; // 3 days.
	const MAX     = 15000;

	/**
	 * Feed definitions: urls, minimum plausible entry count, label.
	 *
	 * @return array
	 */
	public static function sources() {
		return array(
			'spamhaus_drop' => array(
				'urls'  => array( 'https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json' ),
				'min'   => 50,
				'label' => 'Spamhaus DROP',
			),
			'tor'           => array(
				'urls'  => array( 'https://check.torproject.org/torbulkexitlist' ),
				'min'   => 100,
				'label' => 'Tor exit nodes',
			),
		);
	}

	/**
	 * Stored status per feed.
	 *
	 * @return array
	 */
	public static function state() {
		$s = get_option( self::OPTION );
		return is_array( $s ) ? $s : array();
	}

	/**
	 * Refresh enabled feeds and remove disabled ones.
	 *
	 * @return array Status per feed.
	 */
	public static function update() {
		$enabled = (array) Settings::get( 'fw_threat_feeds' );
		$state   = self::state();
		foreach ( self::sources() as $key => $src ) {
			if ( ! in_array( $key, $enabled, true ) ) {
				if ( isset( $state[ $key ] ) ) {
					self::replace( $key, array() );
					unset( $state[ $key ] );
				}
				continue;
			}
			$entries = array();
			$error   = '';
			foreach ( $src['urls'] as $url ) {
				$res = wp_safe_remote_get(
					$url,
					array(
						'timeout'             => 15,
						'limit_response_size' => 4 * MB_IN_BYTES,
						'user-agent'          => 'IronVeil-Security/' . IRONVEIL_VERSION . ' (+' . home_url( '/' ) . ')',
					)
				);
				if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
					$error = is_wp_error( $res ) ? $res->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code( $res );
					continue;
				}
				$entries = array_merge( $entries, self::parse( (string) wp_remote_retrieve_body( $res ) ) );
			}
			$entries = array_slice( array_values( array_unique( $entries ) ), 0, self::MAX );
			if ( count( $entries ) < $src['min'] ) {
				// Empty / truncated / hijacked response: keep the previous list (it expires on its own).
				$state[ $key ] = array_merge(
					$state[ $key ] ?? array(),
					array(
						'checked' => time(),
						'error'   => '' !== $error ? $error : __( 'The list looked incomplete and was not applied.', 'ironveil-security' ),
					)
				);
				Log::add( 'threat_feed_error', sprintf( '%1$s update failed: %2$s', $src['label'], $state[ $key ]['error'] ), Log::NOTICE );
				continue;
			}
			$n             = self::replace( $key, $entries );
			$state[ $key ] = array(
				'count'   => $n,
				'updated' => time(),
				'checked' => time(),
				'error'   => '',
			);
			Log::add( 'threat_feed_updated', sprintf( '%1$s updated: %2$d networks', $src['label'], $n ), Log::INFO );
		}
		update_option( self::OPTION, $state, false );
		self::rebuild_cache();
		return $state;
	}

	/**
	 * Build the compact lookup the firewall reads: feed networks merged into
	 * sorted, non-overlapping ranges, packed as binary (8 bytes per IPv4 range,
	 * 32 per IPv6 range) and base64-encoded in one small autoloaded option.
	 * A lookup is a binary search: microseconds even with thousands of networks,
	 * and nothing large is unserialized on each request.
	 */
	public static function rebuild_cache() {
		global $wpdb;
		$table = Blocklist::table();
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT ip_from, ip_to, expires FROM {$table} WHERE SUBSTR(source, 1, 5) = 'feed:' AND expires > %d", time() ), ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( ! $rows ) {
			delete_option( self::CACHE );
			return;
		}
		$v4  = array();
		$v6  = array();
		$exp = PHP_INT_MAX;
		foreach ( $rows as $r ) {
			$exp = min( $exp, (int) $r[2] );
			if ( 0 === strpos( $r[0], '00000000000000000000ffff' ) && 0 === strpos( $r[1], '00000000000000000000ffff' ) ) {
				$v4[] = array( hex2bin( substr( $r[0], 24 ) ), hex2bin( substr( $r[1], 24 ) ) );
			} else {
				$v6[] = array( hex2bin( $r[0] ), hex2bin( $r[1] ) );
			}
		}
		update_option(
			self::CACHE,
			array(
				'v4'  => base64_encode( self::pack_ranges( $v4 ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'v6'  => base64_encode( self::pack_ranges( $v6 ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'exp' => $exp,
			),
			true
		);
	}

	/**
	 * Sort, merge overlapping/adjacent ranges and concatenate from.to pairs.
	 *
	 * @param array $ranges [ [ from_bin, to_bin ] ].
	 * @return string
	 */
	private static function pack_ranges( array $ranges ) {
		usort(
			$ranges,
			static function ( $a, $b ) {
				return strcmp( $a[0], $b[0] );
			}
		);
		$merged = array();
		foreach ( $ranges as $r ) {
			$last = count( $merged ) - 1;
			if ( $last >= 0 && strcmp( $r[0], $merged[ $last ][1] ) <= 0 ) {
				if ( strcmp( $r[1], $merged[ $last ][1] ) > 0 ) {
					$merged[ $last ][1] = $r[1];
				}
				continue;
			}
			$merged[] = $r;
		}
		$out = '';
		foreach ( $merged as $r ) {
			$out .= $r[0] . $r[1];
		}
		return $out;
	}

	/**
	 * Is a (hex, 16-byte IPv4-mapped) address inside a feed network?
	 *
	 * @param string $hex 32-char hex from IP::to_hex().
	 * @return bool
	 */
	public static function match( $hex ) {
		$c = get_option( self::CACHE );
		if ( ! is_array( $c ) || (int) ( $c['exp'] ?? 0 ) < time() ) {
			return false; // No feeds, or the lists went stale (updates stopped): never block on old data.
		}
		$is4  = 0 === strpos( $hex, '00000000000000000000ffff' );
		$key  = $is4 ? hex2bin( substr( $hex, 24 ) ) : hex2bin( $hex );
		$w    = $is4 ? 4 : 16;
		$data = base64_decode( (string) ( $is4 ? $c['v4'] : $c['v6'] ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( ! $data || false === $key ) {
			return false;
		}
		$lo = 0;
		$hi = intdiv( strlen( $data ), 2 * $w ) - 1;
		while ( $lo <= $hi ) {
			$mid  = ( $lo + $hi ) >> 1;
			$from = substr( $data, $mid * 2 * $w, $w );
			if ( strcmp( $key, $from ) < 0 ) {
				$hi = $mid - 1;
				continue;
			}
			if ( strcmp( $key, substr( $data, $mid * 2 * $w + $w, $w ) ) <= 0 ) {
				return true;
			}
			$lo = $mid + 1;
		}
		return false;
	}


	/**
	 * Extract IPs / CIDRs from a feed body (JSON lines, "cidr ; comment" text, or plain IPs).
	 *
	 * @param string $body Body.
	 * @return string[]
	 */
	public static function parse( $body ) {
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || ';' === $line[0] || '#' === $line[0] ) {
				continue;
			}
			if ( '{' === $line[0] ) {
				$j    = json_decode( $line, true );
				$line = is_array( $j ) && isset( $j['cidr'] ) ? (string) $j['cidr'] : '';
			} else {
				$line = trim( strtok( $line, ' ;#' ) );
			}
			if ( '' === $line || ! IP::range( $line ) ) {
				continue;
			}
			$out[] = $line;
		}
		return $out;
	}

	/**
	 * Replace a feed's rows in the blocklist table.
	 *
	 * @param string   $key     Feed key.
	 * @param string[] $entries Entries.
	 * @return int Rows stored.
	 */
	private static function replace( $key, array $entries ) {
		global $wpdb;
		$table  = Blocklist::table();
		$source = 'feed:' . $key;
		$wpdb->delete( $table, array( 'source' => $source ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$never  = IP::parse_list( array_merge( IP::PRIVATE_RANGES, array( '0.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', 'fe80::/10', '::/128' ) ) );
		$self   = isset( $_SERVER['SERVER_ADDR'] ) ? IP::normalize( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';
		$allow  = IP::parse_list( Settings::lines( 'fw_allowlist' ) );
		$now    = time();
		$rows   = array();
		$params = array();
		$stored = 0;
		foreach ( $entries as $e ) {
			$r = IP::range( $e );
			if ( ! $r ) {
				continue;
			}
			// Never import ranges that overlap private space, this server or the allowlist.
			$overlap = false;
			foreach ( array_merge( $never, $allow ) as $n ) {
				if ( strcmp( $r[0], $n[1] ) <= 0 && strcmp( $n[0], $r[1] ) <= 0 ) {
					$overlap = true;
					break;
				}
			}
			if ( $overlap || ( $self && IP::in_ranges( $self, array( $r ) ) ) ) {
				continue;
			}
			$rows[]   = '(%s, %s, %s, %s, %s, %d, %d)';
			$params[] = $r[0];
			$params[] = $r[1];
			$params[] = substr( $e, 0, 64 );
			$params[] = self::sources()[ $key ]['label'];
			$params[] = $source;
			$params[] = $now;
			$params[] = $now + self::TTL;
			++$stored;
			if ( count( $rows ) >= 400 ) {
				self::insert( $table, $rows, $params );
				$rows   = array();
				$params = array();
			}
		}
		if ( $rows ) {
			self::insert( $table, $rows, $params );
		}
		return $stored;
	}

	/**
	 * @param string $table  Table.
	 * @param array  $rows   Placeholders.
	 * @param array  $params Values.
	 */
	private static function insert( $table, array $rows, array $params ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (ip_from, ip_to, label, reason, source, created, expires) VALUES " . implode( ',', $rows ), $params ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Total feed networks currently stored.
	 *
	 * @return int
	 */
	public static function count() {
		$n = 0;
		foreach ( self::state() as $s ) {
			$n += (int) ( $s['count'] ?? 0 );
		}
		return $n;
	}
}
