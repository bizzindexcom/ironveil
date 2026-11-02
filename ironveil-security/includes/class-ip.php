<?php
/**
 * IP utilities: spoof-resistant client IP detection, IPv4/IPv6 normalisation
 * and CIDR range matching using fixed-width hex (safe to store in utf8 DB
 * columns and options, and comparable with strcmp).
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class IP {

	/** Cloudflare published ranges (https://www.cloudflare.com/ips/). */
	const CLOUDFLARE = array(
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
		'108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
		'162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32',
	);

	const PRIVATE_RANGES = array( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', 'fc00::/7', '::1/128' );

	/** @var string|null */
	private static $client = null;

	/**
	 * Resolve the visitor IP. Proxy headers are honoured only when the TCP
	 * peer (REMOTE_ADDR) is a configured trusted proxy.
	 *
	 * @return string Valid IP or '0.0.0.0'.
	 */
	public static function client() {
		if ( null !== self::$client ) {
			return self::$client;
		}
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? self::normalize( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated by normalize().
		$ip     = $remote ? $remote : '0.0.0.0';
		$source = (string) Settings::get( 'fw_ip_source' );

		if ( 'REMOTE_ADDR' !== $source && $remote && isset( $_SERVER[ $source ] ) ) {
			$trusted = self::parse_list( self::expand_keywords( Settings::lines( 'fw_trusted_proxies' ) ) );
			if ( $trusted && self::in_ranges( $remote, $trusted ) ) {
				$header = (string) wp_unslash( $_SERVER[ $source ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below.
				// Walk right-to-left, skipping our own trusted proxies: the first
				// untrusted hop is the real client (left-most entries are spoofable).
				$hops = array_reverse( array_map( 'trim', explode( ',', $header ) ) );
				foreach ( $hops as $hop ) {
					$hop = self::normalize( $hop );
					if ( ! $hop ) {
						break;
					}
					$ip = $hop;
					if ( ! self::in_ranges( $hop, $trusted ) ) {
						break;
					}
				}
			}
		}
		self::$client = $ip;
		return $ip;
	}

	/** Reset (tests). */
	public static function reset() {
		self::$client = null;
	}

	/**
	 * Validate and canonicalise an IP (IPv4-mapped IPv6 => IPv4, strip port/brackets).
	 *
	 * @param string $ip Raw.
	 * @return string '' when invalid.
	 */
	public static function normalize( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip || strlen( $ip ) > 64 ) {
			return '';
		}
		// [v6]:port or v4:port.
		if ( '[' === $ip[0] && false !== ( $end = strpos( $ip, ']' ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.Found,Squiz.PHP.DisallowMultipleAssignments.FoundInControlStructure
			$ip = substr( $ip, 1, $end - 1 );
		} elseif ( substr_count( $ip, ':' ) === 1 && false !== strpos( $ip, '.' ) ) {
			$ip = strstr( $ip, ':', true );
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return '';
		}
		if ( 16 === strlen( $bin ) && 0 === strncmp( $bin, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			return inet_ntop( substr( $bin, 12 ) );
		}
		return inet_ntop( $bin );
	}

	/**
	 * 32-char hex of the 16-byte (IPv4-mapped) address.
	 *
	 * @param string $ip Valid IP.
	 * @return string '' on failure.
	 */
	public static function to_hex( $ip ) {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $bin ) {
			return '';
		}
		if ( 4 === strlen( $bin ) ) {
			$bin = str_repeat( "\0", 10 ) . "\xff\xff" . $bin;
		}
		return bin2hex( $bin );
	}

	/**
	 * Parse "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" into [from_hex, to_hex].
	 *
	 * @param string $entry Entry.
	 * @return array|null
	 */
	public static function range( $entry ) {
		$entry = trim( (string) $entry );
		$bits  = null;
		if ( false !== strpos( $entry, '/' ) ) {
			list( $entry, $bits ) = explode( '/', $entry, 2 );
			if ( ! ctype_digit( $bits ) ) {
				return null;
			}
			$bits = (int) $bits;
		}
		$ip = self::normalize( $entry );
		if ( ! $ip ) {
			return null;
		}
		$is4 = false !== strpos( $ip, '.' );
		$max = $is4 ? 32 : 128;
		if ( null === $bits ) {
			$bits = $max;
		}
		if ( $bits < 0 || $bits > $max ) {
			return null;
		}
		$bits += $is4 ? 96 : 0;
		$bin   = hex2bin( self::to_hex( $ip ) );
		$from  = '';
		$to    = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$take = max( 0, min( 8, $bits - 8 * $i ) );
			$mask = $take ? ( 0xff << ( 8 - $take ) ) & 0xff : 0;
			$byte = ord( $bin[ $i ] );
			$from .= chr( $byte & $mask );
			$to   .= chr( ( $byte & $mask ) | ( ~$mask & 0xff ) );
		}
		return array( bin2hex( $from ), bin2hex( $to ) );
	}

	/**
	 * @param string[] $entries IPs / CIDRs.
	 * @return array[] Ranges.
	 */
	public static function parse_list( array $entries ) {
		$out = array();
		foreach ( $entries as $e ) {
			$r = self::range( $e );
			if ( $r ) {
				$out[] = $r;
			}
		}
		return $out;
	}

	/**
	 * @param string[] $entries Entries possibly including keywords.
	 * @return string[]
	 */
	public static function expand_keywords( array $entries ) {
		$out = array();
		foreach ( $entries as $e ) {
			$k = strtolower( trim( $e ) );
			if ( 'cloudflare' === $k ) {
				$out = array_merge( $out, self::CLOUDFLARE );
			} elseif ( 'private' === $k ) {
				$out = array_merge( $out, self::PRIVATE_RANGES );
			} else {
				$out[] = $e;
			}
		}
		return $out;
	}

	/**
	 * @param string  $ip     Valid IP.
	 * @param array[] $ranges Parsed ranges.
	 * @return bool
	 */
	public static function in_ranges( $ip, array $ranges ) {
		$hex = self::to_hex( $ip );
		if ( '' === $hex ) {
			return false;
		}
		foreach ( $ranges as $r ) {
			if ( strcmp( $hex, $r[0] ) >= 0 && strcmp( $hex, $r[1] ) <= 0 ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Hex back to printable IP.
	 *
	 * @param string $hex 32-char hex.
	 * @return string
	 */
	public static function from_hex( $hex ) {
		if ( ! is_string( $hex ) || 32 !== strlen( $hex ) || ! ctype_xdigit( $hex ) ) {
			return '';
		}
		$bin = hex2bin( $hex );
		if ( 0 === strncmp( $bin, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			$bin = substr( $bin, 12 );
		}
		return (string) inet_ntop( $bin );
	}

	/**
	 * Is the IP loopback or the server itself (never block ourselves)?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_self( $ip ) {
		if ( '127.0.0.1' === $ip || '::1' === $ip ) {
			return true;
		}
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? self::normalize( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return $server && $server === $ip;
	}
}
