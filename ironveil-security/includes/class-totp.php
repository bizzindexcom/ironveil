<?php
/**
 * RFC 6238 TOTP / RFC 4226 HOTP with RFC 4648 base32 – no dependencies.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const B32    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * New 160-bit secret, base32.
	 *
	 * @return string
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * @param string $bin Binary.
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$bits = '';
		$len  = strlen( $bin );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $bin[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * @param string $b32 Base32 (spaces, lowercase and padding tolerated).
	 * @return string|false Binary.
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( preg_replace( '/[\s=]/', '', (string) $b32 ) );
		if ( '' === $b32 || strspn( $b32, self::B32 ) !== strlen( $b32 ) ) {
			return false;
		}
		$bits = '';
		$len  = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( strpos( self::B32, $b32[ $i ] ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Counter.
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( false === $key ) {
			return '';
		}
		$hmac   = hash_hmac( 'sha1', pack( 'N2', ( $step >> 32 ) & 0xffffffff, $step & 0xffffffff ), $key, true );
		$offset = ord( $hmac[19] ) & 0x0f;
		$value  = ( ( ord( $hmac[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hmac[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hmac[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hmac[ $offset + 3 ] ) & 0xff );
		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify with ±1 step drift. Returns the matched step (for replay
	 * protection) or false.
	 *
	 * @param string $secret    Base32.
	 * @param string $code      User input.
	 * @param int    $last_step Last accepted step (codes at or before it are rejected).
	 * @param int    $now       Timestamp (tests).
	 * @return int|false
	 */
	public static function verify( $secret, $code, $last_step = 0, $now = null ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$step  = (int) floor( ( null === $now ? time() : $now ) / self::PERIOD );
		$match = false;
		for ( $i = -1; $i <= 1; $i++ ) {
			// Evaluate every window (constant work) to avoid timing hints.
			if ( hash_equals( self::code( $secret, $step + $i ), $code ) && ( $step + $i ) > (int) $last_step ) {
				$match = $step + $i;
			}
		}
		return $match;
	}

	/**
	 * otpauth:// provisioning URI.
	 *
	 * @param string $secret  Secret.
	 * @param string $account Account label.
	 * @param string $issuer  Issuer.
	 * @return string
	 */
	public static function uri( $secret, $account, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer ) . ':' . rawurlencode( $account )
			. '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}
}
