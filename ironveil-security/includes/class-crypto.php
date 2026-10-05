<?php
/**
 * Authenticated encryption for secrets at rest (libsodium secretbox; WordPress
 * ships sodium_compat so this works everywhere). The key is derived from the
 * wp-config.php secret keys, which live outside the database: a database-only
 * leak (SQL injection, stolen backup) does not expose 2FA secrets.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Crypto {

	const PREFIX = 'iv1:';

	/**
	 * @return string 32-byte key.
	 */
	private static function key() {
		$material = ( defined( 'IRONVEIL_ENCRYPTION_KEY' ) ? IRONVEIL_ENCRYPTION_KEY : '' )
			. ( defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '' )
			. ( defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : '' );
		return hash_hmac( 'sha256', 'ironveil-secret-box', $material, true );
	}

	/**
	 * @param string $plain Plaintext.
	 * @return string
	 */
	public static function encrypt( $plain ) {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return self::PREFIX . base64_encode( $nonce . sodium_crypto_secretbox( (string) $plain, $nonce, self::key() ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * @param string $blob Ciphertext.
	 * @return string|false
	 */
	public static function decrypt( $blob ) {
		if ( ! is_string( $blob ) || 0 !== strpos( $blob, self::PREFIX ) ) {
			return false;
		}
		$raw = base64_decode( substr( $blob, strlen( self::PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return false;
		}
		try {
			return sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), self::key() );
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
