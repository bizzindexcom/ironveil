<?php
/**
 * Licensing: Free vs Pro.
 *
 * License keys are issued OFFLINE by the author with tools/ironveil-license.php
 * and signed with the author's Ed25519 private key. The plugin only contains
 * the public key, so nobody else can create a valid key. A key is bound to
 * one or more domains, may expire, and can be revoked through the signed
 * signature feed ("revoked_licenses").
 *
 * Key format:  IVL1.<base64url(payload JSON)>.<base64url(Ed25519 signature)>
 * Payload:     { "v":1, "id":"…", "name":"Customer", "type":"paid|complimentary|owner",
 *                "domains":["example.com","*.example.org"], "issued":…, "expires":0 }
 *
 * Note: like every PHP plugin, the source code is readable and editable by
 * whoever controls the server; licensing deters casual use, it cannot stop a
 * determined person from modifying their own copy.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class License {

	/** Author's public verification key (Jassim T Mohammad). */
	const PUBLIC_KEY = '40K0ro0Hol80wqZMB/m1TX1ic5e9tFs00JU2GB6Hrbg=';

	/** Where customers buy a license. Change before distributing. */
	const PURCHASE_URL = 'https://example.com/ironveil-pro';

	/**
	 * Default signed signature/revocation feed that every Pro site follows
	 * (https URL of the signatures.json you publish). Empty = none until set.
	 */
	const DEFAULT_FEED_URL = '';

	const OPTION = 'ironveil_license';
	const CACHE  = 'ironveil_license_cache';

	/** License ids revoked in code (in addition to the signed feed). */
	const REVOKED = array();

	/**
	 * Settings that are Pro-only, and the value they take in the Free edition.
	 * Settings::get() applies these, so every feature respects the license
	 * automatically; stored values are kept and return when a key is added.
	 */
	const PRO_SETTINGS = array(
		'clamav_mode'           => 'off',
		'clamav_all_files'      => 0,
		'clamav_socket'         => '',
		'clamav_max_mb'         => 20,
		'sig_feed_key'          => '',
		'scan_extra_paths'      => '',
		'sig_feed_url'          => '',
		'custom_signatures'     => '',
		'scan_auto_quarantine'  => 0,
		'scan_auto_repair_core' => 0,
		'wpscan_token'          => '',
		'fw_blocked_countries'  => '',
		'notify_events'         => array(),
		'scan_deep_days'        => 0,
	);

	/** @var array|null Per-request result. */
	private static $status = null;

	/**
	 * Is Pro active on this site?
	 *
	 * @return bool
	 */
	public static function is_pro() {
		return ! empty( self::status()['valid'] );
	}

	/**
	 * Is a setting Pro-only?
	 *
	 * @param string $key Setting.
	 * @return bool
	 */
	public static function is_pro_setting( $key ) {
		return array_key_exists( $key, self::PRO_SETTINGS );
	}

	/**
	 * Current license status (cached per request, and across requests in an
	 * autoloaded option keyed by an HMAC of key + domain, so a signature is
	 * only verified when something changes).
	 *
	 * @return array { valid, reason, name, type, id, expires, domains }
	 */
	public static function status() {
		if ( null !== self::$status ) {
			return self::$status;
		}
		$key = (string) get_option( self::OPTION, '' );
		if ( '' === $key ) {
			self::$status = array(
				'valid'  => false,
				'reason' => 'none',
			);
			return self::$status;
		}
		$host  = self::site_host();
		$mac   = hash_hmac( 'sha256', $key . '|' . $host . '|' . self::revocation_fingerprint(), self::local_secret() );
		$cache = get_option( self::CACHE );
		if ( is_array( $cache ) && isset( $cache['mac'] ) && hash_equals( $cache['mac'], $mac ) ) {
			$st = $cache['status'];
		} else {
			$st = self::verify( $key, $host );
			update_option(
				self::CACHE,
				array(
					'mac'    => $mac,
					'status' => $st,
				),
				true
			);
		}
		// Expiry is time-dependent, so it is always re-checked.
		if ( ! empty( $st['valid'] ) && ! empty( $st['expires'] ) && (int) $st['expires'] < time() ) {
			$st['valid']  = false;
			$st['reason'] = 'expired';
		}
		self::$status = $st;
		return $st;
	}

	/**
	 * Verify a key for a host.
	 *
	 * @param string $key  License key.
	 * @param string $host Site host.
	 * @return array
	 */
	public static function verify( $key, $host ) {
		$bad = static function ( $reason ) {
			return array(
				'valid'  => false,
				'reason' => $reason,
			);
		};
		$key = trim( (string) $key );
		if ( ! preg_match( '/^IVL1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/', $key, $m ) || strlen( $key ) > 4096 ) {
			return $bad( 'format' );
		}
		$payload = self::b64url_decode( $m[1] );
		$sig     = self::b64url_decode( $m[2] );
		$pk      = base64_decode( self::PUBLIC_KEY, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $payload || false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) || false === $pk ) {
			return $bad( 'format' );
		}
		try {
			$ok = sodium_crypto_sign_verify_detached( $sig, $payload, $pk );
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		if ( ! $ok ) {
			return $bad( 'signature' );
		}
		$p = json_decode( $payload, true );
		if ( ! is_array( $p ) || 1 !== (int) ( $p['v'] ?? 0 ) || empty( $p['id'] ) || empty( $p['domains'] ) || ! is_array( $p['domains'] ) ) {
			return $bad( 'format' );
		}
		$id = (string) $p['id'];
		if ( in_array( $id, self::revoked_ids(), true ) ) {
			return $bad( 'revoked' );
		}
		if ( ! empty( $p['expires'] ) && (int) $p['expires'] < time() ) {
			return $bad( 'expired' );
		}
		if ( ! self::domain_allowed( $host, $p['domains'] ) ) {
			$st            = $bad( 'domain' );
			$st['domains'] = array_map( 'strval', $p['domains'] );
			return $st;
		}
		return array(
			'valid'   => true,
			'reason'  => 'ok',
			'id'      => $id,
			'name'    => substr( sanitize_text_field( (string) ( $p['name'] ?? '' ) ), 0, 100 ),
			'type'    => in_array( $p['type'] ?? '', array( 'paid', 'complimentary', 'owner' ), true ) ? $p['type'] : 'paid',
			'expires' => (int) ( $p['expires'] ?? 0 ),
			'domains' => array_map( 'strval', $p['domains'] ),
		);
	}

	/**
	 * Domain rules: exact host, "*.example.com" (subdomains and apex), or "*" (any
	 * site – owner keys only). "www." is ignored.
	 *
	 * @param string   $host    Host.
	 * @param string[] $domains Allowed.
	 * @return bool
	 */
	public static function domain_allowed( $host, array $domains ) {
		$host = self::normalize_host( $host );
		foreach ( $domains as $d ) {
			$d = strtolower( trim( (string) $d ) );
			if ( '*' === $d ) {
				return true;
			}
			if ( 0 === strpos( $d, '*.' ) ) {
				$base = self::normalize_host( substr( $d, 2 ) );
				if ( $host === $base || substr( $host, -strlen( '.' . $base ) ) === '.' . $base ) {
					return true;
				}
			} elseif ( self::normalize_host( $d ) === $host ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $h Host.
	 * @return string
	 */
	private static function normalize_host( $h ) {
		$h = strtolower( trim( (string) $h, " .\t\n" ) );
		return 0 === strpos( $h, 'www.' ) ? substr( $h, 4 ) : $h;
	}

	/**
	 * @return string This site's host.
	 */
	public static function site_host() {
		$home = (string) get_option( 'home' );
		$host = (string) wp_parse_url( $home, PHP_URL_HOST );
		return self::normalize_host( $host );
	}

	/**
	 * Revoked ids from code + the signed feed.
	 *
	 * @return string[]
	 */
	private static function revoked_ids() {
		$feed = get_option( Signature_Feed::OPTION );
		$ids  = is_array( $feed ) && ! empty( $feed['revoked'] ) ? (array) $feed['revoked'] : array();
		return array_merge( self::REVOKED, array_map( 'strval', $ids ) );
	}

	/**
	 * @return string Changes whenever the revocation list changes (cache busting).
	 */
	private static function revocation_fingerprint() {
		$feed = get_option( Signature_Feed::OPTION );
		return is_array( $feed ) ? (string) ( $feed['version'] ?? 0 ) : '0';
	}

	/**
	 * Local HMAC secret from wp-config (no pluggable functions: usable early).
	 *
	 * @return string
	 */
	private static function local_secret() {
		return hash( 'sha256', 'ironveil-license|' . ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' ) . ( defined( 'NONCE_SALT' ) ? NONCE_SALT : '' ) );
	}

	/**
	 * @param string $s Input.
	 * @return string|false
	 */
	public static function b64url_decode( $s ) {
		$s = strtr( (string) $s, '-_', '+/' );
		$s .= str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 );
		return base64_decode( $s, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}

	/**
	 * Save a key after verifying it for this site.
	 *
	 * @param string $key Key.
	 * @return array Status.
	 */
	public static function activate( $key ) {
		$key = preg_replace( '/\s+/', '', (string) $key );
		$st  = self::verify( $key, self::site_host() );
		if ( ! empty( $st['valid'] ) ) {
			update_option( self::OPTION, $key, true );
			delete_option( self::CACHE );
			self::$status = null;
			Log::add( 'license_activated', sprintf( 'Pro license activated (%1$s, %2$s)', $st['type'], $st['name'] ), Log::NOTICE );
			do_action( 'ironveil_settings_saved', Settings::all() );
		}
		return $st;
	}

	/**
	 * Remove the key (back to Free).
	 */
	public static function deactivate() {
		delete_option( self::OPTION );
		delete_option( self::CACHE );
		self::$status = null;
		Log::add( 'license_deactivated', 'Pro license removed', Log::NOTICE );
		do_action( 'ironveil_settings_saved', Settings::all() );
	}

	/** Reset per-request cache (after feed updates). */
	public static function flush() {
		self::$status = null;
	}

	/**
	 * Human text for a failure reason.
	 *
	 * @param string $reason Reason code.
	 * @return string
	 */
	public static function reason_text( $reason ) {
		$map = array(
			'none'      => __( 'No license key entered.', 'ironveil-security' ),
			'format'    => __( 'This is not a valid IronVeil license key.', 'ironveil-security' ),
			'signature' => __( 'This license key is not genuine (signature check failed).', 'ironveil-security' ),
			'revoked'   => __( 'This license key has been revoked.', 'ironveil-security' ),
			'domain'    => __( 'This license key is for a different domain.', 'ironveil-security' ),
			'expired'   => __( 'This license key has expired.', 'ironveil-security' ),
		);
		return isset( $map[ $reason ] ) ? $map[ $reason ] : $reason;
	}
}
