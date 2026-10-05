<?php
/**
 * Signature updates without a plugin release.
 *
 * Two sources are merged with the built-in signatures:
 *  1. A remote feed (daily). It MUST be signed with Ed25519: the plugin only
 *     accepts payloads whose detached signature verifies against the public
 *     key you configure. A compromised web host, DNS or TLS MITM therefore
 *     cannot inject rules. Rollback to an older version is refused.
 *  2. Custom signatures typed by an administrator on the Scanner page.
 *
 * Every rule is only a *detection* regex – nothing from the feed is ever
 * executed – and each one is length-limited and test-compiled before use.
 *
 * Feed file format (produced by tools/ironveil-sign.php):
 *   { "payload": "<base64 of the JSON rules>", "signature": "<base64 Ed25519 sig of the raw payload bytes>" }
 * Payload JSON:
 *   { "format": 1, "version": 42, "issued": 1790000000, "expires": 1800000000,
 *     "php": [ { "id": "x", "severity": 4, "description": "…", "pattern": "…" } ],
 *     "js": [ … ], "config": [ … ], "filenames": [ "evil.php" ] }
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Signature_Feed {

	const OPTION        = 'ironveil_sig_feed';
	const MAX_BYTES     = 2097152;
	const MAX_RULES     = 3000;
	const MAX_PATTERN   = 2000;
	const SETS          = array( 'php', 'js', 'config' );

	/**
	 * Configured feed URL (a wp-config constant wins and locks the value).
	 *
	 * @return string
	 */
	public static function url() {
		if ( ! License::is_pro() ) {
			return ''; // Signature updates are a Pro feature.
		}
		if ( defined( 'IRONVEIL_SIG_FEED_URL' ) ) {
			return (string) IRONVEIL_SIG_FEED_URL;
		}
		$url = (string) Settings::get( 'sig_feed_url' );
		return '' !== $url ? $url : License::DEFAULT_FEED_URL;
	}

	/**
	 * Raw 32-byte Ed25519 public key or '' (wp-config constant wins).
	 *
	 * @return string
	 */
	public static function public_key() {
		$b64 = defined( 'IRONVEIL_SIG_FEED_KEY' ) ? (string) IRONVEIL_SIG_FEED_KEY : (string) Settings::get( 'sig_feed_key' );
		if ( '' === trim( $b64 ) ) {
			$b64 = License::PUBLIC_KEY; // Default: feeds signed by the plugin author.
		}
		$raw = base64_decode( trim( $b64 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		return ( false !== $raw && SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen( $raw ) ) ? $raw : '';
	}

	/**
	 * Stored feed state.
	 *
	 * @return array
	 */
	public static function state() {
		$s = get_option( self::OPTION );
		return is_array( $s ) ? $s : array(
			'version' => 0,
			'rules'   => array(),
			'names'   => array(),
		);
	}

	/**
	 * Download, verify and install the feed.
	 *
	 * @param bool $force Ignore ETag cache.
	 * @return true|\WP_Error
	 */
	public static function update( $force = false ) {
		$url = self::url();
		if ( '' === $url ) {
			return new \WP_Error( 'ironveil_feed', __( 'No signature feed URL is configured.', 'ironveil-security' ) );
		}
		if ( 0 !== strpos( $url, 'https://' ) ) {
			return self::fail( __( 'The feed URL must use https://.', 'ironveil-security' ) );
		}
		$key = self::public_key();
		if ( '' === $key ) {
			return self::fail( __( 'A valid Ed25519 public key is required to accept a feed.', 'ironveil-security' ) );
		}
		$state   = self::state();
		$headers = array();
		if ( ! $force && ! empty( $state['etag'] ) ) {
			$headers['If-None-Match'] = $state['etag'];
		}
		$res = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => 10,
				'headers'             => $headers,
				'limit_response_size' => self::MAX_BYTES,
				'user-agent'          => 'IronVeil-Security/' . IRONVEIL_VERSION,
			)
		);
		if ( is_wp_error( $res ) ) {
			return self::fail( $res->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $res );
		if ( 304 === $code ) {
			$state['checked'] = time();
			$state['error']   = '';
			update_option( self::OPTION, $state, false );
			return true;
		}
		if ( 200 !== $code ) {
			/* translators: %d: HTTP status */
			return self::fail( sprintf( __( 'Feed server answered HTTP %d.', 'ironveil-security' ), $code ) );
		}
		$result = self::install( (string) wp_remote_retrieve_body( $res ), $key, (string) wp_remote_retrieve_header( $res, 'etag' ) );
		if ( is_wp_error( $result ) ) {
			return self::fail( $result->get_error_message() );
		}
		return true;
	}

	/**
	 * Verify and store a feed document (also used by tests / manual import).
	 *
	 * @param string $body JSON document.
	 * @param string $key  Raw public key.
	 * @param string $etag ETag.
	 * @return true|\WP_Error
	 */
	public static function install( $body, $key, $etag = '' ) {
		$doc = json_decode( $body, true );
		if ( ! is_array( $doc ) || empty( $doc['payload'] ) || empty( $doc['signature'] ) || ! is_string( $doc['payload'] ) || ! is_string( $doc['signature'] ) ) {
			return new \WP_Error( 'ironveil_feed', __( 'Feed is not in the expected format.', 'ironveil-security' ) );
		}
		$sig = base64_decode( $doc['signature'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$raw = base64_decode( $doc['payload'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $sig || false === $raw || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return new \WP_Error( 'ironveil_feed', __( 'Feed encoding is invalid.', 'ironveil-security' ) );
		}
		try {
			$valid = sodium_crypto_sign_verify_detached( $sig, $raw, $key );
		} catch ( \Throwable $e ) {
			$valid = false;
		}
		if ( ! $valid ) {
			Log::add( 'sig_feed_rejected', 'Signature feed rejected: invalid cryptographic signature', Log::CRITICAL );
			return new \WP_Error( 'ironveil_feed', __( 'Feed signature is INVALID – update rejected (possible tampering).', 'ironveil-security' ) );
		}
		$p = json_decode( $raw, true );
		if ( ! is_array( $p ) || 1 !== (int) ( $p['format'] ?? 0 ) || (int) ( $p['version'] ?? 0 ) < 1 ) {
			return new \WP_Error( 'ironveil_feed', __( 'Unsupported feed format.', 'ironveil-security' ) );
		}
		$state = self::state();
		$ver   = (int) $p['version'];
		if ( $ver < (int) $state['version'] ) {
			Log::add( 'sig_feed_rejected', sprintf( 'Signature feed rollback refused (offered %1$d, installed %2$d)', $ver, $state['version'] ), Log::WARNING );
			/* translators: 1: offered 2: installed */
			return new \WP_Error( 'ironveil_feed', sprintf( __( 'Refused to downgrade signatures from version %2$d to %1$d.', 'ironveil-security' ), $ver, $state['version'] ) );
		}
		if ( ! empty( $p['expires'] ) && (int) $p['expires'] < time() ) {
			return new \WP_Error( 'ironveil_feed', __( 'Feed has expired (stale or replayed). Ask the publisher to re-sign it.', 'ironveil-security' ) );
		}
		$rules    = array();
		$rejected = 0;
		$count    = 0;
		foreach ( self::SETS as $set ) {
			$rules[ $set ] = array();
			foreach ( isset( $p[ $set ] ) && is_array( $p[ $set ] ) ? $p[ $set ] : array() as $r ) {
				if ( ++$count > self::MAX_RULES ) {
					break 2;
				}
				$clean = self::validate_rule( $r );
				if ( $clean ) {
					$rules[ $set ][ 'feed_' . $clean[0] ] = array( $clean[1], $clean[2], $clean[3] );
				} else {
					++$rejected;
				}
			}
		}
		$revoked = array();
		foreach ( isset( $p['revoked_licenses'] ) && is_array( $p['revoked_licenses'] ) ? array_slice( $p['revoked_licenses'], 0, 10000 ) : array() as $rid ) {
			if ( is_string( $rid ) && preg_match( '/^[A-Za-z0-9_-]{4,64}$/', $rid ) ) {
				$revoked[] = $rid;
			}
		}
		$names = array();
		foreach ( isset( $p['filenames'] ) && is_array( $p['filenames'] ) ? array_slice( $p['filenames'], 0, 1000 ) : array() as $n ) {
			$n = strtolower( sanitize_file_name( (string) $n ) );
			if ( '' !== $n ) {
				$names[] = $n;
			}
		}
		update_option(
			self::OPTION,
			array(
				'version'  => $ver,
				'issued'   => (int) ( $p['issued'] ?? 0 ),
				'expires'  => (int) ( $p['expires'] ?? 0 ),
				'rules'    => $rules,
				'names'    => array_values( array_unique( $names ) ),
				'rejected' => $rejected,
				'revoked'  => $revoked,
				'etag'     => substr( $etag, 0, 200 ),
				'updated'  => time(),
				'checked'  => time(),
				'error'    => '',
			),
			false
		);
		Signatures::flush();
		License::flush();
		$total = array_sum( array_map( 'count', $rules ) );
		Log::add( 'sig_feed_updated', sprintf( 'Signatures updated to feed version %1$d (%2$d rules, %3$d rejected)', $ver, $total, $rejected ), Log::NOTICE );
		return true;
	}

	/**
	 * Validate one rule: [ id, severity, description, pattern ] or null.
	 *
	 * @param mixed $r Rule.
	 * @return array|null
	 */
	public static function validate_rule( $r ) {
		if ( ! is_array( $r ) ) {
			return null;
		}
		$id      = isset( $r['id'] ) ? (string) $r['id'] : '';
		$sev     = isset( $r['severity'] ) ? (int) $r['severity'] : 0;
		$desc    = isset( $r['description'] ) ? sanitize_text_field( (string) $r['description'] ) : '';
		$pattern = isset( $r['pattern'] ) ? (string) $r['pattern'] : '';
		if ( ! preg_match( '/^[a-z0-9_]{3,40}$/', $id ) || $sev < 1 || $sev > 4 || '' === $desc || '' === $pattern || strlen( $pattern ) > self::MAX_PATTERN ) {
			return null;
		}
		if ( ! self::pattern_ok( $pattern ) ) {
			return null;
		}
		return array( $id, $sev, substr( $desc, 0, 150 ), $pattern );
	}

	/**
	 * Does the fragment compile inside IronVeil's wrapper, and is it safe?
	 * Rejects PCRE control verbs/callouts and anything that breaks out of
	 * its group; runs it once against a probe string to catch catastrophic
	 * backtracking.
	 *
	 * @param string $pattern Fragment.
	 * @return bool
	 */
	public static function pattern_ok( $pattern ) {
		// No control verbs/callouts, branch-reset, back-references or named groups:
		// rules are merged into one regex, so these would break group numbering.
		$danger = preg_match( '/\(\*|\(\?C|\(\?\||\\\\[1-9gk]|\(\?P?<[a-zA-Z]|\(\?\'|[\x00-\x08\x0e-\x1f]/', $pattern );
		if ( 0 !== $danger ) {
			return false; // Dangerous construct found – or the check itself failed: fail closed.
		}
		if ( ! self::balanced( $pattern ) ) {
			return false;
		}
		$re = '~(?:' . str_replace( '~', '\\~', $pattern ) . ')~iS';
		if ( false === @preg_match( $re, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return false;
		}
		// Must also compile when combined with a following alternative (catches unbalanced ')' tricks).
		if ( false === @preg_match( '~(?:' . str_replace( '~', '\\~', $pattern ) . ')|(?:x)~iS', '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return false;
		}
		$probe = str_repeat( 'a', 5000 ) . str_repeat( '(x', 200 ) . str_repeat( ' ', 2000 );
		return false !== @preg_match( $re, $probe ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	}

	/**
	 * Parentheses must balance at every point (ignoring escapes and character
	 * classes), so a rule can never close IronVeil's wrapper group.
	 *
	 * @param string $p Pattern.
	 * @return bool
	 */
	private static function balanced( $p ) {
		$depth = 0;
		$len   = strlen( $p );
		$class = false;
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $p[ $i ];
			if ( '\\' === $c ) {
				++$i;
				continue;
			}
			if ( $class ) {
				if ( ']' === $c ) {
					$class = false;
				}
				continue;
			}
			if ( '[' === $c ) {
				$class = true;
				if ( isset( $p[ $i + 1 ] ) && ']' === $p[ $i + 1 ] ) {
					++$i; // Literal ] right after [.
				}
			} elseif ( '(' === $c ) {
				++$depth;
			} elseif ( ')' === $c && --$depth < 0 ) {
				return false;
			}
		}
		return 0 === $depth && ! $class;
	}

	/**
	 * Parse the admin's custom signatures textarea.
	 * Line format:  set|severity|description|pattern   (set = php, js or config)
	 *
	 * @param string $text Raw text.
	 * @return array { rules: set => id => rule, errors: string[] }
	 */
	public static function parse_custom( $text ) {
		$rules  = array_fill_keys( self::SETS, array() );
		$errors = array();
		$lines  = preg_split( '/\r\n|\r|\n/', (string) $text );
		foreach ( $lines as $i => $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$parts = explode( '|', $line, 4 );
			if ( 4 !== count( $parts ) || ! in_array( $parts[0], self::SETS, true ) ) {
				/* translators: %d: line number */
				$errors[] = sprintf( __( 'Line %d: expected "set|severity|description|pattern".', 'ironveil-security' ), $i + 1 );
				continue;
			}
			$rule = self::validate_rule(
				array(
					'id'          => 'line_' . ( $i + 1 ),
					'severity'    => $parts[1],
					'description' => $parts[2],
					'pattern'     => $parts[3],
				)
			);
			if ( ! $rule ) {
				/* translators: %d: line number */
				$errors[] = sprintf( __( 'Line %d: invalid severity (1-4) or pattern that does not compile safely.', 'ironveil-security' ), $i + 1 );
				continue;
			}
			$rules[ $parts[0] ][ 'custom_' . $rule[0] ] = array( $rule[1], $rule[2] . ' (custom rule)', $rule[3] );
		}
		return array(
			'rules'  => $rules,
			'errors' => $errors,
		);
	}

	/**
	 * Record a failed update.
	 *
	 * @param string $msg Message.
	 * @return \WP_Error
	 */
	private static function fail( $msg ) {
		$state            = self::state();
		$state['error']   = $msg;
		$state['checked'] = time();
		update_option( self::OPTION, $state, false );
		Log::add( 'sig_feed_error', 'Signature update failed: ' . $msg, Log::NOTICE );
		return new \WP_Error( 'ironveil_feed', $msg );
	}
}
