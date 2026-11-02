<?php
/**
 * IronVeil license key generator (command line only – run it on YOUR computer).
 *
 * Paid license for one site, valid one year:
 *   php ironveil-license.php issue --key=<private.key> --name="Acme Ltd" --domain=acme.com --days=365
 *
 * Free Pro for a site you permit, never expires:
 *   php ironveil-license.php issue --key=<private.key> --name="My friend" --domain=friend.org --type=complimentary --lifetime
 *
 * A domain and all its subdomains:   --domain=shop.com --domain=*.shop.com
 * Owner key for ANY site (keep it secret):  --domain=* --type=owner --lifetime
 *
 * Every key you issue is also appended to licenses-issued.csv next to your
 * private key, so you always have the id you need to revoke it later.
 *
 * Inspect a key (and check it is genuine):
 *   php ironveil-license.php inspect <license key> [--pubkey=<base64> | --plugin=<plugin folder>]
 *
 * Revoke: put the key's id in "revoked_licenses" in your signed feed and publish it.
 *
 * @package IronVeil
 */

require __DIR__ . '/ironveil-common.php';

/**
 * @param string $s Binary.
 * @return string
 */
function ironveil_b64url( $s ) {
	return rtrim( strtr( base64_encode( $s ), '+/', '-_' ), '=' );
}

/**
 * @param string $s Encoded.
 * @return string|false
 */
function ironveil_b64url_decode( $s ) {
	$s = strtr( (string) $s, '-_', '+/' );
	return base64_decode( $s . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true );
}

$ironveil_cmd  = $argv[1] ?? '';
$ironveil_opts = ironveil_parse_args( array_slice( $argv, 2 ), array( 'domain' ) );

if ( 'issue' === $ironveil_cmd ) {
	if ( empty( $ironveil_opts['key'] ) || true === $ironveil_opts['key'] ) {
		ironveil_fail( '--key=<private key file> is required.' );
	}
	$ironveil_type = $ironveil_opts['type'] ?? 'paid';
	if ( ! in_array( $ironveil_type, array( 'paid', 'complimentary', 'owner' ), true ) ) {
		ironveil_fail( '--type must be paid, complimentary or owner.' );
	}
	$ironveil_name = trim( (string) ( $ironveil_opts['name'] ?? '' ) );
	if ( '' === $ironveil_name || true === ( $ironveil_opts['name'] ?? null ) ) {
		ironveil_fail( '--name="Customer name" is required (it is shown on the customer\'s License page).' );
	}
	if ( strlen( $ironveil_name ) > 100 ) {
		ironveil_fail( '--name must be 100 characters or fewer.' );
	}

	// Domains: normalise, validate, de-duplicate.
	$ironveil_domains = array();
	foreach ( $ironveil_opts['domain'] as $ironveil_d ) {
		$ironveil_d = strtolower( trim( (string) $ironveil_d, " \t." ) );
		if ( 0 === strpos( $ironveil_d, 'www.' ) ) {
			$ironveil_d = substr( $ironveil_d, 4 ); // The plugin ignores "www." anyway.
		}
		if ( '*' !== $ironveil_d && ! preg_match( '/^(\*\.)?(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $ironveil_d ) ) {
			ironveil_fail( "Invalid domain \"{$ironveil_d}\". Use the bare host name, e.g. example.com (no https://, path or port). Internationalised names must be in punycode (xn--...)." );
		}
		$ironveil_domains[] = $ironveil_d;
	}
	$ironveil_domains = array_values( array_unique( $ironveil_domains ) );
	if ( ! $ironveil_domains ) {
		ironveil_fail( 'At least one --domain=example.com is required.' );
	}
	if ( in_array( '*', $ironveil_domains, true ) && 'owner' !== $ironveil_type ) {
		ironveil_fail( 'The "*" (any site) domain is only allowed with --type=owner.' );
	}

	// Duration: must be explicit, so a typo can never create a lifetime key.
	$ironveil_life = ! empty( $ironveil_opts['lifetime'] );
	$ironveil_days = $ironveil_opts['days'] ?? null;
	if ( $ironveil_life && null !== $ironveil_days ) {
		ironveil_fail( 'Use either --days=N or --lifetime, not both.' );
	}
	if ( ! $ironveil_life ) {
		if ( null === $ironveil_days || true === $ironveil_days || ! ctype_digit( (string) $ironveil_days ) || (int) $ironveil_days < 1 || (int) $ironveil_days > 36500 ) {
			ironveil_fail( 'Give --days=N (a whole number from 1 to 36500) or --lifetime for a key that never expires.' );
		}
	}
	if ( 'paid' === $ironveil_type && $ironveil_life ) {
		ironveil_warn( 'Issuing a paid license that never expires.' );
	}

	$ironveil_sk      = ironveil_load_key( (string) $ironveil_opts['key'] );
	$ironveil_issued  = time();
	$ironveil_expires = $ironveil_life ? 0 : $ironveil_issued + 86400 * (int) $ironveil_days;
	$ironveil_payload = json_encode(
		array(
			'v'       => 1,
			'id'      => ironveil_b64url( random_bytes( 9 ) ),
			'name'    => $ironveil_name,
			'type'    => $ironveil_type,
			'domains' => $ironveil_domains,
			'issued'  => $ironveil_issued,
			'expires' => $ironveil_expires,
		),
		JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
	);
	if ( false === $ironveil_payload ) {
		ironveil_fail( 'Could not encode the license (is the name valid UTF-8?).' );
	}
	$ironveil_license = 'IVL1.' . ironveil_b64url( $ironveil_payload ) . '.' . ironveil_b64url( sodium_crypto_sign_detached( $ironveil_payload, $ironveil_sk ) );
	if ( strlen( $ironveil_license ) > IRONVEIL_MAX_LICENSE ) {
		ironveil_fail( 'This license would be ' . strlen( $ironveil_license ) . ' characters; the plugin accepts at most ' . IRONVEIL_MAX_LICENSE . '. Use fewer domains (a *.domain entry covers all subdomains).' );
	}
	// Self-check before handing it out.
	if ( ! sodium_crypto_sign_verify_detached( ironveil_b64url_decode( explode( '.', $ironveil_license )[2] ), $ironveil_payload, sodium_crypto_sign_publickey_from_secretkey( $ironveil_sk ) ) ) {
		ironveil_fail( 'Internal self-check failed; nothing was issued.' );
	}

	// Ledger next to the private key (needed for support and revocation).
	$ironveil_p      = json_decode( $ironveil_payload, true );
	$ironveil_ledger = dirname( (string) $ironveil_opts['key'] ) . DIRECTORY_SEPARATOR . 'licenses-issued.csv';
	$ironveil_new    = ! is_file( $ironveil_ledger );
	$ironveil_fh     = @fopen( $ironveil_ledger, 'ab' );
	if ( $ironveil_fh ) {
		if ( $ironveil_new ) {
			fputcsv( $ironveil_fh, array( 'id', 'name', 'type', 'domains', 'issued_utc', 'expires_utc' ), ',', '"', '\\' );
		}
		fputcsv( $ironveil_fh, array( $ironveil_p['id'], $ironveil_name, $ironveil_type, implode( ' ', $ironveil_domains ), gmdate( 'Y-m-d H:i', $ironveil_issued ), $ironveil_expires ? gmdate( 'Y-m-d H:i', $ironveil_expires ) : 'never' ), ',', '"', '\\' );
		fclose( $ironveil_fh );
	} else {
		ironveil_warn( 'Could not record this license in ' . $ironveil_ledger . '. Note its id yourself: ' . $ironveil_p['id'] );
	}

	fwrite( STDERR, "Issued {$ironveil_type} license {$ironveil_p['id']} for " . implode( ', ', $ironveil_domains ) . ( $ironveil_expires ? ', expires ' . gmdate( 'Y-m-d', $ironveil_expires ) : ', never expires' ) . ".\n\n" );
	fwrite( STDOUT, $ironveil_license . "\n" );
	exit( 0 );
}

if ( 'inspect' === $ironveil_cmd ) {
	$ironveil_key   = trim( (string) ( $ironveil_opts['_'][0] ?? '' ) );
	$ironveil_parts = explode( '.', $ironveil_key );
	if ( 3 !== count( $ironveil_parts ) || 'IVL1' !== $ironveil_parts[0] ) {
		ironveil_fail( 'Not an IronVeil license key.' );
	}
	$ironveil_payload = ironveil_b64url_decode( $ironveil_parts[1] );
	$ironveil_p       = false === $ironveil_payload ? null : json_decode( $ironveil_payload, true );
	if ( ! is_array( $ironveil_p ) ) {
		ironveil_fail( 'The license key is damaged (payload is not readable).' );
	}
	fwrite( STDOUT, json_encode( $ironveil_p, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
	$ironveil_exp = (int) ( $ironveil_p['expires'] ?? 0 );
	fwrite( STDOUT, 'Expires: ' . ( $ironveil_exp ? gmdate( 'Y-m-d', $ironveil_exp ) . ( $ironveil_exp < time() ? ' (EXPIRED)' : '' ) : 'never' ) . "\n" );
	$ironveil_pub = $ironveil_opts['pubkey'] ?? ( isset( $ironveil_opts['plugin'] ) ? ironveil_plugin_public_key( (string) $ironveil_opts['plugin'] ) : null );
	if ( $ironveil_pub ) {
		$ironveil_pk  = base64_decode( (string) $ironveil_pub, true );
		$ironveil_sig = ironveil_b64url_decode( $ironveil_parts[2] );
		$ironveil_ok  = false !== $ironveil_pk && SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen( $ironveil_pk ) && false !== $ironveil_sig && SODIUM_CRYPTO_SIGN_BYTES === strlen( $ironveil_sig ) && sodium_crypto_sign_verify_detached( $ironveil_sig, $ironveil_payload, $ironveil_pk );
		fwrite( STDOUT, 'Signature: ' . ( $ironveil_ok ? 'GENUINE' : 'NOT VALID for that public key' ) . "\n" );
		exit( $ironveil_ok ? 0 : 2 );
	}
	fwrite( STDOUT, "Signature: not checked (add --pubkey=<base64> or --plugin=<plugin folder>)\n" );
	exit( 0 );
}

ironveil_fail( "Unknown command.\n  php ironveil-license.php issue --key=<private.key> --name=\"Customer\" --domain=example.com [--domain=...] [--type=paid|complimentary|owner] (--days=365 | --lifetime)\n  php ironveil-license.php inspect <license key> [--pubkey=<base64> | --plugin=<plugin folder>]" );
