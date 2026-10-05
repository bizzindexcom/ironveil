<?php
/**
 * IronVeil license key generator (command line only – run it on YOUR computer).
 *
 * Requires the author's private key file (ironveil-owner-private.key). Never
 * upload that file to a web server or share it.
 *
 * Issue a paid license for one site (1 year):
 *   php ironveil-license.php issue --key=ironveil-owner-private.key --name="Acme Ltd" --domain=acme.com --days=365
 *
 * Grant free Pro to a site you permit (no expiry):
 *   php ironveil-license.php issue --key=ironveil-owner-private.key --name="My friend" --domain=friend.org --type=complimentary
 *
 * Several domains / all subdomains:
 *   --domain=shop.com --domain=*.shop.com
 *
 * Owner key valid on ANY site (keep it private – revoke it if it ever leaks):
 *   php ironveil-license.php issue --key=... --name="Jassim T Mohammad" --domain=* --type=owner
 *
 * Inspect a key (no private key needed):
 *   php ironveil-license.php inspect IVL1.xxxx.yyyy
 *
 * Revoke: add the key's id to "revoked_licenses" in your signed signature feed
 * (see tools/feed-example.json) and publish it; sites drop to Free on the next daily update.
 *
 * @package IronVeil
 */

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}

/**
 * @param string $msg Message.
 */
function ironveil_lic_die( $msg ) {
	fwrite( STDERR, $msg . "\n" );
	exit( 1 );
}

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
	$s = strtr( $s, '-_', '+/' );
	return base64_decode( $s . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true );
}

$cmd  = $argv[1] ?? '';
$opts = array( 'domain' => array() );
foreach ( array_slice( $argv, 2 ) as $arg ) {
	if ( preg_match( '/^--([a-z]+)=(.*)$/s', $arg, $m ) ) {
		if ( 'domain' === $m[1] ) {
			$opts['domain'][] = strtolower( trim( $m[2] ) );
		} else {
			$opts[ $m[1] ] = $m[2];
		}
	} else {
		$opts['_'][] = $arg;
	}
}

if ( 'issue' === $cmd ) {
	$keyfile = $opts['key'] ?? ironveil_lic_die( '--key=<private key file> is required' );
	$sk      = base64_decode( trim( (string) @file_get_contents( $keyfile ) ), true );
	if ( false === $sk || SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== strlen( $sk ) ) {
		ironveil_lic_die( 'Cannot read a valid private key from ' . $keyfile );
	}
	if ( ! $opts['domain'] ) {
		ironveil_lic_die( 'At least one --domain=example.com is required (use --domain=* only for owner keys).' );
	}
	foreach ( $opts['domain'] as $d ) {
		if ( '*' !== $d && ! preg_match( '/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$/', $d ) ) {
			ironveil_lic_die( "Invalid domain: $d (use the bare host, e.g. example.com)" );
		}
	}
	$type = $opts['type'] ?? 'paid';
	if ( ! in_array( $type, array( 'paid', 'complimentary', 'owner' ), true ) ) {
		ironveil_lic_die( '--type must be paid, complimentary or owner' );
	}
	if ( in_array( '*', $opts['domain'], true ) && 'owner' !== $type ) {
		ironveil_lic_die( 'Wildcard "*" domains are only allowed for --type=owner.' );
	}
	$days    = isset( $opts['days'] ) ? (int) $opts['days'] : 0;
	$payload = json_encode(
		array(
			'v'       => 1,
			'id'      => ironveil_b64url( random_bytes( 9 ) ),
			'name'    => (string) ( $opts['name'] ?? '' ),
			'type'    => $type,
			'domains' => array_values( array_unique( $opts['domain'] ) ),
			'issued'  => time(),
			'expires' => $days > 0 ? time() + $days * 86400 : 0,
		),
		JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
	);
	$key = 'IVL1.' . ironveil_b64url( $payload ) . '.' . ironveil_b64url( sodium_crypto_sign_detached( $payload, $sk ) );
	fwrite( STDERR, "License issued:\n" . $payload . "\n\n" );
	echo $key . "\n";
	exit( 0 );
}

if ( 'inspect' === $cmd ) {
	$key = $opts['_'][0] ?? ironveil_lic_die( 'Usage: inspect <license key>' );
	$p   = explode( '.', trim( $key ) );
	if ( 3 !== count( $p ) || 'IVL1' !== $p[0] ) {
		ironveil_lic_die( 'Not an IronVeil license key.' );
	}
	echo ironveil_b64url_decode( $p[1] ) . "\n";
	exit( 0 );
}

ironveil_lic_die( "Usage:\n  php ironveil-license.php issue --key=<private.key> --name=\"Customer\" --domain=example.com [--domain=...] [--type=paid|complimentary|owner] [--days=365]\n  php ironveil-license.php inspect <license key>" );
