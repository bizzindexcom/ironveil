<?php
/**
 * IronVeil signature-feed signing tool (command line only).
 *
 * Run this on YOUR OWN computer, never on the web server, and keep the
 * secret key offline. The web server only ever needs the public key.
 *
 *   php ironveil-sign.php keygen  <secret-key-file>
 *       Creates an Ed25519 key pair. Prints the public key to paste into
 *       IronVeil → Scanner → "Feed public key" (or IRONVEIL_SIG_FEED_KEY).
 *
 *   php ironveil-sign.php sign    <rules.json> <secret-key-file> > signatures.json
 *       Validates every rule, stamps issued/expires, signs the payload.
 *       Upload signatures.json to any https:// location (your site, a
 *       GitHub raw URL, a CDN) and set it as the feed URL.
 *
 *   php ironveil-sign.php verify  <signatures.json> <public-key-base64>
 *
 * rules.json format: see feed-example.json. Increase "version" every time.
 *
 * @package IronVeil
 */

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
if ( ! function_exists( 'sodium_crypto_sign_detached' ) ) {
	fwrite( STDERR, "PHP sodium extension is required (PHP 7.2+).\n" );
	exit( 1 );
}

$cmd = $argv[1] ?? '';

/**
 * Print to stderr and exit.
 *
 * @param string $msg Message.
 */
function ironveil_die( $msg ) {
	fwrite( STDERR, $msg . "\n" );
	exit( 1 );
}

if ( 'keygen' === $cmd ) {
	$file = $argv[2] ?? ironveil_die( 'Usage: keygen <secret-key-file>' );
	if ( file_exists( $file ) ) {
		ironveil_die( "Refusing to overwrite $file" );
	}
	$pair = sodium_crypto_sign_keypair();
	umask( 0077 );
	file_put_contents( $file, base64_encode( sodium_crypto_sign_secretkey( $pair ) ) . "\n" );
	chmod( $file, 0600 );
	echo 'Secret key written to ' . $file . " (keep it private and backed up).\n";
	echo 'Public key: ' . base64_encode( sodium_crypto_sign_publickey( $pair ) ) . "\n";
	exit( 0 );
}

if ( 'sign' === $cmd ) {
	$rules_file = $argv[2] ?? ironveil_die( 'Usage: sign <rules.json> <secret-key-file>' );
	$key_file   = $argv[3] ?? ironveil_die( 'Usage: sign <rules.json> <secret-key-file>' );
	$rules      = json_decode( (string) file_get_contents( $rules_file ), true );
	if ( ! is_array( $rules ) ) {
		ironveil_die( 'rules.json is not valid JSON: ' . json_last_error_msg() );
	}
	$sk = base64_decode( trim( (string) file_get_contents( $key_file ) ), true );
	if ( false === $sk || SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== strlen( $sk ) ) {
		ironveil_die( 'Invalid secret key file.' );
	}
	if ( empty( $rules['version'] ) || (int) $rules['version'] < 1 ) {
		ironveil_die( '"version" must be a positive integer and must increase with every release.' );
	}
	$errors = 0;
	foreach ( array( 'php', 'js', 'config' ) as $set ) {
		foreach ( $rules[ $set ] ?? array() as $i => $r ) {
			$p = (string) ( $r['pattern'] ?? '' );
			$bad = ! preg_match( '/^[a-z0-9_]{3,40}$/', (string) ( $r['id'] ?? '' ) )
				|| (int) ( $r['severity'] ?? 0 ) < 1 || (int) ( $r['severity'] ?? 0 ) > 4
				|| '' === trim( (string) ( $r['description'] ?? '' ) )
				|| '' === $p || strlen( $p ) > 2000
				|| preg_match( '/\(\*|\(\?C|\(\?\||\\\\[1-9]|\\\\g|\\\\k|\(\?P?<[a-zA-Z]|\(\?\'/', $p )
				|| false === @preg_match( '~(?:' . str_replace( '~', '\\~', $p ) . ')|(?:x)~iS', '' );
			if ( $bad ) {
				fwrite( STDERR, "Invalid rule {$set}[{$i}] (" . ( $r['id'] ?? '?' ) . ") – IronVeil would reject it.\n" );
				++$errors;
			}
		}
	}
	if ( $errors ) {
		ironveil_die( "$errors invalid rule(s); nothing signed." );
	}
	$rules['format']  = 1;
	$rules['issued']  = time();
	$rules['expires'] = $rules['expires'] ?? time() + 90 * 86400; // Stale feeds stop being accepted.
	$payload          = json_encode( $rules, JSON_UNESCAPED_SLASHES );
	echo json_encode(
		array(
			'version'   => (int) $rules['version'],
			'payload'   => base64_encode( $payload ),
			'signature' => base64_encode( sodium_crypto_sign_detached( $payload, $sk ) ),
		),
		JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
	) . "\n";
	exit( 0 );
}

if ( 'verify' === $cmd ) {
	$doc = json_decode( (string) file_get_contents( $argv[2] ?? ironveil_die( 'Usage: verify <signatures.json> <public-key>' ) ), true );
	$pk  = base64_decode( (string) ( $argv[3] ?? '' ), true );
	if ( ! is_array( $doc ) || false === $pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
		ironveil_die( 'Bad input.' );
	}
	$payload = base64_decode( (string) $doc['payload'], true );
	$ok      = sodium_crypto_sign_verify_detached( base64_decode( (string) $doc['signature'], true ), (string) $payload, $pk );
	echo $ok ? "VALID signature.\n" : "INVALID signature!\n";
	exit( $ok ? 0 : 2 );
}

ironveil_die( "Usage:\n  php ironveil-sign.php keygen <secret-key-file>\n  php ironveil-sign.php sign <rules.json> <secret-key-file> > signatures.json\n  php ironveil-sign.php verify <signatures.json> <public-key>" );
