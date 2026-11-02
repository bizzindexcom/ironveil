<?php
/**
 * Rebuild checksums.json after editing any plugin file (e.g. PURCHASE_URL),
 * so IronVeil's self-integrity check does not report your edit as tampering.
 *
 *   php tools/build-checksums.php /path/to/ironveil-security
 *
 * Command line only. This file is NOT part of the plugin you distribute.
 *
 * @package IronVeil
 */

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
$ironveil_root = isset( $argv[1] ) ? rtrim( $argv[1], '/\\' ) : '';
if ( '' === $ironveil_root || ! is_file( $ironveil_root . '/ironveil-security.php' ) ) {
	fwrite( STDERR, "Usage: php tools/build-checksums.php /path/to/ironveil-security\n" );
	exit( 1 );
}
$ironveil_files = array();
$ironveil_it    = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $ironveil_root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $ironveil_it as $ironveil_f ) {
	$ironveil_rel = str_replace( '\\', '/', substr( $ironveil_f->getPathname(), strlen( $ironveil_root ) + 1 ) );
	if ( 'checksums.json' === $ironveil_rel ) {
		continue;
	}
	$ironveil_files[ $ironveil_rel ] = md5_file( $ironveil_f->getPathname() );
}
ksort( $ironveil_files );
preg_match( "/define\( 'IRONVEIL_VERSION', '([^']+)'/", (string) file_get_contents( $ironveil_root . '/ironveil-security.php' ), $ironveil_m );
file_put_contents(
	$ironveil_root . '/checksums.json',
	json_encode(
		array(
			'plugin'  => 'ironveil-security',
			'version' => $ironveil_m[1] ?? '',
			'files'   => $ironveil_files,
		),
		JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
	) . "\n"
);
echo count( $ironveil_files ) . " files hashed into checksums.json\n";
