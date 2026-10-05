<?php
/**
 * Rebuild checksums.json after editing any plugin file (e.g. PURCHASE_URL),
 * so IronVeil's self-integrity check does not report your edit as tampering.
 *
 *   php tools/build-checksums.php
 *
 * @package IronVeil
 */

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
$root  = dirname( __DIR__ );
$files = array();
$it    = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	$rel = str_replace( '\\', '/', substr( $f->getPathname(), strlen( $root ) + 1 ) );
	if ( 'checksums.json' === $rel ) {
		continue;
	}
	$files[ $rel ] = md5_file( $f->getPathname() );
}
ksort( $files );
preg_match( "/define\( 'IRONVEIL_VERSION', '([^']+)'/", (string) file_get_contents( $root . '/ironveil-security.php' ), $m );
file_put_contents( $root . '/checksums.json', json_encode( array( 'plugin' => 'ironveil-security', 'version' => $m[1] ?? '', 'files' => $files ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
echo count( $files ) . " files hashed into checksums.json\n";
