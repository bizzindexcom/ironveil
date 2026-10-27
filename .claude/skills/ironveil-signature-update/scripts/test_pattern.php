<?php
// Test a signature regex: must hit the sample, should miss clean files.
// Usage: php test_pattern.php '<pattern>' <sample> [clean file or dir ...]
if ( $argc < 3 ) { fwrite( STDERR, "Usage: test_pattern.php '<pattern>' <sample> [clean...]\n" ); exit( 2 ); }
$re = '~' . str_replace( '~', '\~', $argv[1] ) . '~i';
if ( false === @preg_match( $re, '' ) ) { echo "FAIL invalid regex: " . preg_last_error_msg() . "\n"; exit( 1 ); }
// Probe without JIT so backtrack_limit applies; production hosts may run either way.
ini_set( 'pcre.jit', '0' );
ini_set( 'pcre.backtrack_limit', '100000' );
foreach ( array( 'a', ' ', '0', 'x=', '%' ) as $c ) {
	if ( false === preg_match( $re, str_repeat( $c, 5000 ) . "\x01" ) ) { echo "FAIL catastrophic backtracking on a repeated '$c' probe\n"; exit( 1 ); }
}
ini_set( 'pcre.jit', '1' );
$hit = preg_match( $re, (string) file_get_contents( $argv[2] ) );
echo ( $hit ? 'ok   ' : 'FAIL ' ) . "sample {$argv[2]} " . ( $hit ? 'matched' : 'NOT matched' ) . "\n";
$fp = 0; $n = 0;
foreach ( array_slice( $argv, 3 ) as $p ) {
	$files = is_dir( $p ) ? new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $p, FilesystemIterator::SKIP_DOTS ) ) : array( new SplFileInfo( $p ) );
	foreach ( $files as $f ) {
		if ( ! preg_match( '/\.(php|js|html?|htaccess|txt|json)$/i', $f->getFilename() ) ) { continue; }
		$n++;
		if ( preg_match( $re, (string) file_get_contents( $f->getPathname() ) ) ) { echo "FP   {$f->getPathname()}\n"; $fp++; }
	}
}
echo "clean files checked: $n, false positives: $fp\n";
exit( $hit && ! $fp ? 0 : 1 );
