<?php
/**
 * PSR-4-ish autoloader: IronVeil\Foo_Bar => includes/class-foo-bar.php
 *
 * @package IronVeil
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( $class ) {
		if ( 0 !== strpos( $class, 'IronVeil\\' ) ) {
			return;
		}
		$name = substr( $class, 9 );
		if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $name ) ) {
			return;
		}
		$file = __DIR__ . '/class-' . strtolower( str_replace( '_', '-', $name ) ) . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);
