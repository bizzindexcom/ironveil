<?php
/**
 * Reversible quarantine. Files are moved out of the executable tree into a
 * web-denied folder, stored base64-encoded (inert even if the server were to
 * serve or execute the folder), and can be restored or deleted permanently.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Quarantine {

	const OPTION = 'ironveil_quarantine';

	/** Largest file that is moved into the quarantine (it is held in memory once). */
	const MAX_BYTES = 52428800;

	/** Deny rules that work on Apache 2.2 and 2.4 (a bare "Deny from all" is a 500 on 2.4 without mod_access_compat). */
	const HTACCESS = "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\nOptions -Indexes\n";

	/**
	 * @return string Directory (created and locked down on demand).
	 */
	public static function dir() {
		$dir = trailingslashit( WP_CONTENT_DIR ) . 'ironveil-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$guards = array(
			'.htaccess'  => self::HTACCESS,
			'index.php'  => "<?php\n// Silence is golden.\n",
			'index.html' => '',
			'web.config' => '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
		);
		foreach ( $guards as $f => $c ) {
			$path = $dir . '/' . $f;
			// Rewrite the old 1.2.x .htaccess (could 500 on Apache 2.4) as well as missing guards.
			if ( ! is_file( $path ) || ( '.htaccess' === $f && false === strpos( (string) file_get_contents( $path ), 'IfModule' ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				file_put_contents( $path, $c ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			}
		}
		return $dir;
	}

	/**
	 * @return array id => meta
	 */
	public static function all() {
		$q = get_option( self::OPTION, array() );
		return is_array( $q ) ? $q : array();
	}

	/**
	 * Quarantine a file.
	 *
	 * @param string $rel    Stored path.
	 * @param string $reason Reason.
	 * @param bool   $remove Remove the original (false = backup copy only).
	 * @return true|\WP_Error
	 */
	public static function add( $rel, $reason, $remove = true ) {
		$abs = Scanner::safe_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return new \WP_Error( 'ironveil_q', __( 'File not found or outside the WordPress directory.', 'ironveil-security' ) );
		}
		if ( $remove && self::protected_file( $abs ) ) {
			return new \WP_Error( 'ironveil_q', __( 'This file is essential to WordPress and cannot be quarantined. Use "Repair" or edit it manually.', 'ironveil-security' ) );
		}
		if ( (int) @filesize( $abs ) > self::MAX_BYTES ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return new \WP_Error( 'ironveil_q', __( 'This file is larger than 50 MB. Move it out of the website folders (or delete it) with your host\'s File Manager or FTP.', 'ironveil-security' ) );
		}

		$content = file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $content ) {
			return new \WP_Error( 'ironveil_q', __( 'File is not readable.', 'ironveil-security' ) );
		}
		$perms = fileperms( $abs ) & 0777;
		$id    = bin2hex( random_bytes( 12 ) );
		$dest = self::dir() . '/' . $id . '.q';
		if ( false === file_put_contents( $dest, base64_encode( $content ), LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			return new \WP_Error( 'ironveil_q', __( 'Quarantine folder is not writable.', 'ironveil-security' ) );
		}
		if ( $remove && ! @unlink( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			wp_delete_file( $dest );
			return new \WP_Error( 'ironveil_q', __( 'Could not remove the original file (permissions).', 'ironveil-security' ) );
		}
		$q        = self::all();
		$q[ $id ] = array(
			'path'    => Scanner::rel( $abs ),
			'md5'     => md5( $content ),
			'size'    => strlen( $content ),
			'perms'   => $perms,
			'time'    => time(),
			'reason'  => substr( (string) $reason, 0, 190 ),
			'removed' => (bool) $remove,
		);
		update_option( self::OPTION, $q, false );
		Log::add( 'quarantined', sprintf( '%1$s: %2$s', $remove ? 'Quarantined' : 'Backed up', Scanner::rel( $abs ) ), Log::WARNING );
		return true;
	}

	/**
	 * Files that must never be removed.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	private static function protected_file( $abs ) {
		$rel = Scanner::rel( $abs );
		return in_array( $rel, array( 'wp-config.php', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php' ), true )
			|| wp_normalize_path( $abs ) === wp_normalize_path( IRONVEIL_FILE );
	}

	/**
	 * Remove the newest backup-only copy of a path (used when a repair failed
	 * after the backup was taken, so no stray backups pile up).
	 *
	 * @param string $rel Path.
	 */
	public static function drop_latest_backup( $rel ) {
		$latest = null;
		foreach ( self::all() as $id => $item ) {
			if ( $item['path'] === $rel && empty( $item['removed'] ) && ( null === $latest || $item['time'] >= self::all()[ $latest ]['time'] ) ) {
				$latest = $id;
			}
		}
		if ( null !== $latest ) {
			self::delete( $latest, false );
		}
	}

	/**
	 * Restore a quarantined file (never overwrites an existing file).
	 *
	 * @param string $id Id.
	 * @return true|\WP_Error
	 */
	public static function restore( $id ) {
		$q  = self::all();
		$id = preg_replace( '/[^a-f0-9]/', '', (string) $id );
		if ( ! isset( $q[ $id ] ) ) {
			return new \WP_Error( 'ironveil_q', __( 'Unknown quarantine item.', 'ironveil-security' ) );
		}
		$target = Scanner::safe_path( $q[ $id ]['path'] );
		if ( ! $target ) {
			return new \WP_Error( 'ironveil_q', __( 'Unsafe restore path.', 'ironveil-security' ) );
		}
		if ( file_exists( $target ) ) {
			return new \WP_Error( 'ironveil_q', __( 'A file already exists at the original location.', 'ironveil-security' ) );
		}
		$raw = file_get_contents( self::dir() . '/' . $id . '.q' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$bin = false !== $raw ? base64_decode( $raw, true ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $bin || md5( $bin ) !== $q[ $id ]['md5'] ) {
			return new \WP_Error( 'ironveil_q', __( 'Quarantined copy is damaged.', 'ironveil-security' ) );
		}
		if ( ! is_dir( dirname( $target ) ) ) {
			wp_mkdir_p( dirname( $target ) );
		}
		if ( false === file_put_contents( $target, $bin, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return new \WP_Error( 'ironveil_q', __( 'Could not write the file back.', 'ironveil-security' ) );
		}
		if ( ! empty( $q[ $id ]['perms'] ) ) {
			chmod( $target, (int) $q[ $id ]['perms'] & 0755 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- never restore world-writable bits.
		}
		self::delete( $id, false );
		Log::add( 'quarantine_restored', sprintf( 'Restored from quarantine: %s', $q[ $id ]['path'] ), Log::WARNING );
		return true;
	}

	/**
	 * Permanently delete an item.
	 *
	 * @param string $id  Id.
	 * @param bool   $log Log it.
	 */
	public static function delete( $id, $log = true ) {
		$q  = self::all();
		$id = preg_replace( '/[^a-f0-9]/', '', (string) $id );
		if ( isset( $q[ $id ] ) ) {
			wp_delete_file( self::dir() . '/' . $id . '.q' );
			if ( $log ) {
				Log::add( 'quarantine_deleted', sprintf( 'Deleted permanently: %s', $q[ $id ]['path'] ), Log::NOTICE );
			}
			unset( $q[ $id ] );
			update_option( self::OPTION, $q, false );
		}
	}
}
