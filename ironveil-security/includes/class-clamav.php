<?php
/**
 * ClamAV integration via the clamd daemon socket (INSTREAM protocol).
 *
 * Why the daemon and not the clamscan binary: clamd keeps the virus database
 * loaded in memory, so each file costs milliseconds. clamscan reloads the
 * whole database (~1 GB RAM, 10–30 s CPU) on every run, which would violate
 * IronVeil's low-load design. INSTREAM streams the bytes over the socket, so
 * clamd does not need filesystem permission to read WordPress files, and no
 * shell/exec functions are used (they are often disabled on shared hosting).
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class ClamAV {

	const CHUNK = 65536;

	/** Common clamd socket locations (Debian/Ubuntu, RHEL/CentOS, cPanel, Alpine, Docker). */
	const CANDIDATES = array(
		'unix:///run/clamav/clamd.ctl',
		'unix:///var/run/clamav/clamd.ctl',
		'unix:///run/clamd.scan/clamd.sock',
		'unix:///var/run/clamd.scan/clamd.sock',
		'unix:///var/run/clamav/clamd.sock',
		'unix:///run/clamav/clamd.sock',
		'unix:///var/run/clamd/clamd.sock',
		'unix:///tmp/clamd.socket',
		'unix:///tmp/clamd.sock',
		'tcp://127.0.0.1:3310',
	);

	/**
	 * The industry-standard harmless EICAR test string, stored reversed and
	 * encoded so host antivirus never flags this plugin file itself.
	 *
	 * @return string
	 */
	private static function eicar() {
		return strrev( base64_decode( 'KkgrSCQhRUxJRi1UU0VULVNVUklWSVROQS1EUkFETkFUUy1SQUNJRSR9NylDQzcpXlAoNDVYWlBcNFtQQUAlUCFPNVg=' ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}

	/** @var int Consecutive connection failures in this request. */
	private static $failures = 0;

	/** @var string|false|null Resolved endpoint for this request. */
	private static $endpoint = null;

	/**
	 * Is ClamAV scanning enabled and reachable?
	 *
	 * @return bool
	 */
	public static function available() {
		return 'off' !== Settings::get( 'clamav_mode' ) && false !== self::endpoint();
	}

	/**
	 * Resolve the clamd endpoint (configured, or auto-detected and cached 1h).
	 *
	 * @param bool $fresh Ignore the cached detection.
	 * @return string|false
	 */
	public static function endpoint( $fresh = false ) {
		if ( null !== self::$endpoint && ! $fresh ) {
			return self::$endpoint;
		}
		$mode = Settings::get( 'clamav_mode' );
		if ( 'off' === $mode ) {
			self::$endpoint = false;
			return false;
		}
		if ( 'custom' === $mode ) {
			$ep             = self::normalize_endpoint( (string) Settings::get( 'clamav_socket' ) );
			self::$endpoint = ( $ep && self::ping( $ep ) ) ? $ep : false;
			return self::$endpoint;
		}
		$cached = $fresh ? false : get_transient( 'ironveil_clamd_ep' );
		if ( false !== $cached ) {
			self::$endpoint = 'none' === $cached ? false : $cached;
			return self::$endpoint;
		}
		$found = false;
		foreach ( self::CANDIDATES as $ep ) {
			if ( 0 === strpos( $ep, 'unix://' ) && ! @file_exists( substr( $ep, 7 ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may warn.
				continue;
			}
			if ( self::ping( $ep ) ) {
				$found = $ep;
				break;
			}
		}
		// Positive results are cached for an hour; "not found" only for 10 minutes so a
		// freshly installed/restarted daemon is picked up quickly.
		set_transient( 'ironveil_clamd_ep', $found ? $found : 'none', $found ? HOUR_IN_SECONDS : 10 * MINUTE_IN_SECONDS );
		self::$endpoint = $found;
		return $found;
	}

	/**
	 * Accepts "/path/to/clamd.sock", "unix:///path", "host:port", "tcp://host:port".
	 * TCP endpoints must be loopback/private unless IRONVEIL_CLAMAV_ALLOW_REMOTE is
	 * defined – file contents are streamed to that host.
	 *
	 * @param string $raw Raw setting.
	 * @return string|false
	 */
	public static function normalize_endpoint( $raw ) {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return false;
		}
		if ( '/' === $raw[0] ) {
			return 'unix://' . $raw;
		}
		if ( 0 === strpos( $raw, 'unix:///' ) ) {
			return $raw;
		}
		$raw = preg_replace( '~^tcp://~', '', $raw );
		if ( ! preg_match( '~^\[?([0-9a-fA-F:.]+|[a-zA-Z0-9.-]+)\]?:(\d{1,5})$~', $raw, $m ) ) {
			return false;
		}
		$host = $m[1];
		$port = (int) $m[2];
		if ( $port < 1 || $port > 65535 ) {
			return false;
		}
		$ip = IP::normalize( $host );
		if ( ! $ip ) {
			$resolved = gethostbyname( $host );
			$ip       = IP::normalize( $resolved );
		}
		$internal = $ip && IP::in_ranges( $ip, IP::parse_list( IP::PRIVATE_RANGES ) );
		if ( ! $internal && ! ( defined( 'IRONVEIL_CLAMAV_ALLOW_REMOTE' ) && IRONVEIL_CLAMAV_ALLOW_REMOTE ) ) {
			return false;
		}
		return 'tcp://' . ( false !== strpos( $host, ':' ) ? '[' . $host . ']' : $host ) . ':' . $port;
	}

	/**
	 * @param string $ep      Endpoint.
	 * @param float  $timeout Seconds.
	 * @return resource|false
	 */
	private static function connect( $ep, $timeout = 2.0 ) {
		$errno  = 0;
		$errstr = '';
		$sock   = @stream_socket_client( $ep, $errno, $errstr, $timeout ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! $sock ) {
			return false;
		}
		stream_set_timeout( $sock, 30 );
		return $sock;
	}

	/**
	 * Send a simple z-command and read the reply.
	 *
	 * @param string $ep  Endpoint.
	 * @param string $cmd Command (PING, VERSION).
	 * @return string|false
	 */
	private static function command( $ep, $cmd ) {
		$sock = self::connect( $ep, 1.0 );
		if ( ! $sock ) {
			return false;
		}
		stream_set_timeout( $sock, 3 );
		fwrite( $sock, 'z' . $cmd . "\0" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		$reply = self::read_reply( $sock );
		fclose( $sock ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return $reply;
	}

	/**
	 * @param resource $sock Socket.
	 * @return string|false
	 */
	private static function read_reply( $sock ) {
		$out = '';
		while ( ! feof( $sock ) && strlen( $out ) < 4096 ) {
			$c = fread( $sock, 1024 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			if ( false === $c || '' === $c ) {
				$meta = stream_get_meta_data( $sock );
				if ( ! empty( $meta['timed_out'] ) ) {
					return false;
				}
				break;
			}
			$out .= $c;
			if ( false !== strpos( $out, "\0" ) ) {
				break;
			}
		}
		return rtrim( $out, "\0\n" );
	}

	/**
	 * @param string $ep Endpoint.
	 * @return bool
	 */
	public static function ping( $ep ) {
		return 'PONG' === trim( (string) self::command( $ep, 'PING' ) );
	}

	/**
	 * "ClamAV 1.4.1/27412/Mon Sep 28 08:00:00 2026" (engine / DB version / DB date).
	 *
	 * @return string|false
	 */
	public static function version() {
		$ep = self::endpoint();
		return $ep ? self::command( $ep, 'VERSION' ) : false;
	}

	/**
	 * Max bytes to stream (clamd's StreamMaxLength default is 25 MB).
	 *
	 * @return int
	 */
	public static function max_bytes() {
		return MB_IN_BYTES * max( 1, (int) Settings::get( 'clamav_max_mb' ) );
	}

	/**
	 * Scan a file.
	 *
	 * @param string $abs Absolute path.
	 * @return array { status: clean|infected|skipped|error, name: string }
	 */
	public static function scan_file( $abs ) {
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > self::max_bytes() ) {
			return array( 'status' => 'skipped', 'name' => '' );
		}
		$fh = @fopen( $abs, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( ! $fh ) {
			return array( 'status' => 'error', 'name' => 'unreadable' );
		}
		$res = self::stream( $fh );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return $res;
	}

	/**
	 * Scan a string (used by the EICAR self-test).
	 *
	 * @param string $data Data.
	 * @return array
	 */
	public static function scan_string( $data ) {
		$fh = fopen( 'php://memory', 'w+b' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		fwrite( $fh, $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		rewind( $fh );
		$res = self::stream( $fh );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return $res;
	}

	/**
	 * INSTREAM: <len:uint32be><bytes>... then a zero-length chunk.
	 *
	 * @param resource $fh Readable handle.
	 * @return array
	 */
	private static function stream( $fh ) {
		$ep = self::endpoint();
		if ( ! $ep ) {
			return array( 'status' => 'error', 'name' => 'clamd unavailable' );
		}
		// Circuit breaker: after 3 consecutive connection failures stop trying for
		// the rest of this request, so a dead daemon never stalls a scan step.
		if ( self::$failures >= 3 ) {
			return array( 'status' => 'error', 'name' => 'clamd unreachable' );
		}
		$sock = self::connect( $ep );
		if ( ! $sock ) {
			++self::$failures;
			return array( 'status' => 'error', 'name' => 'connect failed' );
		}
		self::$failures = 0;
		fwrite( $sock, "zINSTREAM\0" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		while ( ! feof( $fh ) ) {
			$chunk = fread( $fh, self::CHUNK ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			if ( false === @fwrite( $sock, pack( 'N', strlen( $chunk ) ) . $chunk ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
				break; // clamd closed the stream (e.g. size limit) – read its reply below.
			}
		}
		@fwrite( $sock, pack( 'N', 0 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		$reply = self::read_reply( $sock );
		fclose( $sock ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return self::parse( $reply );
	}

	/**
	 * @param string|false $reply "stream: OK" | "stream: Eicar-Signature FOUND" | "... ERROR".
	 * @return array
	 */
	public static function parse( $reply ) {
		if ( false === $reply || '' === $reply ) {
			return array( 'status' => 'error', 'name' => 'no reply' );
		}
		if ( preg_match( '/:\s*(.+?)\s+FOUND$/', $reply, $m ) ) {
			return array( 'status' => 'infected', 'name' => substr( sanitize_text_field( $m[1] ), 0, 120 ) );
		}
		if ( preg_match( '/:\s*OK$/', $reply ) ) {
			return array( 'status' => 'clean', 'name' => '' );
		}
		return array( 'status' => 'error', 'name' => substr( sanitize_text_field( $reply ), 0, 120 ) );
	}

	/**
	 * End-to-end self-test with the harmless EICAR test string.
	 *
	 * @return array { ok: bool, message: string }
	 */
	public static function self_test() {
		$ep = self::endpoint( true );
		if ( ! $ep ) {
			return array(
				'ok'      => false,
				'message' => __( 'No clamd daemon found. Install clamav-daemon (and run freshclam) on the server, or set the socket path.', 'ironveil-security' ),
			);
		}
		$r = self::scan_string( self::eicar() );
		if ( 'infected' === $r['status'] ) {
			/* translators: 1: endpoint 2: version 3: signature name */
			return array( 'ok' => true, 'message' => sprintf( __( 'ClamAV works: %1$s (%2$s) detected the EICAR test file as "%3$s".', 'ironveil-security' ), $ep, (string) self::version(), $r['name'] ) );
		}
		/* translators: 1: endpoint 2: status */
		return array( 'ok' => false, 'message' => sprintf( __( 'clamd at %1$s answered but did not detect the EICAR test file (%2$s). Is the virus database loaded? Run freshclam.', 'ironveil-security' ), $ep, $r['status'] . ( $r['name'] ? ': ' . $r['name'] : '' ) ) );
	}
}
