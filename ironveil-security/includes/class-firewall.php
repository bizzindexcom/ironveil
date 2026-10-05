<?php
/**
 * Request firewall. Runs as early as possible and short-circuits malicious
 * requests before WordPress renders anything, which *reduces* server load
 * under attack. A clean request costs: one autoloaded-option lookup (already
 * in memory), a hash lookup on the blocklist and a handful of PCRE calls on
 * the request's own parameters. No extra DB queries, no file I/O.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Firewall {

	/** @var bool */
	private static $booted = false;

	/** @var array|null Pending match waiting for user capability check. */
	private static $deferred = null;

	/**
	 * Entry point (idempotent).
	 */
	public static function boot() {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		if ( defined( 'IRONVEIL_DISABLE_FIREWALL' ) && IRONVEIL_DISABLE_FIREWALL ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI || wp_installing() ) {
			return;
		}
		if ( ! get_option( 'ironveil_db_version' ) ) {
			return; // Not installed yet.
		}
		$mode = Settings::get( 'fw_mode' );
		if ( 'off' === $mode ) {
			return;
		}
		self::run( 'monitor' === $mode );
	}

	/**
	 * @param bool $monitor Log only.
	 */
	private static function run( $monitor ) {
		$ip = IP::client();

		// 1. Allowlist: full bypass.
		$allow = Settings::lines( 'fw_allowlist' );
		if ( $allow && IP::in_ranges( $ip, IP::parse_list( $allow ) ) ) {
			return;
		}
		$is_self = IP::is_self( $ip );

		// 2. Blocklist (zero-query; autoloaded cache).
		if ( ! $is_self ) {
			$block = Blocklist::match( $ip );
			if ( $block ) {
				// Never log every blocked hit: that would turn a flood into DB writes.
				self::deny( 'blocklist', $monitor, false );
			}
		}

		// 3. Country blocking via edge/server-provided header (no lookups).
		$countries = Settings::lines( 'fw_blocked_countries' );
		if ( $countries && ! $is_self ) {
			$cc = '';
			foreach ( array( 'HTTP_CF_IPCOUNTRY', 'GEOIP_COUNTRY_CODE', 'HTTP_X_COUNTRY_CODE' ) as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
					$cc = strtoupper( substr( sanitize_key( wp_unslash( $_SERVER[ $h ] ) ), 0, 2 ) );
					break;
				}
			}
			if ( $cc && in_array( $cc, array_map( 'strtoupper', $countries ), true ) ) {
				self::deny( 'country:' . $cc, $monitor, false );
			}
		}

		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- inspected, never output.
		$path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? basename( (string) wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// 4. XML-RPC fully disabled => refuse before WordPress builds the server.
		if ( 'xmlrpc.php' === $script && 'disable' === Settings::get( 'xmlrpc' ) && ! $is_self ) {
			self::deny( 'xmlrpc_disabled', $monitor, false );
		}

		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ), 0, 1024 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// 5. Optional global rate limit – only with a persistent object cache.
		$limit = (int) Settings::get( 'fw_rate_limit' );
		if ( $limit > 0 && ! $is_self && wp_using_ext_object_cache() ) {
			$key = 'rl_' . md5( $ip ) . '_' . (int) floor( time() / 60 );
			wp_cache_add( $key, 0, 'ironveil', 70 );
			$n = (int) wp_cache_incr( $key, 1, 'ironveil' );
			if ( $n > $limit ) {
				if ( $n === $limit + 1 ) {
					Log::add( 'rate_limited', sprintf( 'Rate limit exceeded (%d req/min)', $limit ), Log::WARNING );
				}
				self::deny( 'rate_limit', $monitor, false, 429 );
			}
		}

		// 6. Fake search-engine bots (DNS verified once per IP, cached).
		if ( Settings::get( 'fw_block_fake_bots' ) && ! $is_self && preg_match( '~\b(googlebot|bingbot|google-inspectiontool|googleother)\b~i', $ua, $bm ) ) {
			if ( ! self::verify_bot( $ip, strtolower( $bm[1] ) ) ) {
				self::hit( 'fake_bot', 'Fake search engine crawler', $ip, $monitor );
			}
		}

		// 7. Signature inspection.
		$match = self::inspect( $path, $ua );
		if ( $match ) {
			if ( self::has_auth_cookie() ) {
				// Could be a privileged user; decide once pluggable functions exist.
				self::$deferred = $match;
				add_action( 'plugins_loaded', array( __CLASS__, 'resolve_deferred' ), -PHP_INT_MAX );
				return;
			}
			self::hit( $match['group'], $match['detail'], $ip, $monitor );
		}
	}

	/**
	 * Inspect request data against enabled rule groups.
	 *
	 * @param string $path Request path.
	 * @param string $ua   User agent.
	 * @return array|null { group, detail }
	 */
	private static function inspect( $path, $ua ) {
		$enabled = (array) Settings::get( 'fw_rules' );
		if ( ! $enabled ) {
			return null;
		}
		$rules      = Waf_Rules::compiled();
		$skip_param = array_flip( array_map( 'strtolower', Settings::lines( 'fw_param_allowlist' ) ) );

		$sources = array(
			'path'   => array( array( 'path', $path ) ),
			'ua'     => '' !== $ua ? array( array( 'user-agent', $ua ) ) : array(),
			'query'  => self::flatten( $_GET ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'body'   => self::flatten( $_POST ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'cookie' => self::flatten( self::filtered_cookies() ),
		);

		foreach ( $enabled as $group ) {
			if ( 'uploads' === $group ) {
				$bad = self::inspect_uploads();
				if ( $bad ) {
					return array(
						'group'  => 'uploads',
						'detail' => 'Blocked upload: ' . $bad,
					);
				}
				continue;
			}
			if ( ! isset( $rules[ $group ] ) ) {
				continue;
			}
			$rule = $rules[ $group ];
			foreach ( $rule['targets'] as $target => $unused ) {
				foreach ( $sources[ $target ] as $pair ) {
					list( $name, $value ) = $pair;
					if ( isset( $skip_param[ strtolower( $name ) ] ) || isset( $rule['skip'][ strtolower( $name ) ] ) ) {
						continue;
					}
					$norm = Waf_Rules::normalize( $value, 'sqli' === $group );
					if ( '' === $norm ) {
						continue;
					}
					$hit = preg_match( $rule['regex'], $norm, $m );
					if ( false === $hit && strlen( $norm ) < 8192 ) {
						// PCRE failure on a short input = deliberate evasion attempt: fail closed.
						$hit = 1;
						$m   = array( 'pcre-error' );
					}
					if ( $hit ) {
						return array(
							'group'  => $group,
							'detail' => sprintf( '%s in %s[%s]: %s', $group, $target, substr( $name, 0, 60 ), substr( $m[0], 0, 80 ) ),
						);
					}
				}
			}
		}
		return null;
	}

	/**
	 * Flatten nested request data into [ top-level name, value ] pairs.
	 * Parameter names (keys) are inspected too, since payloads can hide there.
	 *
	 * @param array $data Data.
	 * @return array[]
	 */
	private static function flatten( $data ) {
		$out   = array();
		$stack = array( array( null, (array) $data ) );
		while ( $stack && count( $out ) < 1000 ) {
			list( $top, $arr ) = array_pop( $stack );
			foreach ( $arr as $k => $v ) {
				$name = null === $top ? (string) $k : $top;
				if ( ! preg_match( '/^[\w\-]{0,64}$/', (string) $k ) || preg_match( '/__proto__|constructor|prototype/i', (string) $k ) ) {
					$out[] = array( $name, (string) $k );
				}
				if ( is_array( $v ) ) {
					$stack[] = array( $name, $v );
				} elseif ( is_scalar( $v ) && '' !== (string) $v ) {
					$v     = (string) $v;
					$out[] = array( $name, strlen( $v ) > 65536 ? substr( $v, 0, 65536 ) : $v );
				}
			}
		}
		return $out;
	}

	/**
	 * Cookies worth inspecting (skip WordPress' own signed cookies).
	 *
	 * @return array
	 */
	private static function filtered_cookies() {
		$out = array();
		foreach ( $_COOKIE as $k => $v ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( preg_match( '/^(wordpress_|wp-settings-|wp_woocommerce_session_|comment_author_|wp-postpass_|ironveil_)/', (string) $k ) ) {
				continue;
			}
			$out[ $k ] = $v;
		}
		return $out;
	}

	/**
	 * Detect dangerous uploads from anonymous/untrusted requests.
	 *
	 * @return string|null Offending filename.
	 */
	private static function inspect_uploads() {
		if ( empty( $_FILES ) ) {
			return null;
		}
		$names = array();
		array_walk_recursive(
			$_FILES,
			static function ( $v, $k ) use ( &$names ) {
				if ( 'name' === $k || 'full_path' === $k ) {
					$names[] = (string) $v;
				}
			}
		);
		foreach ( $names as $n ) {
			if ( preg_match( '~\.(?:php[0-9s]?|phtml|phar|pht|pgif|shtml|htaccess|user\.ini|cgi|pl|asp|aspx|jsp|exe|sh)(?:\.|$)~i', $n ) || false !== strpos( $n, "\0" ) || preg_match( '~(?:\.\.[/\\\\]|^\.ht)~', $n ) ) {
				return substr( preg_replace( '/[^\w.\-]+/', '_', $n ), 0, 100 );
			}
		}
		// Content sniff: PHP open tag inside an "image".
		foreach ( self::tmp_files() as $tmp ) {
			if ( is_uploaded_file( $tmp ) ) {
				$fh   = fopen( $tmp, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
				$head = $fh ? (string) fread( $fh, 8192 ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
				if ( $fh ) {
					fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
				}
				if ( preg_match( '~<\?php|<\?=|<script\s+language\s*=\s*["\']?php~i', $head ) ) {
					return 'embedded PHP code';
				}
			}
		}
		return null;
	}

	/**
	 * @return string[]
	 */
	private static function tmp_files() {
		$out = array();
		array_walk_recursive(
			$_FILES,
			static function ( $v, $k ) use ( &$out ) {
				if ( 'tmp_name' === $k && is_string( $v ) && '' !== $v ) {
					$out[] = $v;
				}
			}
		);
		return array_slice( $out, 0, 20 );
	}

	/**
	 * @return bool
	 */
	private static function has_auth_cookie() {
		foreach ( $_COOKIE as $k => $unused ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( 0 === strpos( (string) $k, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Decide a deferred match once we can validate the auth cookie.
	 * Users with unfiltered_html (admins/editors) may legitimately send HTML/JS;
	 * users who can edit posts may send HTML that core's KSES will sanitise.
	 */
	public static function resolve_deferred() {
		if ( ! self::$deferred ) {
			return;
		}
		$match          = self::$deferred;
		self::$deferred = null;
		$user_id        = (int) wp_validate_auth_cookie( '', 'logged_in' );
		if ( $user_id ) {
			if ( user_can( $user_id, 'unfiltered_html' ) || user_can( $user_id, 'manage_options' ) ) {
				return;
			}
			if ( 'xss' === $match['group'] && user_can( $user_id, 'edit_posts' ) ) {
				return;
			}
		}
		self::hit( $match['group'], $match['detail'], IP::client(), 'monitor' === Settings::get( 'fw_mode' ) );
	}

	/**
	 * Record an attack, auto-block repeat offenders, then deny.
	 *
	 * @param string $group   Rule group.
	 * @param string $detail  Detail.
	 * @param string $ip      IP.
	 * @param bool   $monitor Monitor mode.
	 */
	public static function hit( $group, $detail, $ip, $monitor ) {
		Log::add(
			'waf_' . ( $monitor ? 'monitor' : 'block' ),
			$detail,
			$monitor ? Log::NOTICE : Log::WARNING,
			array(
				'group' => $group,
				'ref'   => self::ref(),
			)
		);

		$threshold = (int) Settings::get( 'fw_autoblock_hits' );
		if ( ! $monitor && $threshold > 0 && ! IP::is_self( $ip ) ) {
			$key = 'ironveil_hits_' . md5( $ip );
			$n   = (int) get_transient( $key ) + 1;
			set_transient( $key, $n, 10 * MINUTE_IN_SECONDS );
			if ( $n >= $threshold ) {
				delete_transient( $key );
				Blocklist::add( $ip, sprintf( 'Auto-blocked after %d attacks (%s)', $n, $group ), 'waf', HOUR_IN_SECONDS * (int) Settings::get( 'fw_autoblock_hours' ) );
				do_action( 'ironveil_ip_autoblocked', $ip, $group );
			}
		}
		self::deny( $group, $monitor, false );
	}

	/**
	 * Send a minimal 403 and stop (unless monitoring).
	 *
	 * @param string $reason  Reason (not shown to visitor).
	 * @param bool   $monitor Monitor mode.
	 * @param bool   $log     Log it.
	 * @param int    $status  HTTP status.
	 */
	public static function deny( $reason, $monitor = false, $log = true, $status = 403 ) {
		if ( $log ) {
			Log::add( 'waf_block', $reason, Log::WARNING, array( 'ref' => self::ref() ) );
		}
		if ( $monitor ) {
			return;
		}
		$ref = self::ref();
		if ( ! headers_sent() ) {
			http_response_code( $status );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-cache, no-store, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			if ( 429 === $status ) {
				header( 'Retry-After: 60' );
			}
		}
		// Static page: nothing from the request is reflected.
		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Access denied</title>'
			. '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:grid;place-items:center;min-height:100vh;margin:0}'
			. 'main{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:32rem}'
			. 'h1{font-size:1.4rem;margin:0 0 .5rem}code{background:#eef;padding:.1rem .35rem;border-radius:4px}</style></head>'
			. '<body><main><h1>Access denied</h1><p>This request was blocked by the site&#8217;s security firewall.</p>'
			. '<p>If you believe this is a mistake, contact the site owner and quote reference <code>' . esc_html( $ref ) . '</code>.</p></main></body></html>';
		exit;
	}

	/**
	 * Per-request incident reference shown to the visitor and stored in the log.
	 *
	 * @return string
	 */
	public static function ref() {
		static $ref = null;
		if ( null === $ref ) {
			$ref = bin2hex( random_bytes( 6 ) );
		}
		return $ref;
	}

	/**
	 * Verify a crawler with reverse + forward-confirmed DNS (cached per IP).
	 *
	 * @param string $ip  IP.
	 * @param string $bot Bot token.
	 * @return bool
	 */
	private static function verify_bot( $ip, $bot ) {
		$key    = 'ironveil_bot_' . md5( $ip );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return '1' === $cached;
		}
		$suffixes = 0 === strpos( $bot, 'bing' ) ? array( '.search.msn.com' ) : array( '.googlebot.com', '.google.com', '.googleusercontent.com' );
		$ok       = false;
		$host     = gethostbyaddr( $ip );
		if ( $host && $host !== $ip ) {
			foreach ( $suffixes as $s ) {
				if ( substr( strtolower( $host ), -strlen( $s ) ) === $s ) {
					$records = false !== strpos( $ip, ':' ) ? (array) @dns_get_record( $host, DNS_AAAA ) : (array) @dns_get_record( $host, DNS_A ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					foreach ( $records as $r ) {
						$addr = isset( $r['ip'] ) ? $r['ip'] : ( isset( $r['ipv6'] ) ? $r['ipv6'] : '' );
						if ( $addr && IP::normalize( $addr ) === $ip ) {
							$ok = true;
							break 2;
						}
					}
				}
			}
		}
		set_transient( $key, $ok ? '1' : '0', DAY_IN_SECONDS );
		return $ok;
	}
}
