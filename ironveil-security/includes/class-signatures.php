<?php
/**
 * Malware signatures and heuristics used by the file scanner.
 *
 * Each set is compiled into ONE regex using PCRE (*MARK) verbs, so a file is
 * scanned in a single pass regardless of how many signatures exist.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Signatures {

	/** Bump to force re-analysis of every file with new signatures. */
	const VERSION = 5;

	const SEV_LOW      = 1;
	const SEV_MEDIUM   = 2;
	const SEV_HIGH     = 3;
	const SEV_CRITICAL = 4;

	/**
	 * id => [ severity, description, regex-fragment ].
	 *
	 * @return array
	 */
	private static function builtin_php() {
		return array(
			'php_eval_decode'     => array( self::SEV_CRITICAL, 'eval() of decoded/obfuscated data', 'eval\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(' ),
			'php_eval_input'      => array( self::SEV_CRITICAL, 'eval()/assert() of request input', '(?:eval|assert)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)' ),
			'php_exec_input'      => array( self::SEV_CRITICAL, 'Command execution from request input', '\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*|base64_decode\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER\s*\[\s*[\'"]HTTP_)' ),
			'php_var_func_input'  => array( self::SEV_CRITICAL, 'Function name taken from request input', '\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*[\'"]?[^\]]{1,40}[\'"]?\s*\]\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE)' ),
			'php_preg_e'          => array( self::SEV_CRITICAL, 'preg_replace with /e (code execution)', 'preg_replace\s*\(\s*[\'"]([^\w\s\'"\\\\]).{1,200}?\1[imsxuADSUX]*e[imsxuADSUX]*[\'"]\s*,' ),
			'php_create_func_in'  => array( self::SEV_CRITICAL, 'create_function with request input', 'create_function\s*\([^;]{0,200}\$_(?:POST|GET|REQUEST|COOKIE)' ),
			'php_shell_marker'    => array( self::SEV_CRITICAL, 'Known web-shell fingerprint', '(?:FilesMan|WSOsetcookie|wso_version|c99shell|c99_sess|r57shell|b374k|IndoXploit|AnonymousFox|0byt3m1n1|Alfa[\s_-]?Shell|ALFA_DATA|MARIJUANA|Priv8\s*Uploader|WebShellOrb|mini\s*shell|Hacked\s+By|gel4y|bypass\s+shell|uname\s*\(\s*\)\s*\.\s*[\'"]\s*<br|php_uname\s*\(\s*\)\s*;\s*\?>\s*<br)' ),
			'php_uploader'        => array( self::SEV_HIGH, 'Arbitrary file uploader', 'move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*(?:[\'"][^\'"]*[\'"]\s*\.\s*)?\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]name[\'"]\s*\]' ),
			'php_write_input'     => array( self::SEV_HIGH, 'Writes request input to a file', '\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:POST|GET|REQUEST|COOKIE)\s*\[' ),
			'php_include_image'   => array( self::SEV_CRITICAL, 'Includes code hidden in an image/text file', '(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"]{1,200}\.(?:ico|png|jpe?g|gif|bmp|txt|log|svg)[\'"]' ),
			'php_include_input'   => array( self::SEV_CRITICAL, 'Includes a file named by request input', '(?:include|require)(?:_once)?\s*\(?\s*\$_(?:POST|GET|REQUEST|COOKIE)' ),
			'php_globals_obf'     => array( self::SEV_HIGH, 'Obfuscated call through $GLOBALS array', '\$GLOBALS\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\[\s*\d+\s*\]\s*\(\s*\$GLOBALS' ),
			'php_hex_chain'       => array( self::SEV_HIGH, 'Long hex/octal-escaped string (obfuscation)', '(?:\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){60,}' ),
			'php_decode_chain'    => array( self::SEV_MEDIUM, 'Nested decoding of an embedded blob', '(?:gzinflate|gzuncompress|str_rot13|strrev)\s*\(\s*(?:base64_decode|str_rot13|gzinflate)\s*\(' ),
			'php_chr_chain'       => array( self::SEV_MEDIUM, 'Code assembled from chr() calls', '(?:chr\s*\(\s*\d{2,3}\s*\)\s*\.\s*){12,}' ),
			'php_ini_danger'      => array( self::SEV_HIGH, 'Weakens PHP security settings', 'ini_set\s*\(\s*[\'"](?:allow_url_include|disable_functions|open_basedir|safe_mode)[\'"]' ),
			'php_auth_backdoor'   => array( self::SEV_CRITICAL, 'Login backdoor (auth cookie from request parameter)', 'isset\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\)[^;{]{0,80}\{?[^}]{0,300}?\b(?:wp_set_auth_cookie|wp_create_user|wp_insert_user)\s*\(' ),
			'php_hidden_admin'    => array( self::SEV_HIGH, 'Hides users from the admin user list', 'pre_user_query[^;]{0,300}user_login\s*!=|views_users[^;]{0,300}unset' ),
			'php_long_b64_eval'   => array( self::SEV_HIGH, 'Huge encoded blob next to a decoder', '(?:base64_decode|gzinflate|str_rot13)\s*\(\s*[\'"][A-Za-z0-9+/=]{2000,}[\'"]' ),
			'php_remote_payload'  => array( self::SEV_HIGH, 'Downloads and runs remote code', '(?:eval|assert|include|require)(?:_once)?\s*\(\s*(?:@\s*)?(?:file_get_contents|wp_remote_retrieve_body|curl_exec)\s*\(' ),
			'php_spam_injector'   => array( self::SEV_HIGH, 'SEO spam / cloaking for search bots', '(?:HTTP_USER_AGENT|HTTP_REFERER)[^;]{0,80}(?:googlebot|bingbot|yahoo|baidu)[^;]{0,300}(?:viagra|cialis|casino|porn|payday|replica|pharma)' ),
			'js_in_php_inject'    => array( self::SEV_HIGH, 'Injected obfuscated JavaScript', 'document\.write\s*\(\s*unescape\s*\(|String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){30,}' ),
		);
	}

	/**
	 * JavaScript signatures.
	 *
	 * @return array
	 */
	private static function builtin_js() {
		return array(
			'js_charcode_eval' => array( self::SEV_HIGH, 'Obfuscated JavaScript (eval of char codes)', 'eval\s*\(\s*String\.fromCharCode\s*\(' ),
			'js_unescape_doc'  => array( self::SEV_HIGH, 'document.write(unescape()) injection', 'document\.write\s*\(\s*unescape\s*\(' ),
			'js_long_charcode' => array( self::SEV_MEDIUM, 'Very long String.fromCharCode payload', 'String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){60,}' ),
			'js_known_malware' => array( self::SEV_CRITICAL, 'Known WordPress JS malware campaign', '(?:balantfromsun|lowerbeforwarden|trackstatisticsss|dontkinhooot|belowfirstinaline|donaldjtrumpprez|stringengines\.com|ws\.stivenfernando|dns\.createrelativeposts|js\.greenstatisticsgo|developsincelock|drakefollow\.com|lovegreenpencils|chaintiger\.xyz|temp\.xmlstudy)' ),
			'js_atob_eval'     => array( self::SEV_HIGH, 'eval(atob()) payload', 'eval\s*\(\s*atob\s*\(' ),
		);
	}

	/**
	 * .htaccess / .user.ini signatures.
	 *
	 * @return array
	 */
	private static function builtin_config() {
		return array(
			'cfg_prepend'       => array( self::SEV_HIGH, 'auto_prepend/append_file injection', '(?:auto_prepend_file|auto_append_file)\s*=?\s*["\']?[^\s"\']+' ),
			'cfg_img_as_php'    => array( self::SEV_CRITICAL, 'Images executed as PHP', '(?:AddHandler|AddType|SetHandler)\s+[^\n]*(?:x-httpd-php|php\d?-script|application/x-httpd)[^\n]*\.(?:jpe?g|png|gif|ico|txt|bmp)' ),
			'cfg_search_redir'  => array( self::SEV_HIGH, 'Search-engine referrer redirect (SEO spam)', 'RewriteCond\s+%\{HTTP_(?:REFERER|USER_AGENT)\}[^\n]*(?:google|bing|yahoo|baidu|yandex)[\s\S]{0,300}?RewriteRule\s+[^\n]*https?://' ),
		);
	}

	/**
	 * Suspicious filenames (basename, lowercase).
	 *
	 * @return string[]
	 */
	private static function builtin_filenames() {
		return array( 'wso.php', 'c99.php', 'r57.php', 'b374k.php', 'alfa.php', 'alfashell.php', 'shell.php', 'cmd.php', 'up.php', 'uploader.php', 'radio.php', 'wp-vcd.php', 'wp-tmp.php', 'class.theme-modules.php', 'adminer.php', 'mini.php', 'leafmailer.php', 'priv8.php', 'wp-crom.php', 'wp-2019.php', 'xleet.php', 'marijuana.php', 'fox.php', 'lf.php', 'x.php', 'accesson.php', 'wp-conflg.php', 'wp-l0gin.php', 'wp-atom.php', 'wp-feed.php', 'wp-p.php', 'byp.php', 'sx.php', 'wp-admin-ajax.php', 'wp-signin.php' );

	}

	/** @var array|null Merged rule sets (built-in + feed + custom). */
	private static $merged = null;

	/**
	 * Merge built-in rules with the signed feed and the admin's custom rules.
	 *
	 * @return array
	 */
	private static function merged() {
		if ( null === self::$merged ) {
			$feed   = Signature_Feed::state();
			$custom = Signature_Feed::parse_custom( (string) Settings::get( 'custom_signatures' ) );
			self::$merged = array(
				'php'       => self::builtin_php(),
				'js'        => self::builtin_js(),
				'config'    => self::builtin_config(),
				'filenames' => self::builtin_filenames(),
			);
			$pro = License::is_pro();
			foreach ( Signature_Feed::SETS as $set ) {
				if ( $pro && ! empty( $feed['rules'][ $set ] ) && is_array( $feed['rules'][ $set ] ) ) {
					self::$merged[ $set ] += $feed['rules'][ $set ];
				}
				self::$merged[ $set ] += $custom['rules'][ $set ];
			}
			if ( $pro && ! empty( $feed['names'] ) ) {
				self::$merged['filenames'] = array_values( array_unique( array_merge( self::$merged['filenames'], (array) $feed['names'] ) ) );
			}
		}
		return self::$merged;
	}

	/** @return array */
	public static function php() {
		return self::merged()['php'];
	}

	/** @return array */
	public static function js() {
		return self::merged()['js'];
	}

	/** @return array */
	public static function config() {
		return self::merged()['config'];
	}

	/** @return string[] */
	public static function filenames() {
		return self::merged()['filenames'];
	}

	/**
	 * Effective signature version: changes whenever built-in, feed or custom
	 * rules change, which makes the incremental scanner re-check every file.
	 *
	 * @return int
	 */
	public static function version() {
		if ( null === self::$ver ) {
			$feed      = Signature_Feed::state();
			self::$ver = (int) ( crc32( self::VERSION . '|' . ( License::is_pro() ? (int) $feed['version'] : 0 ) . '|' . md5( (string) Settings::get( 'custom_signatures' ) ) . '|' . ( ClamAV::available() ? 'clam' : '' ) ) & 0x7fffffff );
		}
		return self::$ver;
	}

	/** @var int|null */
	private static $ver = null;

	/** Reset caches after an update. */
	public static function flush() {
		self::$merged = null;
		self::$ver    = null;
		self::$compiled_cache = array();
	}

	/** @var array */
	private static $compiled_cache = array();

	/**
	 * Rule counts per source (admin display).
	 *
	 * @return array
	 */
	public static function counts() {
		$m   = self::merged();
		$out = array( 'builtin' => 0, 'feed' => 0, 'custom' => 0 );
		foreach ( Signature_Feed::SETS as $set ) {
			foreach ( array_keys( $m[ $set ] ) as $id ) {
				$src         = 0 === strpos( $id, 'feed_' ) ? 'feed' : ( 0 === strpos( $id, 'custom_' ) ? 'custom' : 'builtin' );
				$out[ $src ] += 1;
			}
		}
		return $out;
	}

	/**
	 * Compile a signature set into one (*MARK) regex.
	 *
	 * @param string $set php|js|config.
	 * @return string
	 */
	public static function compiled( $set ) {
		if ( ! isset( self::$compiled_cache[ $set ] ) ) {
			$parts = array();
			foreach ( self::$set() as $id => $def ) {
				$parts[] = '(?:' . str_replace( '~', '\\~', $def[2] ) . ')(*MARK:' . $id . ')';
			}
			$re = '~' . implode( '|', $parts ) . '~iS';
			// Defensive: if a merged rule ever breaks compilation, fall back to built-ins only.
			if ( false === @preg_match( $re, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$parts   = array();
				$builtin = 'builtin_' . $set;
				foreach ( self::$builtin() as $id => $def ) {
					$parts[] = '(?:' . str_replace( '~', '\\~', $def[2] ) . ')(*MARK:' . $id . ')';
				}
				$re = '~' . implode( '|', $parts ) . '~iS';
			}
			self::$compiled_cache[ $set ] = $re;
		}
		return self::$compiled_cache[ $set ];
	}

	/**
	 * Scan content; returns the most severe match.
	 *
	 * @param string $content Content.
	 * @param string $set     Set.
	 * @return array|null { id, severity, description, snippet }
	 */
	public static function scan( $content, $set ) {
		$defs  = self::$set();
		$best  = null;
		$regex = self::compiled( $set );
		$off   = 0;
		$len   = strlen( $content );
		// Iterate matches (bounded) to find the most severe one.
		for ( $i = 0; $i < 25 && $off < $len; $i++ ) {
			if ( ! preg_match( $regex, $content, $m, PREG_OFFSET_CAPTURE, $off ) ) {
				break;
			}
			$id = isset( $m['MARK'] ) ? ( is_array( $m['MARK'] ) ? $m['MARK'][0] : $m['MARK'] ) : null;
			if ( $id && isset( $defs[ $id ] ) && ( ! $best || $defs[ $id ][0] > $best['severity'] ) ) {
				$best = array(
					'id'          => $id,
					'severity'    => $defs[ $id ][0],
					'description' => $defs[ $id ][1],
					'snippet'     => substr( $m[0][0], 0, 160 ),
				);
				if ( self::SEV_CRITICAL === $best['severity'] ) {
					break;
				}
			}
			$off = $m[0][1] + max( 1, strlen( $m[0][0] ) );
		}
		return $best;
	}
}
