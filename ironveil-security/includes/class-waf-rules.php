<?php
/**
 * Web application firewall signatures.
 *
 * Rules are intentionally high-confidence (few false positives) and are
 * combined into one alternation per group so each inspected value costs a
 * single PCRE call per group. Inputs are normalised (multi-pass URL decode,
 * entity decode, SQL comment stripping, lowercase) before matching.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Waf_Rules {

	/**
	 * Group => [ targets, patterns[] ]. Targets: path, query, body, cookie, ua.
	 *
	 * @return array
	 */
	public static function groups() {
		return array(
			'sqli'       => array(
				'targets'  => array( 'query', 'body', 'cookie', 'ua' ),
				'patterns' => array(
					'\bunion\b[\s(]+(?:all\s+|distinct\s+)?[\s(]*select\b',
					'\bselect\b.{1,200}?\bfrom\b.{0,80}?\b(?:information_schema|mysql\.user|pg_catalog|sqlite_master|sys\.objects)\b',
					'\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)',
					'\bbenchmark\s*\(\s*\d{3,}\s*,',
					'\bwaitfor\s+delay\s+[\'"]',
					'\bload_file\s*\(',
					'\binto\s+(?:out|dump)file\s+[\'"]',
					'(?:[\'"`)]|\d)\s*(?:or|and|\|\||&&)\s+[\'"`(]?\s*(\w+)\s*[\'"`)]?\s*=\s*[\'"`(]?\s*\1\b[\'"`)]?\s*(?:--|#|;|$)',

					'[\'"`)]\s*(?:or|and)\s+\d+\s*(?:=|<|>)\s*\d+\s*(?:--|#|$)',
					'\b(?:extractvalue|updatexml)\s*\(\s*\d',
					';\s*(?:drop|truncate|alter)\s+table\b',
					'\bexec(?:ute)?\s+(?:xp_cmdshell|sp_executesql)\b',
					'\bgroup_concat\s*\(.{0,80}?\b(?:user_pass|user_login|password|table_name|column_name)\b',
					'\b(?:user_pass|table_name|column_name)\b.{0,40}?\bfrom\b.{0,40}?\b(?:\w+_users|information_schema)\b',
					'@@(?:version|datadir|hostname)\b',
					'\bchar\s*\(\s*\d{2,3}\s*(?:,\s*\d{2,3}\s*){3,}\)',
					'\b0x[0-9a-f]{16,}\b.{0,20}\b(?:into|from|union)\b',
				),
			),
			'xss'        => array(
				'targets'  => array( 'query', 'body' ),
				'patterns' => array(
					'<\s*script[\s>/]',
					'<\s*/\s*script\s*>',
					'(?:^|[\s"\'`=(<>])(?:java|vb)script\s*:',
					'<[a-z][^>]{0,200}?[\s/"\'](?:on(?:error|load|mouse\w+|focus\w*|blur|click|dblclick|key\w+|toggle|animation\w+|transition\w+|pointer\w+|begin|end|message|pageshow|hashchange|input|change|submit|wheel|copy|paste|drag\w*|drop|resize|scroll|unload|beforeunload|auxclick|contextmenu|touch\w+))\s*=',
					'<\s*(?:iframe|frame|frameset|object|embed|applet|base|meta|link|svg|math|form|isindex)[\s/>]',
					'\bdocument\s*\.\s*(?:cookie|domain|write\s*\()',
					'\b(?:srcdoc|formaction)\s*=',
					'\bexpression\s*\(',
					'data\s*:\s*text/html',
					'\{\{\s*constructor\s*\.\s*constructor',
				),
			),
			'traversal'  => array(
				'targets'  => array( 'path', 'query', 'body', 'cookie' ),
				'patterns' => array(
					'(?:\.\.[/\\\\]){2,}',
					'(?:^|[/\\\\])\.\.[/\\\\].{0,80}?(?:wp-config|passwd|shadow|\.htaccess|\.env|win\.ini|boot\.ini|php\.ini)',
					'(?:etc/(?:passwd|shadow|group|hosts)|proc/self/(?:environ|cmdline|fd)|windows[/\\\\]win\.ini|boot\.ini)',
					'\b(?:php|zip|phar|expect|glob|data|file|compress\.zlib|ogg|rar|ssh2)://',
					'(?:^|[/\\\\])wp-config\.php',
				),
			),
			'rce'        => array(
				'targets'  => array( 'query', 'body', 'cookie', 'ua' ),
				'skip'     => array( 'comment' ), // Code snippets in blog comments are escaped by core, not executed.
				'patterns' => array(
					'<\?(?:php|=)',
					'\b(?:passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\(',
					'\b(?:system|exec|assert|eval)\s*\(\s*(?:\$_|base64_decode|gzinflate|str_rot13|[\'"]\s*(?:id|whoami|uname|cat|ls|wget|curl)\b)',
					'\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*\$_',
					'\$\{\s*(?:jndi|env|sys|java|lower|upper|::-)\s*:',
					'[;|`&]\s*(?:wget|curl|nc|ncat|netcat|bash|sh|python\d?|perl|php)\s+(?:-[a-z]+\s+)*(?:https?://|/(?:tmp|dev)/|-e\s)',
					'\$\(\s*(?:wget|curl|id|whoami|uname|cat)\b',
					'`\s*(?:id|whoami|uname\s+-a|cat\s+/etc)\s*`',
					'\bcall_user_func(?:_array)?\s*\(\s*[\'"]?(?:system|exec|passthru|assert)',
					'\{\{.*?(?:_self\.env|registerundefinedfiltercallback|\[\s*[\'"]__class__)',
					'(?:^|[\[.])__proto__(?:$|[\[.=\]])',
					// Remote file inclusion: a URL ending in "?" so the appended ".php" is ignored.
					'^(?:https?|ftps?)://[^\s?#]+\.(?:txt|gif|jpe?g|png|php)\?{1,2}$',
				),
			),
			'ssrf'       => array(
				'targets'  => array( 'query', 'body', 'cookie' ),
				'patterns' => array(
					// Cloud metadata services (credential theft through server-side requests).
					'(?:https?|ftp|gopher|dict|ldap|tftp)://(?:[^/\s@]*@)?\[?(?:169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|instance-data(?:\.ec2\.internal)?)(?:[\]:/?#\s]|$)',
					// Protocol smuggling schemes used to talk to internal services.
					'\b(?:gopher|dict|ldap|tftp|jar|netdoc)://',
				),
			),
			// Evaluated together with "ssrf", except on sites that themselves run on a loopback host.
			'ssrf_local' => array(
				'targets'  => array( 'query', 'body', 'cookie' ),
				'patterns' => array(
					'(?:https?)://(?:[^/\s@]*@)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|0x7f[0-9a-f.x]*|2130706433|0177\.0*\.0*\.0*1|\[(?:0*:)+0*1\]|\[::\]|localhost)(?::\d{1,5})?(?:[/?#]|$)',
				),
			),

			'xxe'        => array(
				'targets'  => array( 'query', 'body', 'raw' ),
				'patterns' => array(
					'<!ENTITY\s+%?\s*[\w.:-]+\s+(?:SYSTEM|PUBLIC)\b',
					'<!DOCTYPE[^>\[]{0,300}\[\s*<!(?:ENTITY|ELEMENT)',
					'<xi:include\b[^>]{0,200}\bhref\s*=',
				),
			),
			'crlf'       => array(
				'targets'  => array( 'path', 'query', 'cookie' ),
				'raw'      => true, // Keep CR/LF: normalisation would turn them into spaces.
				'patterns' => array(
					'[\r\n]\s*(?:set-cookie|location|content-(?:type|length|disposition)|refresh|x-[\w-]+|access-control-[\w-]+|link)\s*:',
					'[\r\n]\s*<(?:html|script|body)',
					'%0[ad]',
				),
			),

			'objinj'     => array(
				'targets'  => array( 'query', 'body', 'cookie' ),
				'patterns' => array(
					'(?:^|[;{\s(])o:\+?\d+:"[a-z_\x7f-\xff][a-z0-9_\x7f-\xff\\\\]*":\d+:\{',
					'(?:^|[;{\s(])c:\+?\d+:"[a-z_\x7f-\xff][a-z0-9_\x7f-\xff\\\\]*":\d+:\{',
				),
			),
			'probes'     => array(
				'targets'  => array( 'path' ),
				'patterns' => array(
					'/\.(?:env|git|svn|hg|bzr|ds_store|aws|ssh|docker|npmrc|htpasswd)(?:/|$|\.)',
					'/wp-config\.(?:php)?(?:[~#]|\.(?:bak|old|orig|save|swp|txt|zip|tar|gz|1|dist|backup))$',
					'\.(?:sql|sqlite|bak|old|swp|tar|tgz|tar\.gz|7z|rar)$',
					'/(?:phpmyadmin|pma|myadmin|adminer|phpinfo|info|test|shell|c99|r57|wso|b374k|alfa|up|uploader|cmd|x|xx|1|leaf|mailer)\.php$',
					'/vendor/phpunit/|/eval-stdin\.php',
					'/(?:cgi-bin|boaform|hnap1|goform|actuator|solr|jmx-console|manager/html|console|owa|autodiscover|druid|telescope|_ignition|\.well-known/acme-challenge/\.\.)(?:/|$)',
					'/wp-content/(?:plugins|themes|uploads)/.{0,200}\.(?:php[0-9]?|phtml|phar|pht|inc)/?.{0,40}\.(?:php|html?)$',
					'/(?:xmlrpc|wp-login)\.php/.+',
				),
			),
			'scanner_ua' => array(
				'targets'  => array( 'ua' ),
				'patterns' => array(
					'\b(?:sqlmap|nikto|acunetix|nessus|openvas|masscan|zgrab|nmap\s+scripting|nuclei|havij|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|w3af|netsparker|appscan|arachni|skipfish|jaeles|commix|xsstrike|fimap|whatweb|wpscan|joomscan|zmeu|morfeus|muieblackcat|jorgee|blackwidow|brutus|hydra|medusa|webshag|paros|zap/|burpcollaborator|interact\.sh|oast\.)\b',
					'^\(\)\s*\{',
				),
			),
		);
	}

	/**
	 * Compiled regex per group (memoised).
	 *
	 * @return array group => [ regex, targets ]
	 */
	public static function compiled() {
		static $compiled = null;
		if ( null === $compiled ) {
			$compiled = array();
			foreach ( self::groups() as $group => $def ) {
				// Named-ish capture reuse (\1) needs each alternative isolated; wrap with (?| ... ) branch reset.
				$compiled[ $group ] = array(
					'regex'   => '~(?|' . implode( '|', array_map( array( __CLASS__, 'wrap' ), $def['patterns'] ) ) . ')~isS',
					'targets' => array_flip( $def['targets'] ),
					'skip'    => isset( $def['skip'] ) ? array_flip( $def['skip'] ) : array(),
					'raw'     => ! empty( $def['raw'] ),
				);
			}
		}
		return $compiled;
	}

	/**
	 * @param string $p Pattern.
	 * @return string
	 */
	private static function wrap( $p ) {
		return '(?:' . str_replace( '~', '\\~', $p ) . ')';
	}

	/**
	 * Normalise an input value for matching (defeats common encodings).
	 *
	 * @param string $v        Raw value.
	 * @param bool   $sql      Also strip SQL comments.
	 * @param bool   $keep_ws  Keep CR/LF (header-injection rules need them).
	 * @return string
	 */
	public static function normalize( $v, $sql = false, $keep_ws = false ) {
		$v = (string) $v;
		for ( $i = 0; $i < 3 && false !== strpos( $v, '%' ); $i++ ) {
			$d = rawurldecode( $v );
			if ( $d === $v ) {
				break;
			}
			$v = $d;
		}
		if ( false !== strpos( $v, '&' ) ) {
			$v = html_entity_decode( $v, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		}
		if ( false !== strpos( $v, '\\u' ) || false !== strpos( $v, '\\x' ) ) {
			$v = preg_replace_callback(
				'~\\\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))~',
				static function ( $m ) {
					$code = hexdec( '' !== $m[1] ? $m[1] : $m[2] );
					return $code < 128 ? chr( $code ) : $m[0];
				},
				$v
			);
		}
		if ( $keep_ws ) {
			return str_replace( "\0", '', $v );
		}
		$v = str_replace( array( "\0", "\t", "\r", "\n", "\x0b", "\x0c" ), array( '', ' ', ' ', ' ', ' ', ' ' ), $v );

		if ( $sql ) {
			$v = preg_replace( '~/\*!?\d*|\*/~', ' ', $v ); // MySQL comment / version-comment obfuscation.
		}
		return $v;
	}
}
