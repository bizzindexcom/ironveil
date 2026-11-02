<?php
// Security regression tests for 1.3.3 fixes. Run: php tests/security-fixes-test.php
// WordPress functions are stubbed; plugin classes are the real files. Keys are throwaway, made at runtime.
namespace { $GLOBALS["keys"] = array(); foreach ( array( "owner", "other" ) as $n ) { $k = sodium_crypto_sign_keypair(); $GLOBALS["keys"][ $n ] = array( sodium_crypto_sign_secretkey( $k ), sodium_crypto_sign_publickey( $k ) ); } define( "IV_TEST_PK", base64_encode( $GLOBALS["keys"]["owner"][1] ) ); }
namespace { 
define('ABSPATH', __DIR__.'/'); define('IRONVEIL_VERSION','test'); define('MB_IN_BYTES',1048576);
$GLOBALS['opts']=array(); $GLOBALS['log']=array(); $GLOBALS['ht']=array(); $GLOBALS['probes']=array();
class WP_Error { public $c,$m; function __construct($c='',$m=''){$this->c=$c;$this->m=$m;} function get_error_message(){return $this->m;} function get_error_code(){return $this->c;} }
function is_wp_error($x){return $x instanceof WP_Error;}
function __($s){return $s;} function sanitize_file_name($s){return preg_replace('/[^A-Za-z0-9._-]/','',$s);}
function get_option($k,$d=false){return $GLOBALS['opts'][$k]??$d;} function update_option($k,$v){$GLOBALS['opts'][$k]=$v;return true;}
function insert_with_markers($f,$m,$l){$GLOBALS['ht'][]=$l;return true;} function apply_filters($h,$v){return $v;}
function wp_remote_get($u){$s=array_shift($GLOBALS['probes']); return $s===null?new WP_Error('x','loopback blocked'):array('code'=>$s);}
function wp_remote_retrieve_response_code($r){return $r['code'];}
}
namespace IronVeil {
class Log { const NOTICE=1; const WARNING=2; const CRITICAL=3; const INFO=0; static function add($e,$m){$GLOBALS['log'][]=$e;} }
class Signatures { static function flush(){} }
class License { const PUBLIC_KEY=IV_TEST_PK; const DEFAULT_FEED_URL=''; static function flush(){} }
}
namespace {
$P=__DIR__.'/../ironveil-security/includes/';
require $P.'class-ip.php'; require $P.'class-threat-feeds.php'; require $P.'class-signature-feed.php'; require $P.'class-hardening.php';
use IronVeil\{IP,Threat_Feeds,Signature_Feed,Hardening};
$fail=0; function t($name,$ok){global $fail; echo ($ok?"PASS ":"FAIL ")."$name\n"; if(!$ok)$fail++;}

echo "== Threat feed range cap\n";
foreach (array('64.0.0.0/3'=>true,'1.0.0.0/7'=>true,'5.0.0.0/8'=>false,'45.9.148.0/22'=>false,'203.0.113.7'=>false,'::/1'=>true,'2a06:e480::/15'=>true,'2a06:e480::/29'=>false,'2001:db8::1'=>false) as $c=>$want)
  t("too_wide($c) = ".var_export($want,true), Threat_Feeds::too_wide(IP::range($c))===$want);

echo "== Revocations\n";
function feed($sk,$ver,$revoked){ $p=json_encode(array('format'=>1,'version'=>$ver,'expires'=>time()+3600,'revoked_licenses'=>$revoked)); return json_encode(array('payload'=>base64_encode($p),'signature'=>base64_encode(sodium_crypto_sign_detached($p,$GLOBALS["keys"][$sk][0])))); }
$own=$GLOBALS["keys"]["owner"][1]; $oth=$GLOBALS["keys"]["other"][1];
t("owner feed installs revocation", true===Signature_Feed::install(feed('owner',5,array('abcd1234')),$own) && Signature_Feed::state()['revoked']===array('abcd1234'));
t("admin's own feed (other key, higher version, empty list) installs rules", true===Signature_Feed::install(feed('other',9,array()),$oth));
t("... but does NOT clear the author's revocations", Signature_Feed::state()['revoked']===array('abcd1234'));
t("other key cannot add revocations either", true===Signature_Feed::install(feed('other',10,array('zzzz9999')),$oth) && Signature_Feed::state()['revoked']===array('abcd1234'));
t("revocations-only update from author (version 6) applies despite rules feed at v10", true===Signature_Feed::install(feed('owner',6,array('abcd1234','efgh5678')),$own,'',true) && count(Signature_Feed::state()['revoked'])===2 && Signature_Feed::state()['version']===10);
t("revocations-only rollback (v5) refused", is_wp_error(Signature_Feed::install(feed('owner',5,array()),$own,'',true)) && count(Signature_Feed::state()['revoked'])===2);
t("revocations-only from other key refused", is_wp_error(Signature_Feed::install(feed('other',99,array()),$oth,'',true)));
$d=json_decode(feed('owner',50,array()),true); $d['payload']=base64_encode(str_replace('"version":50','"version":51',base64_decode($d['payload']))); 
t("tampered feed (version edited after signing) refused", is_wp_error(Signature_Feed::install(json_encode($d),$own)) && Signature_Feed::state()['version']===10);

echo "== .htaccess checked write\n";
$L=array('Options -Indexes','<FilesMatch "x">','</FilesMatch>','php_flag engine off');
$GLOBALS['ht']=array(); $GLOBALS['probes']=array(200,200);
t("host accepts rules -> full block kept", true===Hardening::insert_rules_checked('f','m',$L,'u') && end($GLOBALS['ht'])===$L);
$GLOBALS['ht']=array(); $GLOBALS['probes']=array(200,500,200);
$r=Hardening::insert_rules_checked('f','m',$L,'u'); $last=end($GLOBALS['ht']);
t("Options rejected (500) -> retried without Options/php_flag, kept", true===$r && $last===array('<FilesMatch "x">','</FilesMatch>'));
$GLOBALS['ht']=array(); $GLOBALS['probes']=array(200,500,500);
$r=Hardening::insert_rules_checked('f','m',$L,'u');
t("still 500 -> block removed, error returned", is_wp_error($r) && end($GLOBALS['ht'])===array());
$GLOBALS['ht']=array(); $GLOBALS['probes']=array(500,500);
t("site already 500 without our rules -> not blamed, rules kept", true===Hardening::insert_rules_checked('f','m',$L,'u') && end($GLOBALS['ht'])===$L);
$GLOBALS['ht']=array(); $GLOBALS['probes']=array();
t("loopback blocked -> rules kept (cannot verify)", true===Hardening::insert_rules_checked('f','m',$L,'u'));
t("first write of a probe run clears old block (baseline)", $GLOBALS['ht'][0]===array());

echo "== Verify\n";
$src=file_get_contents($P.'class-verify.php'); t("edit-theme-plugin-file is gated", false!==strpos($src,"'edit-theme-plugin-file'"));
echo $fail? "\n$fail FAILED\n" : "\nALL PASSED\n"; exit($fail?1:0);
}
