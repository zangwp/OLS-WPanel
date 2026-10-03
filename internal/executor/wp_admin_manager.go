package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const wpAdminManagerPHPSource = `
$ols_wpanel_token=getenv('OLS_WPANEL_RUNNER_TOKEN');$ols_wpanel_sent=false;
$ols_wpanel_send=function($ok,$data=[],$code='')use(&$ols_wpanel_sent,$ols_wpanel_token){if($ols_wpanel_sent)return;$ols_wpanel_sent=true;file_put_contents('php://fd/3',json_encode(['token'=>$ols_wpanel_token,'ok'=>$ok,'data'=>$data,'error_code'=>$code],JSON_UNESCAPED_SLASHES));};
register_shutdown_function(function()use(&$ols_wpanel_sent,$ols_wpanel_send){if(!$ols_wpanel_sent){$e=error_get_last();$ols_wpanel_send(false,[],$e?'fatal_error':'no_result');}});
$ols_wpanel_raw=stream_get_contents(STDIN,65537);$ols_wpanel_input=json_decode($ols_wpanel_raw,true);
if(PHP_SAPI!=='cli'||!preg_match('/^[0-9a-f]{32}$/',$ols_wpanel_token)||strlen($ols_wpanel_raw)>65536||!is_array($ols_wpanel_input)){$ols_wpanel_send(false,[],'invalid_input');exit(2);}
$ols_wpanel_root=$ols_wpanel_input['root']??'';$ols_wpanel_action=$ols_wpanel_input['action']??'';
if(!is_string($ols_wpanel_root)||!is_dir($ols_wpanel_root)||realpath($ols_wpanel_root)!==rtrim($ols_wpanel_root,'/')){$ols_wpanel_send(false,[],'invalid_root');exit(2);}
chdir($ols_wpanel_root);ob_start();if(!defined('WP_USE_THEMES'))define('WP_USE_THEMES',false);if(!defined('WP_HTTP_BLOCK_EXTERNAL'))define('WP_HTTP_BLOCK_EXTERNAL',true);require $ols_wpanel_root.'/wp-load.php';ob_end_clean();
global $wpdb;
if(is_multisite()){$ols_wpanel_send(false,[],'multisite_unsupported');exit(1);}
$ols_wpanel_expected_db=$ols_wpanel_input['db_name']??'';$ols_wpanel_expected_prefix=$ols_wpanel_input['table_prefix']??'';
if(!is_string($ols_wpanel_expected_db)||!is_string($ols_wpanel_expected_prefix)||DB_NAME!==$ols_wpanel_expected_db||$wpdb->prefix!==$ols_wpanel_expected_prefix){$ols_wpanel_send(false,[],'database_mismatch');exit(1);}
if($ols_wpanel_action==='list'){
  $ols_wpanel_users=get_users(['role'=>'administrator','orderby'=>'ID','order'=>'ASC']);$ols_wpanel_items=[];
  foreach($ols_wpanel_users as $ols_wpanel_user){$ols_wpanel_items[]=['id'=>(int)$ols_wpanel_user->ID,'login'=>$ols_wpanel_user->user_login,'email'=>$ols_wpanel_user->user_email,'display_name'=>$ols_wpanel_user->display_name,'nicename'=>$ols_wpanel_user->user_nicename];}
  $ols_wpanel_send(true,['administrators'=>$ols_wpanel_items,'site_admin_email'=>(string)get_option('admin_email')]);exit;
}
if($ols_wpanel_action!=='preflight'&&$ols_wpanel_action!=='update'){$ols_wpanel_send(false,[],'invalid_action');exit(2);}
$ols_wpanel_id=(int)($ols_wpanel_input['user_id']??0);$ols_wpanel_user=get_userdata($ols_wpanel_id);
if(!$ols_wpanel_user||!in_array('administrator',(array)$ols_wpanel_user->roles,true)){$ols_wpanel_send(false,[],'administrator_not_found');exit(1);}
$ols_wpanel_old_login=$ols_wpanel_user->user_login;$ols_wpanel_new_login=$ols_wpanel_input['login']??$ols_wpanel_old_login;
if(!is_string($ols_wpanel_new_login)||$ols_wpanel_new_login===''||mb_strlen($ols_wpanel_new_login)>60){$ols_wpanel_send(false,[],'invalid_login');exit(1);}
$ols_wpanel_sanitized=trim(apply_filters('pre_user_login',sanitize_user($ols_wpanel_new_login,true)));if($ols_wpanel_sanitized!==$ols_wpanel_new_login){$ols_wpanel_send(false,[],'invalid_login');exit(1);}
$ols_wpanel_illegal=(array)apply_filters('illegal_user_logins',[]);if(in_array(strtolower($ols_wpanel_new_login),array_map('strtolower',$ols_wpanel_illegal),true)){$ols_wpanel_send(false,[],'invalid_login');exit(1);}
$ols_wpanel_existing=username_exists($ols_wpanel_new_login);if($ols_wpanel_existing&&((int)$ols_wpanel_existing!==$ols_wpanel_id)){$ols_wpanel_send(false,[],'login_exists');exit(1);}
$ols_wpanel_email=$ols_wpanel_input['email']??$ols_wpanel_user->user_email;if(!is_string($ols_wpanel_email)||!is_email($ols_wpanel_email)){$ols_wpanel_send(false,[],'invalid_email');exit(1);}
$ols_wpanel_existing=email_exists($ols_wpanel_email);if($ols_wpanel_existing&&((int)$ols_wpanel_existing!==$ols_wpanel_id)){$ols_wpanel_send(false,[],'email_exists');exit(1);}
$ols_wpanel_display=$ols_wpanel_input['display_name']??$ols_wpanel_user->display_name;if(!is_string($ols_wpanel_display)||trim($ols_wpanel_display)===''||mb_strlen($ols_wpanel_display)>250){$ols_wpanel_send(false,[],'invalid_display_name');exit(1);}
$ols_wpanel_password=$ols_wpanel_input['password']??'';if(!is_string($ols_wpanel_password)||($ols_wpanel_password!==''&&strlen($ols_wpanel_password)<8)||strlen($ols_wpanel_password)>4096){$ols_wpanel_send(false,[],'invalid_password');exit(1);}
$ols_wpanel_sync_nicename=!empty($ols_wpanel_input['sync_nicename']);$ols_wpanel_sync_admin_email=!empty($ols_wpanel_input['sync_admin_email']);$ols_wpanel_destroy_sessions=!empty($ols_wpanel_input['destroy_sessions']);
$ols_wpanel_transactional_tables=[$wpdb->users,$wpdb->usermeta,$wpdb->options];foreach($ols_wpanel_transactional_tables as $ols_wpanel_table){$ols_wpanel_engine=$wpdb->get_var($wpdb->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',DB_NAME,$ols_wpanel_table));if(!is_string($ols_wpanel_engine)||strtoupper($ols_wpanel_engine)!=='INNODB'){$ols_wpanel_send(false,[],'non_transactional_engine');exit(1);}}
if($ols_wpanel_sync_nicename&&sanitize_title($ols_wpanel_new_login)===''){$ols_wpanel_send(false,[],'invalid_login');exit(1);}
if($ols_wpanel_action==='preflight'){$ols_wpanel_send(true,['validated'=>true]);exit;}
add_filter('send_password_change_email','__return_false',PHP_INT_MAX);add_filter('send_email_change_email','__return_false',PHP_INT_MAX);
$ols_wpanel_transaction=$wpdb->query('START TRANSACTION');if($ols_wpanel_transaction===false){$ols_wpanel_send(false,[],'transaction_failed');exit(1);}
$ols_wpanel_fail=function($code)use($wpdb,$ols_wpanel_send,$ols_wpanel_id,$ols_wpanel_old_login,$ols_wpanel_new_login){$wpdb->query('ROLLBACK');clean_user_cache($ols_wpanel_id);wp_cache_delete($ols_wpanel_old_login,'userlogins');wp_cache_delete($ols_wpanel_new_login,'userlogins');$ols_wpanel_send(false,[],$code);exit(1);};
$ols_wpanel_conflict=$wpdb->get_var($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE user_login=%s AND ID<>%d LIMIT 1 FOR UPDATE",$ols_wpanel_new_login,$ols_wpanel_id));if($ols_wpanel_conflict)$ols_wpanel_fail('login_exists');
$ols_wpanel_update=['ID'=>$ols_wpanel_id,'user_email'=>$ols_wpanel_email,'display_name'=>trim($ols_wpanel_display)];
if($ols_wpanel_password!=='')$ols_wpanel_update['user_pass']=$ols_wpanel_password;
if($ols_wpanel_sync_nicename){$ols_wpanel_update['user_nicename']=sanitize_title($ols_wpanel_new_login);$ols_wpanel_update['nickname']=$ols_wpanel_new_login;}
$ols_wpanel_result=wp_update_user($ols_wpanel_update);if(is_wp_error($ols_wpanel_result))$ols_wpanel_fail('user_update_failed');
if($ols_wpanel_new_login!==$ols_wpanel_old_login){$ols_wpanel_changed=$wpdb->update($wpdb->users,['user_login'=>$ols_wpanel_new_login],['ID'=>$ols_wpanel_id],['%s'],['%d']);if($ols_wpanel_changed===false)$ols_wpanel_fail('login_update_failed');}
if($ols_wpanel_sync_admin_email){update_option('admin_email',$ols_wpanel_email);delete_option('new_admin_email');}
if($ols_wpanel_destroy_sessions||$ols_wpanel_password!==''||$ols_wpanel_new_login!==$ols_wpanel_old_login){WP_Session_Tokens::get_instance($ols_wpanel_id)->destroy_all();}
clean_user_cache($ols_wpanel_id);wp_cache_delete($ols_wpanel_old_login,'userlogins');wp_cache_delete($ols_wpanel_new_login,'userlogins');
$ols_wpanel_updated=get_userdata($ols_wpanel_id);if(!$ols_wpanel_updated||$ols_wpanel_updated->user_login!==$ols_wpanel_new_login||$ols_wpanel_updated->user_email!==$ols_wpanel_email)$ols_wpanel_fail('verification_failed');
if($ols_wpanel_password!==''&&!wp_check_password($ols_wpanel_password,$ols_wpanel_updated->user_pass,$ols_wpanel_id))$ols_wpanel_fail('password_verification_failed');
if($wpdb->query('COMMIT')===false)$ols_wpanel_fail('commit_failed');
$ols_wpanel_send(true,['administrator'=>['id'=>(int)$ols_wpanel_updated->ID,'login'=>$ols_wpanel_updated->user_login,'email'=>$ols_wpanel_updated->user_email,'display_name'=>$ols_wpanel_updated->display_name,'nicename'=>$ols_wpanel_updated->user_nicename],'site_admin_email'=>(string)get_option('admin_email')]);`

type WPAdministrator struct {
	ID          int    `json:"id"`
	Login       string `json:"login"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Nicename    string `json:"nicename"`
}

type WPAdministratorList struct {
	Administrators []WPAdministrator `json:"administrators"`
	SiteAdminEmail string            `json:"site_admin_email"`
}

type WPAdministratorResult struct {
	Administrator  WPAdministrator `json:"administrator"`
	SiteAdminEmail string          `json:"site_admin_email"`
}

type WPAdministratorUpdate struct {
	UserID          int    `json:"user_id"`
	Login           string `json:"login"`
	Password        string `json:"password,omitempty"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	SyncNicename    bool   `json:"sync_nicename"`
	SyncAdminEmail  bool   `json:"sync_admin_email"`
	DestroySessions bool   `json:"destroy_sessions"`
}

type wpAdminManagerInput struct {
	Action      string `json:"action"`
	Root        string `json:"root"`
	DBName      string `json:"db_name"`
	TablePrefix string `json:"table_prefix"`
	WPAdministratorUpdate
}

type wpAdminManagerEnvelope struct {
	Token     string          `json:"token"`
	OK        bool            `json:"ok"`
	Data      json.RawMessage `json:"data"`
	ErrorCode string          `json:"error_code"`
}

var wpAdminManagerErrorPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

type WPAdminManagerError struct{ Code string }

func (e *WPAdminManagerError) Error() string { return "administrator runner: " + e.Code }

func WPAdminManagerErrorCode(err error) string {
	var managerErr *WPAdminManagerError
	if errors.As(err, &managerErr) {
		return managerErr.Code
	}
	return ""
}

func ListWPAdministrators(ctx context.Context, site *models.Website) (WPAdministratorList, error) {
	var result WPAdministratorList
	if err := runWPAdminManager(ctx, site, "list", WPAdministratorUpdate{}, &result); err != nil {
		return result, err
	}
	if result.Administrators == nil {
		result.Administrators = []WPAdministrator{}
	}
	return result, nil
}

func UpdateWPAdministrator(ctx context.Context, site *models.Website, update WPAdministratorUpdate) (WPAdministratorResult, error) {
	var result WPAdministratorResult
	if err := runWPAdminManager(ctx, site, "update", update, &result); err != nil {
		return result, err
	}
	return result, nil
}

func PreflightWPAdministratorUpdate(ctx context.Context, site *models.Website, update WPAdministratorUpdate) error {
	var result struct {
		Validated bool `json:"validated"`
	}
	if err := runWPAdminManager(ctx, site, "preflight", update, &result); err != nil {
		return err
	}
	if !result.Validated {
		return errors.New("administrator preflight response invalid")
	}
	return nil
}

func runWPAdminManager(ctx context.Context, site *models.Website, action string, update WPAdministratorUpdate, target interface{}) error {
	if site == nil || site.SiteType != "wordpress" || site.ID <= 0 || site.DBName == "" || !IsValidWPTablePrefix(site.TablePrefix) {
		return errors.New("invalid WordPress site")
	}
	cfg := config.AppConfig
	if cfg == nil {
		return errors.New("panel configuration unavailable")
	}
	runner, err := newDefaultWPCorePHPRunner(cfg.Paths.WWWRoot)
	if err != nil {
		return err
	}
	validated, err := runner.validate(wpCoreUpdateExecution{WebRoot: site.WebRoot, SystemUser: site.SystemUser, PHPVersion: site.PHPVersion})
	if err != nil {
		return err
	}
	input := wpAdminManagerInput{Action: action, Root: validated.root, DBName: site.DBName, TablePrefix: site.TablePrefix, WPAdministratorUpdate: update}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > 64<<10 {
		return errors.New("administrator request too large")
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	args := []string{"-u", validated.user, "--", validated.php, "-d", "open_basedir=" + strings.Join([]string{validated.root, "/tmp", "/usr/share/php"}, ":"), "-d", "disable_functions=" + sitePHPDisabledFunctions(), "-d", "allow_url_include=0", "-d", "display_errors=0", "-d", "memory_limit=256M", "-r", wpAdminManagerPHPSource}
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(execCtx, validated.runuser, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=" + validated.home, "USER=" + validated.user, "LOGNAME=" + validated.user, "TMPDIR=/tmp", "OLS_WPANEL_RUNNER_TOKEN=" + token}
	cmd.Stdin = bytes.NewReader(payload)
	stdout, stderr, protocol := newCountingSink(64<<10, false), newCountingSink(64<<10, false), newCountingSink(64<<10, true)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readPipe.Close()
	cmd.ExtraFiles = []*os.File{writePipe}
	wpInventoryConfigureCommand(cmd)
	if err := cmd.Start(); err != nil {
		writePipe.Close()
		return errors.New("administrator runner start failed")
	}
	_ = writePipe.Close()
	done := make(chan error, 1)
	go func() { _, err := io.Copy(protocol, readPipe); done <- err }()
	waitErr := cmd.Wait()
	copyErr := <-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if execCtx.Err() != nil {
		return errors.New("administrator runner timed out")
	}
	_, stdoutExceeded, _ := stdout.snapshot()
	_, stderrExceeded, _ := stderr.snapshot()
	_, protocolExceeded, raw := protocol.snapshot()
	if copyErr != nil || stdoutExceeded || stderrExceeded || protocolExceeded {
		return errors.New("administrator runner output invalid")
	}
	var envelope wpAdminManagerEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Token != token || waitErr != nil || !envelope.OK {
		if envelope.Token == token && wpAdminManagerErrorPattern.MatchString(envelope.ErrorCode) {
			return &WPAdminManagerError{Code: envelope.ErrorCode}
		}
		return errors.New("administrator runner failed")
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return errors.New("administrator runner response invalid")
	}
	return nil
}
