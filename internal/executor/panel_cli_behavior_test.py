"""Run the actual Bash functions with every host command replaced by fixtures."""
import os
import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import sys
import unicodedata
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).with_name('panel_cli.sh').read_text(encoding='utf-8')
INSTALL_SOURCE = (pathlib.Path(__file__).parents[2]/'install.sh').read_text(encoding='utf-8')
DEFINITIONS, DISPATCH = SOURCE.split('\ncase "${1:-}" in', 1)
BASH = os.environ.get('OLS_QA_BASH') or shutil.which('bash')
UPDATE_CODE=SOURCE.split("<<'PYUPDATE'\n",1)[1].split('\nPYUPDATE',1)[0]


def quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def actual_color_source():
    return 'color() {'+SOURCE.split('color() {',1)[1].split('\naudit_cli() {',1)[0]+'\n'


STDOUT_TTY_FIXTURE='''
[() {
    if builtin test "$#" -eq 3 && builtin test "$1" = -t && builtin test "$2" = 1; then return 0; fi
    builtin [ "$@"
}
'''


def presentation_source(width, views=None, tty=False):
    """Use actual layout functions; only the Python interpreter and read payloads are fixtures."""
    helpers='text_block() {'+SOURCE.split('text_block() {',1)[1].split('\nrule() {',1)[0]
    helpers+='\nrule() {'+SOURCE.split('rule() {',1)[1].split('\npage() {',1)[0]
    helpers+='\npage() {'+SOURCE.split('page() {',1)[1].split('\npause_page() {',1)[0]
    helpers+='\npython3() { '+quote(pathlib.Path(sys.executable).as_posix())+' "$@"; }\n'
    helpers+='tput() { echo '+str(width)+'; }\nblue() { printf "%s\\n" "$*"; }\n'
    if tty:helpers+=actual_color_source()+STDOUT_TTY_FIXTURE
    if views is not None:
        helpers+='read_view() { case "$1" in\n'
        for view,output in views.items():helpers+=quote(view)+') printf "%s" '+quote(output)+';;\n'
        helpers+='*) echo "[fixture] 状态读取";; esac; }\n'
    return helpers


@unittest.skipUnless(BASH, 'native Bash unavailable')
class BashBehaviorTest(unittest.TestCase):
    def fixture(self, body, dispatch=None, definitions=DEFINITIONS, env_extra=None):
        with tempfile.TemporaryDirectory() as directory:
            script = pathlib.Path(directory) / 'synthetic.sh'
            mocks = '''
PATH=''
green() { printf 'GREEN:%s\\n' "$*"; }
red() { printf 'RED:%s\\n' "$*"; }
blue() { :; }; dim() { printf '%s\\n' "$*"; }
page() { :; }; text_block() { printf '%s\\n' "$*"; }
pause_page() { :; }; sleep() { :; }
need_root() { return 0; }
confirm_vps() { return 0; }
read_view() { return 0; }
systemctl() { return 23; }
journalctl() { :; }; tail() { :; }
synthetic_binary() { printf 'SYNTHETIC_FAILURE\\n' >&2; return 23; }
BIN=synthetic_binary
index=0
pick() { [ "$index" -lt "${#choices[@]}" ] || return 1; choice="${choices[$index]}"; index=$((index+1)); }
'''
            script.write_text(definitions + mocks + body + ('\ncase "${1:-}" in' + DISPATCH if dispatch else ''), encoding='utf-8', newline='\n')
            env = dict(os.environ, PATH='', TERM='dumb', NO_COLOR='1', BASH_ENV='')
            env.update(env_extra or {})
            return subprocess.run([BASH, '--noprofile', '--norc', str(script), *([dispatch] if dispatch else [])], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15, env=env)

    def test_restart_and_info_do_not_hide_command_failure(self):
        for command in ['restart', 'info']:
            result = self.fixture('', dispatch=command)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('GREEN:', result.stdout)
        result = self.fixture('systemctl() { [ "$1" = restart ]; }\n', dispatch='restart')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('重启后未能启动', result.stdout)

    def test_result_and_swap_failure_preserve_nonzero_status(self):
        result = self.fixture('result synthetic_binary\n')
        self.assertEqual(result.returncode, 23)
        self.assertNotIn('GREEN:', result.stdout)
        result = self.fixture('swap_apply swap-custom 1024:60\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('设置已完成', result.stdout)

    def test_background_update_does_not_report_completion(self):
        result = self.fixture('synthetic_binary() { echo TASK_STARTED; }\nread_view() { echo VIEW:$1; }\nchoices=(1 0 0)\nupdates_page\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('后台更新任务已启动', result.stdout)
        self.assertNotIn('操作已完成', result.stdout)
        self.assertIn('VIEW:update-status',result.stdout)

    def test_failed_update_never_opens_a_success_progress_flow(self):
        result=self.fixture('read_view() { echo VIEW:$1; }\nchoices=(1 0)\nupdates_page\n')
        self.assertIn('未成功启动',result.stdout)
        self.assertNotIn('后台更新任务已启动',result.stdout)
        self.assertNotIn('VIEW:update-status',result.stdout)

    def test_new_readonly_commands_dispatch_and_preserve_read_failure(self):
        for command in ['processes','health']:
            result=self.fixture('read_view() { echo VIEW:$1; return 23; }\n',dispatch=command)
            self.assertEqual(result.returncode,23)
            self.assertIn('VIEW:'+command,result.stdout)
            self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)
        result=self.fixture('read_view() { echo VIEW:$1; return 23; }\nchoices=(1 0)\nreadonly_page processes test\n')
        self.assertEqual(result.stdout.count('VIEW:processes'),2)
        self.assertIn('不能据此判断正常',result.stdout)

    def test_home_refresh_health_and_performance_process_entries_only_read(self):
        result=self.fixture('read_view() { echo VIEW:$1; }\nchoices=(r h 0 0)\nvps_menu\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.count('VIEW:home-menu'),3)
        self.assertIn('VIEW:health',result.stdout)
        self.assertNotIn('VIEW:info',result.stdout)
        result=self.fixture('read_view() { echo VIEW:$1; }\nchoices=(1 0)\nvps_menu\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.count('VIEW:info'),1)
        result=self.fixture('read_view() { echo VIEW:$1; }\nchoices=(5 0 6 0 0)\nperformance_menu\n')
        self.assertIn('VIEW:processes',result.stdout);self.assertIn('VIEW:health',result.stdout)
        self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)

    def test_clean_partial_failure_still_reads_after_state_without_false_success(self):
        body='read_view() { case "$1" in clean-bytes) echo 1024;; clean-result) echo RESULT:$2;; *) echo VIEW:$1;; esac; }\nchoices=(1 0)\nclean_page\n'
        result=self.fixture(body)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('RESULT:1024:1024:23',result.stdout)
        self.assertEqual(result.stdout.count('VIEW:clean'),3)
        self.assertNotIn('GREEN:',result.stdout)

    def test_account_and_unban_confirmation_describe_actual_scope(self):
        result=self.fixture('confirm_vps() { printf "CONFIRM:%s\\n" "$*"; return 1; }\nchoices=(6 7 0)\npanel_menu\n')
        for expected in ['Basic Auth','两层用户名','WordPress','含网站与 SSH 防护','云安全组']:
            self.assertIn(expected,result.stdout)
        self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)

    def test_help_keeps_existing_commands_and_adds_only_readonly_shortcuts(self):
        result=self.fixture('',dispatch='help')
        for command in ['o processes','o health','o report','o ssh-confirm','o update','o system-update-status','o password','o unban','o swap','o advanced']:
            self.assertIn(command,result.stdout)

    def test_report_shortcut_and_advanced_entry_remain_plain_and_readonly(self):
        body=STDOUT_TTY_FIXTURE+actual_color_source()+'python3() { :; }\nread_view() { echo REPORT_BODY:$1; return 23; }\n'
        result=self.fixture(body,dispatch='report',env_extra={'TERM':'xterm','NO_COLOR':''})
        self.assertEqual(result.returncode,23,result.stderr)
        self.assertEqual(result.stdout,'REPORT_BODY:report\n')
        self.assertNotIn('\x1b',result.stdout)
        self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)
        result=self.fixture('python3() { :; }\nread_view() { echo VIEW:$1; }\nchoices=(7 0)\nadvanced_menu\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.count('VIEW:report'),1)
        for entry in ['1. 快捷命令帮助','2. 普通卸载','3. 完全卸载','4. 终端维护记录','5. 维护工具依赖','6. APT / dpkg 健康检查','7. 生成脱敏诊断摘要']:
            self.assertIn(entry,result.stdout)
        self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)
        missing=self.fixture(STDOUT_TTY_FIXTURE+actual_color_source(),dispatch='report',env_extra={'TERM':'xterm','NO_COLOR':''})
        self.assertEqual(missing.returncode,1,missing.stderr)
        self.assertIn('报告状态: failed',missing.stdout);self.assertIn('o status',missing.stdout)
        self.assertNotIn('\x1b',missing.stdout)
        for line in missing.stdout.splitlines():
            cells=sum(0 if unicodedata.combining(c) else (2 if unicodedata.east_asian_width(c) in 'WF' else 1) for c in line)
            self.assertLessEqual(cells,32,line)

    def test_actual_menu_layout_fits_narrow_and_wide_columns(self):
        from panel_cli_render_test import render
        for width in [40,72]:
            views={view:render(view,width)[0] for view in ['home','login-addresses','home-menu']}
            menus=[('vps_menu','choices=(0)'),('network_menu','choices=(0)'),('system_menu','choices=(0)'),('performance_menu','choices=(0)'),('updates_page','choices=(0)'),('clean_page','choices=(0)'),('panel_menu','choices=(0)'),('advanced_menu','choices=(0)')]
            for menu,choices in menus:
                result=self.fixture(presentation_source(width,views)+choices+'\n'+menu+'\n')
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertNotIn('\x1b',result.stdout)
                self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)
                for line in result.stdout.splitlines():
                    if line.startswith(('https://','http://')):continue
                    cells=sum(0 if unicodedata.combining(c) else (2 if unicodedata.east_asian_width(c) in 'WF' else 1) for c in line)
                    self.assertLessEqual(cells,width,(menu,width,line))

    def test_actual_shell_color_requires_tty_and_obeys_no_color_and_dumb(self):
        body=actual_color_source()+'blue 标题\ngreen 正常\nred 失败\ndim 正文\n'
        # The subprocess stdout is a real pipe: TERM alone must not force escapes.
        result=self.fixture(body,env_extra={'TERM':'xterm-256color','NO_COLOR':''})
        self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('\x1b',result.stdout)
        # Only the stdout TTY predicate is simulated; actual color functions and env gates execute in Bash.
        result=self.fixture(STDOUT_TTY_FIXTURE+body,env_extra={'TERM':'xterm','NO_COLOR':''})
        self.assertEqual(result.returncode,0,result.stderr)
        for sequence in ['\x1b[1;36m标题','\x1b[32m正常','\x1b[31m失败']:self.assertIn(sequence,result.stdout)
        self.assertNotIn('\x1b[2m',result.stdout)
        for term,no_color in [('dumb',''),('xterm','1'),('xterm','0')]:
            result=self.fixture(STDOUT_TTY_FIXTURE+body,env_extra={'TERM':term,'NO_COLOR':no_color})
            self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('\x1b',result.stdout)

    def test_readonly_new_menus_never_execute_mutations(self):
        for body in ['choices=(4 5 0)\nnetwork_menu\n', 'choices=(3 4 0 0)\nperformance_menu\n', 'choices=(4 5 6 0)\nadvanced_menu\n', 'choices=(1 0)\nssh_page\n']:
            result = self.fixture(body)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('SYNTHETIC_FAILURE', result.stderr)

    def test_missing_locales_cannot_be_selected_by_hidden_numbers(self):
        result = self.fixture('read_view() { [ "$1" != locale ]; }\nchoices=(1 2 3 0)\nsettings_page locale\n')
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('SYNTHETIC_FAILURE', result.stderr)
        self.assertIn('请先确认安装 locales', result.stdout)
        result=self.fixture('choices=(4 0)\nsettings_page locale\n')
        self.assertEqual(result.returncode,0)
        self.assertNotIn('SYNTHETIC_FAILURE',result.stderr)
        self.assertIn('无需重复安装',result.stdout)

    def test_unsupported_dns_and_ssh_cannot_start_changes(self):
        for body in ['choices=(2 0)\ndns_preset_page international\n', 'choices=(2 0)\nssh_page\n']:
            result = self.fixture('read_view() { return 2; }\n' + body)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn('SYNTHETIC_FAILURE', result.stderr)

    def test_release_comparison_uses_numeric_components_and_rejects_junk(self):
        for left, right, expected in [('v1.18.0','v1.17.10',0),('v1.17.10','v1.17.2',0),('v1.18.0','v1.18.0',1),('dev','v1.18.0',1),('v99999999999.0.0','v1.0.0',1),('v1.2.3;echo BAD','v1.2.3',1)]:
            result = self.fixture('release_is_newer ' + quote(left) + ' ' + quote(right) + '\n')
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertNotIn('BAD', result.stdout)

    def test_diagnostics_count_listener_and_service_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cfg, db, unit = [root / name for name in ['config.json','panel.db','panel.service']]
            for path in [cfg, db, unit]: path.write_text('{}')
            definitions = DEFINITIONS.replace('/etc/systemd/system/${SVC}.service', unit.as_posix())
            setup = '\nBIN='+quote(pathlib.Path(BASH).as_posix())+'\nCFG='+quote(cfg.as_posix())+'\n'
            setup += 'python3() { local source="" line=""; while IFS= builtin read -r line; do source+="$line"; done; case "$source" in *sqlite*) echo '+quote(db.as_posix())+';; *tls_port*) echo "http 8080";; esac; }\n'
            setup += 'ss() { return 0; }; grep() { local line; builtin read -r line; }\n'
            result = self.fixture(setup+'diag\n', definitions=definitions)
            self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('端口 8080 未监听',result.stdout)
            self.assertIn('发现 2 个问题',result.stdout)
            self.assertNotIn('所有检查通过',result.stdout)
            result = self.fixture(setup+'unset -f python3\ndiag\n', definitions=definitions)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('缺少 python3',result.stdout)
            self.assertNotIn('JSON 格式错误',result.stdout)

    def test_installer_bbr_success_requires_actual_kernel_readback(self):
        tuning=INSTALL_SOURCE.split('apply_system_tuning() {',1)[1].split('\nwhile [[ $#',1)[0]
        tuning='apply_system_tuning() {'+tuning
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            tuning=tuning.replace('/etc/sysctl.d/99-ols-wpanel.conf',(root/'sysctl.conf').as_posix()).replace('/etc/security/limits.conf',(root/'limits.conf').as_posix())
            mocks='''
nproc() { echo 2; }; modprobe() { return 1; }; grep() { return 1; }
cat() { local line; while IFS= builtin read -r line; do printf '%s\\n' "$line"; done; }
log_info() { printf 'INFO:%s\\n' "$*"; }; log_warn() { printf 'WARN:%s\\n' "$*"; }
'''
            for algorithm,queue,verified in [('bbr','fq',True),('cubic','fq',False),('bbr','pfifo_fast',False)]:
                body=mocks+'sysctl() { case "$1:$2" in --system:*) return 1;; -n:net.ipv4.tcp_congestion_control) echo '+quote(algorithm)+';; -n:net.core.default_qdisc) echo '+quote(queue)+';; esac; }\napply_system_tuning\n'
                result=self.fixture(body,definitions=tuning)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual('已启用并核验' in result.stdout,verified,result.stdout)
                if not verified:self.assertIn('未确认生效',result.stdout)

    def test_fresh_credentials_remain_literal_and_repair_does_not_reprint_them(self):
        summary='print_install_summary() {'+INSTALL_SOURCE.split('print_install_summary() {',1)[1].split('\nprint_install_summary\n',1)[0]
        variables='''
BOLD='' YELLOW='' NC='' TERM=dumb NO_COLOR=1
INSTALLER_RELEASE_VERSION=v1.18.0 STATUS=running PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false
PUBLIC_IP=192.0.2.24 PUBLIC_HOST=192.0.2.24 LOCAL_IP=10.0.0.24 LOCAL_HOST=10.0.0.24 VALIDATED_TLS_PORT=8443 PANEL_SUFFIX=example-only
BASIC_USER=browser-admin BASIC_PASS='synthetic%pass\\literal' WEB_USER=panel-admin WEB_PASS=synthetic-panel-password CERT_FILE=/example/cert.pem
'''
        for repair in ['false','true']:
            result=self.fixture(variables+'REPAIR_MODE='+repair+'\nprint_install_summary\n',definitions=summary)
            self.assertEqual(result.returncode,0,result.stderr)
            for value in ['browser-admin',r'synthetic%pass\literal','panel-admin','synthetic-panel-password']:
                self.assertEqual(result.stdout.count(value),int(repair=='false'),(repair,value,result.stdout))
            self.assertNotIn('\x1b',result.stdout)


class UpdateTargetTest(unittest.TestCase):
    def render(self,current='v1.18.0',latest='v1.19.0',entry='v1.18.0'):
        def response(request,timeout):
            self.assertEqual(timeout,15)
            if request.get_method()=='HEAD':
                item=io.BytesIO(b'');item.headers={'X-OLS-WPanel-Release':entry}
                return item
            return io.BytesIO(json.dumps({'tag_name':latest}).encode())
        out,err=io.StringIO(),io.StringIO();code=0
        with patch('sys.argv',['update',current,'https://ols.zangyubin.top/install']),patch('urllib.request.urlopen',response),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:exec(compile(UPDATE_CODE,'actual-update-check','exec'),{})
            except SystemExit as e:code=e.code
        return out.getvalue(),err.getvalue(),code

    def test_entry_lag_is_not_advertised_as_installing_latest(self):
        text,err,code=self.render()
        self.assertEqual(code,0,err)
        self.assertIn('GitHub 最新发布: v1.19.0',text)
        self.assertIn('o update 实际目标: v1.18.0',text)
        self.assertIn('短入口尚未同步',text)
        self.assertNotIn('可执行 o update',text)

    def test_installable_update_and_downgrade_are_distinct(self):
        text,err,code=self.render(entry='v1.19.0')
        self.assertEqual(code,0,err);self.assertIn('签名入口有可用更新',text)
        text,err,code=self.render(current='v1.19.0')
        self.assertEqual(code,0,err);self.assertIn('已阻止 o update 降级',text)

    def test_missing_or_invalid_target_is_a_failure(self):
        for entry in [None,'dev','v1.18.0;echo bad']:
            text,err,code=self.render(entry=entry)
            self.assertEqual(code,1);self.assertIn('实际目标: 未确认',text)
            self.assertIn('未返回有效目标版本',err)
            self.assertNotIn('可执行 o update',text)


if __name__ == '__main__': unittest.main()
