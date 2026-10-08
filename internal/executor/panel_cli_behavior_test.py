"""Run the actual Bash functions with every host command replaced by fixtures."""
import os
import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).with_name('panel_cli.sh').read_text(encoding='utf-8')
INSTALL_SOURCE = (pathlib.Path(__file__).parents[2]/'install.sh').read_text(encoding='utf-8')
DEFINITIONS, DISPATCH = SOURCE.split('\ncase "${1:-}" in', 1)
BASH = os.environ.get('OLS_QA_BASH') or shutil.which('bash')
UPDATE_CODE=SOURCE.split("<<'PYUPDATE'\n",1)[1].split('\nPYUPDATE',1)[0]


def quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


@unittest.skipUnless(BASH, 'native Bash unavailable')
class BashBehaviorTest(unittest.TestCase):
    def fixture(self, body, dispatch=None, definitions=DEFINITIONS):
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
        result = self.fixture('synthetic_binary() { echo TASK_STARTED; }\nchoices=(1 0)\nupdates_page\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('后台更新任务已启动', result.stdout)
        self.assertNotIn('操作已完成', result.stdout)

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
