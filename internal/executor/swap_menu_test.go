package executor

import (
	"strings"
	"testing"
)

func runSwapMenuFixture(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(panelCommandScript, "swap_page() {")
	if start < 0 {
		t.Fatal("Swap menu function not found")
	}
	end := strings.Index(panelCommandScript[start:], "\nresult() {")
	if end < 0 {
		t.Fatal("Swap menu function not found")
	}
	// Only redirect the fixture's terminal reads to /dev/null. The read mock
	// supplies synthetic answers; no terminal or host-setting command is opened.
	menu := strings.ReplaceAll(panelCommandScript[start:start+end], "< /dev/tty", "< /dev/null")
	fixture := menu + `
page() { echo "PAGE:$1"; }
text_block() { echo "$*"; }
green() { echo "$*"; }
red() { echo "$*"; }
mutate() {
    if [ "$2" = swap-status ]; then
        echo STATUS_READ
    else
        [ "$#" -eq 6 ] && [ "$3" = --vps-value ] && [ "$5" = --config ] || return 91
        echo "MUTATION:$*" >&2
        echo UPDATED_STATUS
    fi
}
read_view() {
    if [ "$1" = swap-actions ]; then echo "1 1 1"; else echo "VIEW:$1"; fi
}
input_index=0
inputs=()
read() {
    case "$2" in recommended_ready) builtin read "$@"; return;; esac
    [ "$input_index" -lt "${#inputs[@]}" ] || return 1
    local read_arg="" read_var=""
    for read_arg in "$@"; do read_var="$read_arg"; done
    IFS= builtin read -r "$read_var" <<< "${inputs[$input_index]}"
    input_index=$((input_index+1))
}
` + body
	return runPanelMenuFixture(t, fixture)
}

func assertNoSwapMutation(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "MUTATION:") {
		t.Fatalf("read, cancellation, or unavailable action changed Swap: %s", out)
	}
}

func TestSwapMenuViewRefreshAndSystemNavigation(t *testing.T) {
	out := runSwapMenuFixture(t, "choices=(1 0)\nswap_page\n")
	assertNoSwapMutation(t, out)
	if strings.Count(out, "VIEW:swap") != 2 {
		t.Fatalf("view and refresh must both render status: %s", out)
	}
	out = runSwapMenuFixture(t, "choices=(3 0 0)\nsystem_menu\n")
	assertNoSwapMutation(t, out)
	if strings.Count(out, "PAGE:Swap 管理") != 1 {
		t.Fatalf("system settings did not open Swap exactly once: %s", out)
	}
}

func TestSwapMenuCanceledChangesAndRootFailure(t *testing.T) {
	for _, fixture := range []string{
		"confirm_vps() { return 1; }\nchoices=(2 3 4 0)\ninputs=(1024 60 10)\nswap_page\n",
		"need_root() { return 1; }\nchoices=(2 3 4 5 0)\nswap_page\n",
		"choices=(3 0)\ninputs=('')\nswap_page\n",
	} {
		assertNoSwapMutation(t, runSwapMenuFixture(t, fixture))
	}
}

func TestSwapMenuUnavailableActionsCannotBeTypedManually(t *testing.T) {
	out := runSwapMenuFixture(t, `
read_view() { if [ "$1" = swap-actions ]; then echo "0 0 0"; else echo "VIEW:$1"; fi; }
choices=(2 3 5 0)
swap_page
`)
	assertNoSwapMutation(t, out)
	for _, label := range []string{"2. 应用建议配置", "3. 自定义 Swap 文件容量", "5. 删除受管 Swap 文件"} {
		if strings.Contains(out, label) {
			t.Fatalf("unavailable action was displayed: %q\n%s", label, out)
		}
	}
	for _, reason := range []string{"当前不可应用建议配置", "当前不可创建或调整受管文件", "没有可删除的受管文件"} {
		if !strings.Contains(out, reason) {
			t.Fatalf("manually entered unavailable action was not rejected: %s", out)
		}
	}
}

func TestSwapMenuRejectsInvalidCustomCapacityAndSwappiness(t *testing.T) {
	for _, capacity := range []string{"0", "511", "513", "8193", "10000", "999999", "-512", "1e3", "1024;echo BAD"} {
		t.Run("capacity-"+capacity, func(t *testing.T) {
			out := runSwapMenuFixture(t, "choices=(3 0)\ninputs=('"+capacity+"')\nswap_page\n")
			assertNoSwapMutation(t, out)
			if !strings.Contains(out, "容量须为 512–8192 MB") {
				t.Fatalf("invalid capacity was not rejected explicitly: %s", out)
			}
		})
	}
	for _, value := range []string{"0", "101", "1000", "-1", "1.5", "abc", "10;echo BAD"} {
		t.Run("swappiness-"+value, func(t *testing.T) {
			out := runSwapMenuFixture(t, "choices=(3 4 0)\ninputs=(1024 '"+value+"' '"+value+"')\nswap_page\n")
			assertNoSwapMutation(t, out)
			if strings.Count(out, "swappiness 须为 1–100") != 2 {
				t.Fatalf("invalid custom and standalone swappiness were not both rejected: %s", out)
			}
		})
	}
}

func TestSwapMenuValidCustomBoundariesAndExplicitRemoval(t *testing.T) {
	out := runSwapMenuFixture(t, "choices=(2 3 3 4 5 0)\ninputs=(512 1 8192 100 60 'REMOVE SWAP')\nswap_page\n")
	for _, invocation := range []string{
		"--vps-tool swap-recommended --vps-value  --config",
		"--vps-tool swap-custom --vps-value 512:1 --config",
		"--vps-tool swap-custom --vps-value 8192:100 --config",
		"--vps-tool swap-swappiness --vps-value 60 --config",
		"--vps-tool swap-remove --vps-value REMOVE SWAP --config",
	} {
		if strings.Count(out, "MUTATION:"+invocation) != 1 {
			t.Fatalf("valid action did not dispatch exactly once with its arguments: %q\n%s", invocation, out)
		}
	}
	if strings.Count(out, "MUTATION:") != 5 {
		t.Fatalf("unexpected extra Swap modifications: %s", out)
	}
	for _, confirmation := range []string{"", "remove swap", "REMOVE", "REMOVE SWAP ", "YES"} {
		out = runSwapMenuFixture(t, "choices=(5 0)\ninputs=('"+confirmation+"')\nswap_page\n")
		assertNoSwapMutation(t, out)
	}
}

func TestSwapMenuStopsOnMissingStatusOrFormatterFailure(t *testing.T) {
	for _, fixture := range []string{
		"mutate() { return 1; }\nchoices=(2)\nswap_page || :\n",
		"read_view() { return 1; }\nchoices=(2)\nswap_page || :\n",
	} {
		out := runSwapMenuFixture(t, fixture)
		assertNoSwapMutation(t, out)
		if strings.Contains(out, "2. 应用建议配置") {
			t.Fatalf("failed status exposed modification controls: %s", out)
		}
	}
}

func TestSwapMenuCommandFailureIsVisibleWithoutSuccess(t *testing.T) {
	out := runSwapMenuFixture(t, `
mutate() {
    if [ "$2" = swap-status ]; then echo STATUS_READ; else echo SYNTHETIC_COMMAND_FAILURE >&2; return 9; fi
}
choices=(2 0)
swap_page
`)
	if !strings.Contains(out, "SYNTHETIC_COMMAND_FAILURE") || !strings.Contains(out, "Swap 设置失败") {
		t.Fatalf("failed command reason was hidden: %s", out)
	}
	if strings.Contains(out, "Swap 设置已完成") {
		t.Fatalf("failed command reported success: %s", out)
	}
}
