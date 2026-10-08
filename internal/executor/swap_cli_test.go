package executor

import (
	"errors"
	"fmt"
	"testing"
)

func TestSwapCLIRequestValidatesBeforeExecution(t *testing.T) {
	tests := []struct {
		action, value string
		valid         bool
		size, setting int64
	}{
		{"swap-status", "", true, 0, 0},
		{"swap-recommended", "", true, 0, 0},
		{"swap-custom", "512:1", true, 512, 1},
		{"swap-custom", "8192:100", true, 8192, 100},
		{"swap-custom", "1024:60", true, 1024, 60},
		{"swap-swappiness", "1", true, 0, 1},
		{"swap-swappiness", "100", true, 0, 100},
		{"swap-remove", "REMOVE SWAP", true, 0, 0},
		{"swap-status", "60", false, 0, 0},
		{"swap-recommended", "1024", false, 0, 0},
		{"swap-custom", "256:60", false, 0, 0},
		{"swap-custom", "8193:60", false, 0, 0},
		{"swap-custom", "513:60", false, 0, 0},
		{"swap-custom", "1024:0", false, 0, 0},
		{"swap-custom", "1024:101", false, 0, 0},
		{"swap-custom", "1024", false, 0, 0},
		{"swap-custom", "1024:60:extra", false, 0, 0},
		{"swap-custom", "1024: 60", false, 0, 0},
		{"swap-custom", "+1024:60", false, 0, 0},
		{"swap-custom", "1024;touch /tmp/unsafe:60", false, 0, 0},
		{"swap-swappiness", "", false, 0, 0},
		{"swap-swappiness", "-1", false, 0, 0},
		{"swap-swappiness", "1.5", false, 0, 0},
		{"swap-swappiness", "0x3c", false, 0, 0},
		{"swap-swappiness", "101", false, 0, 0},
		{"swap-swappiness", "999999999999999999999999", false, 0, 0},
		{"swap-remove", "remove swap", false, 0, 0},
		{"swap-remove", "REMOVE SWAP\n", false, 0, 0},
		{"swap-unknown", "", false, 0, 0},
	}
	for _, test := range tests {
		t.Run(test.action+"/"+test.value, func(t *testing.T) {
			request, err := parseSwapCLIRequest(test.action, test.value)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
			if test.valid && (request.sizeMB != test.size || request.swappiness != test.setting) {
				t.Fatalf("request=%+v", request)
			}
			if (ValidateSwapCLI(test.action, test.value) == nil) != test.valid {
				t.Fatal("exported validation disagrees with parser")
			}
		})
	}
}

func TestSwapCLIDispatchUsesOnlyRequestedExecutor(t *testing.T) {
	for _, test := range []struct {
		action, value, call string
	}{
		{"swap-status", "", "status"},
		{"swap-recommended", "", "recommended"},
		{"swap-custom", "1536:25", "custom:1536:25"},
		{"swap-swappiness", "60", "swappiness:60"},
		{"swap-remove", "REMOVE SWAP", "remove:REMOVE SWAP"},
	} {
		t.Run(test.action, func(t *testing.T) {
			calls := []string{}
			want := SwapStatus{TotalBytes: 987654, Swappiness: 25}
			record := func(call string) (SwapStatus, error) {
				calls = append(calls, call)
				return want, nil
			}
			operations := swapCLIOperations{
				status:      func() (SwapStatus, error) { return record("status") },
				recommended: func() (SwapStatus, error) { return record("recommended") },
				custom: func(size, setting int64) (SwapStatus, error) {
					return record(fmt.Sprintf("custom:%d:%d", size, setting))
				},
				swappiness: func(setting int64) (SwapStatus, error) {
					return record(fmt.Sprintf("swappiness:%d", setting))
				},
				remove: func(confirm string) (SwapStatus, error) { return record("remove:" + confirm) },
			}
			request, err := parseSwapCLIRequest(test.action, test.value)
			if err != nil {
				t.Fatal(err)
			}
			got, err := executeSwapCLI(request, operations)
			if err != nil || got.TotalBytes != want.TotalBytes || got.Swappiness != want.Swappiness {
				t.Fatalf("status=%+v error=%v", got, err)
			}
			if len(calls) != 1 || calls[0] != test.call {
				t.Fatalf("calls=%v, want [%s]", calls, test.call)
			}
		})
	}
}

func TestSwapCLIRetainsSafetyFailureAndRejectsUnknownDispatch(t *testing.T) {
	want := errors.New("insufficient memory")
	request, err := parseSwapCLIRequest("swap-remove", "REMOVE SWAP")
	if err != nil {
		t.Fatal(err)
	}
	_, err = executeSwapCLI(request, swapCLIOperations{remove: func(string) (SwapStatus, error) {
		return SwapStatus{}, want
	}})
	if !errors.Is(err, want) {
		t.Fatalf("executor safety error=%v", err)
	}
	if _, err := executeSwapCLI(swapCLIRequest{action: "swap-invalid"}, swapCLIOperations{}); err == nil {
		t.Fatal("unknown action was accepted")
	}
}
