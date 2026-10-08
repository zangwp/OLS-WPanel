package executor

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type swapCLIRequest struct {
	action     string
	sizeMB     int64
	swappiness int64
}

type swapCLIOperations struct {
	status      func() (SwapStatus, error)
	recommended func() (SwapStatus, error)
	custom      func(int64, int64) (SwapStatus, error)
	swappiness  func(int64) (SwapStatus, error)
	remove      func(string) (SwapStatus, error)
}

// RunSwapCLI is the one-shot terminal bridge. It does not start the daemon or
// migrate its database. Host changes keep the existing Swap safety checks and
// are serialized between separate SSH processes by a protected kernel lock.
func RunSwapCLI(action, value string) (SwapStatus, error) {
	request, err := parseSwapCLIRequest(action, value)
	if err != nil {
		return SwapStatus{}, err
	}
	if request.action != "swap-status" {
		if os.Geteuid() != 0 {
			return SwapStatus{}, errors.New("修改 Swap 需要 root 权限")
		}
		lock, err := acquireSwapCLILock(canonicalSwapCLILockPath)
		if err != nil {
			return SwapStatus{}, err
		}
		defer lock.Close()
	}
	return executeSwapCLI(request, swapCLIOperations{
		status: GetSwapStatus, recommended: ApplyRecommendedSwap,
		custom: ApplyManagedSwap, swappiness: SetSwapSwappiness, remove: RemoveManagedSwap,
	})
}

// ValidateSwapCLI rejects invalid input before main opens any database.
func ValidateSwapCLI(action, value string) error {
	_, err := parseSwapCLIRequest(action, value)
	return err
}

func parseSwapCLIRequest(action, value string) (swapCLIRequest, error) {
	request := swapCLIRequest{action: action}
	switch action {
	case "swap-status", "swap-recommended":
		if value != "" {
			return request, errors.New("此 Swap 操作不接受额外参数")
		}
	case "swap-custom":
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return request, errors.New("Swap 参数格式必须为 容量MB:swappiness")
		}
		var err error
		request.sizeMB, err = parseSwapCLIInteger(parts[0])
		if err != nil {
			return request, err
		}
		request.swappiness, err = parseSwapCLIInteger(parts[1])
		if err != nil {
			return request, err
		}
		if err := validateSwapSettings(request.sizeMB, request.swappiness); err != nil {
			return request, err
		}
	case "swap-swappiness":
		var err error
		request.swappiness, err = parseSwapCLIInteger(value)
		if err != nil {
			return request, err
		}
		if request.swappiness < 1 || request.swappiness > 100 {
			return request, errors.New("swappiness 必须在 1 到 100 之间")
		}
	case "swap-remove":
		if value != "REMOVE SWAP" {
			return request, errors.New("删除 Swap 必须输入确认词 REMOVE SWAP")
		}
	default:
		return request, errors.New("未知 Swap 操作")
	}
	return request, nil
}

func parseSwapCLIInteger(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("Swap 参数必须为十进制正整数")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errors.New("Swap 参数必须为十进制正整数")
		}
	}
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("Swap 数值参数超出范围")
	}
	return number, nil
}

func executeSwapCLI(request swapCLIRequest, operations swapCLIOperations) (SwapStatus, error) {
	switch request.action {
	case "swap-status":
		return operations.status()
	case "swap-recommended":
		return operations.recommended()
	case "swap-custom":
		return operations.custom(request.sizeMB, request.swappiness)
	case "swap-swappiness":
		return operations.swappiness(request.swappiness)
	case "swap-remove":
		return operations.remove("REMOVE SWAP")
	default:
		return SwapStatus{}, errors.New("未知 Swap 操作")
	}
}
