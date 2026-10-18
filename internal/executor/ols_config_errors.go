package executor

import (
	"errors"
	"fmt"
)

func olsConfigStageError(label string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", label, err)
}

func olsConfigRecoveryError(cause error, restoredMessage string, failures ...error) error {
	if recoveryErr := errors.Join(failures...); recoveryErr != nil {
		return errors.Join(cause, recoveryErr)
	}
	if cause == nil || restoredMessage == "" {
		return cause
	}
	return fmt.Errorf("%w；%s", cause, restoredMessage)
}
