//go:build !linux

package executor

import (
	"context"
	"errors"
	"io"
)

func StartWPPanelAccessBroker(context.Context, WPPanelAccessRedeemer) (io.Closer, error) {
	return nil, errors.New("WordPress login broker requires Linux")
}
