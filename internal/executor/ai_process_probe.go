package executor

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

const (
	aiProcessProbeTimeout = 3 * time.Second
	aiProcessOutputLimit  = 8 << 20
)

var aiProcessCommandContext = exec.CommandContext

var errAIProcessOutputLimit = errors.New("process resource output exceeds limit")

// Keep bytes.Buffer named rather than embedded: an inherited ReadFrom would
// bypass the output budget when os/exec copies process stdout.
type aiProcessOutput struct {
	buffer bytes.Buffer
	limit  int
	cancel context.CancelFunc
	err    error
}

func (w *aiProcessOutput) Write(p []byte) (int, error) {
	remaining := w.limit - w.buffer.Len()
	if len(p) > remaining {
		written, _ := w.buffer.Write(p[:remaining])
		w.err = errAIProcessOutputLimit
		w.cancel()
		return written, w.err
	}
	return w.buffer.Write(p)
}

func runAIProcessList(parent context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, aiProcessProbeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := aiProcessCommandContext(ctx, "ps", "-eo", "user:32,%cpu,%mem,comm")
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	output := &aiProcessOutput{limit: aiProcessOutputLimit, cancel: cancel}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		if output.err != nil {
			return nil, output.err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output.buffer.Bytes(), nil
}
