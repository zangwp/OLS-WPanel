package executor

import "io"

// The adapters use the same protected storage for history and cross-process
// SSH state. Tests substitute only filesystem/lock operations inside fixtures;
// SSH finalization itself still uses the original transaction implementation.
type vpsCLIStorage struct {
	ensureDirectory func(string, bool) error
	readFile        func(string, int64) ([]byte, error)
	writeFile       func(string, []byte) error
	lock            func(string) (io.Closer, error)
}

func productionVPSCLIStorage() vpsCLIStorage {
	return vpsCLIStorage{ensureDirectory: ensureVPSCLIPrivateDirectory, readFile: readVPSCLIPrivateFile, writeFile: writeVPSCLIPrivateFile, lock: func(path string) (io.Closer, error) { return acquireSwapCLILock(path) }}
}
