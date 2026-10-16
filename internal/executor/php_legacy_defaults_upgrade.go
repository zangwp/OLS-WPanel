package executor

import (
	"os"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func init() {
	database.RegisterUpgrade("1.0.51", UpgradeLegacyPHPMaxInputVars)
}

// UpgradeLegacyPHPMaxInputVars changes the old max_input_vars default from 2000 to 10000.
// Only values equal to 2000 are changed; the config cannot distinguish an explicit
// 2000 from the old default. Other administrator values are preserved.
// This one-time 1.0.51 migration leaves later changes back to 2000 untouched.
func UpgradeLegacyPHPMaxInputVars() error {
	path := PHPRuntimeConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // EnsurePHPRuntimeConfigFile will initialize the new default.
		}
		return err
	}

	content := string(data)
	if findIniValue(content, "max_input_vars") != "2000" {
		return nil
	}

	next := setIniValue(content, "max_input_vars", "10000")
	return os.WriteFile(path, []byte(next), 0644)
}
