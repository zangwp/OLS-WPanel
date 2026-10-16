package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCNBootstrapVerifiesRealSignedInstallerWithoutDescriptiveComments(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		if os.Getenv("OLS_WPANEL_REQUIRE_BOOTSTRAP_TESTS") == "1" {
			t.Fatalf("Bash is required for bootstrap verifier tests: %v", err)
		}
		t.Skip("Bash unavailable")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("OLS_WPANEL_REQUIRE_BOOTSTRAP_TESTS") == "1" {
			t.Fatalf("OpenSSL is required for bootstrap verifier tests: %v", err)
		}
		t.Skip("OpenSSL unavailable")
	}
	if output, err := exec.Command(openssl, "version").CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL runtime unavailable: %v\n%s", err, output)
	}

	bootstrap := readInstallScript(t, installCNScriptPath)
	installer := readInstallScript(t, installScriptPath)
	const version = "v9.8.7"
	versionLine := regexp.MustCompile(`(?m)^INSTALLER_RELEASE_VERSION="[^"]*"$`)
	if len(versionLine.FindAllString(installer, -1)) != 1 {
		t.Fatal("actual install.sh must declare exactly one installer release version")
	}
	installer = versionLine.ReplaceAllString(installer, `INSTALLER_RELEASE_VERSION="`+version+`"`)

	// Use the real runtime assignments and unmodified verifier functions. Only the
	// fixture's release version and trusted signature PEM are supplied at runtime;
	// install.sh retains the production release-key identity and executable body.
	preambleEnd := requiredIndex(t, bootstrap, "\nlog_info()")
	verifier := bootstrap[:preambleEnd] + "\n" +
		extractShellFunction(t, bootstrap, "file_size_within_limit", "download_install_script") + "\n" +
		extractShellFunction(t, bootstrap, "verify_install_script_bundle", "copy_local_install_script_bundle")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyLine := regexp.MustCompile(`(?m)^RELEASE_PUBLIC_KEY_HEX="[^"]*"$`)
	if len(keyLine.FindAllString(installer, -1)) != 1 {
		t.Fatal("actual install.sh must declare exactly one release-key identity")
	}
	assignments := regexp.MustCompile(`(?m)^[A-Z_][A-Z0-9_]*=`).FindStringIndex(installer)
	if assignments == nil {
		t.Fatal("actual install.sh must declare its runtime variables")
	}
	var headerLines []string
	for index, line := range strings.Split(installer[:assignments[0]], "\n") {
		if index != 0 && strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		headerLines = append(headerLines, line)
	}
	headerWithoutComments := strings.Join(headerLines, "\n")
	withoutDescription := headerWithoutComments + installer[assignments[0]:]
	translatedDescription := headerWithoutComments + "# 安装程序说明可以翻译；签名校验不依赖说明文字。\n" + installer[assignments[0]:]

	type bundle struct{ script, manifest, signature []byte }
	signed := func(body string) bundle {
		script := []byte(body)
		manifest := []byte(fmt.Sprintf("%x  install.sh\n", sha256.Sum256(script)))
		return bundle{script, manifest, ed25519.Sign(privateKey, manifest)}
	}
	signManifest := func(b *bundle, text string) {
		b.manifest = []byte(text)
		b.signature = ed25519.Sign(privateKey, b.manifest)
	}
	tests := []struct {
		name   string
		body   string
		mutate func(*bundle)
		accept bool
	}{
		{name: "actual installer", body: installer, accept: true},
		{name: "translated description", body: translatedDescription, accept: true},
		{name: "removed description", body: withoutDescription, accept: true},
		{name: "missing interpreter", body: strings.TrimPrefix(installer, "#!/bin/bash\n")},
		{name: "wrong interpreter", body: strings.Replace(installer, "#!/bin/bash\n", "#!/bin/sh\n", 1)},
		{name: "interpreter below first line", body: "# A description is not an interpreter directive.\n" + installer},
		{name: "missing release version", body: versionLine.ReplaceAllString(installer, "")},
		{name: "mismatched release version", body: versionLine.ReplaceAllString(installer, `INSTALLER_RELEASE_VERSION="v9.8.8"`)},
		{name: "mismatched release key", body: keyLine.ReplaceAllString(installer, `RELEASE_PUBLIC_KEY_HEX="`+strings.Repeat("0", 64)+`"`)},
		{name: "missing release verification identity", body: strings.ReplaceAll(installer, "verify_panel_release_bundle", "unrelated_release_bundle")},
		{name: "modified script after signing", body: installer, mutate: func(b *bundle) { b.script = append(b.script, []byte("\nprintf 'tampered'\n")...) }},
		{name: "modified manifest after signing", body: installer, mutate: func(b *bundle) { b.manifest[0] ^= 1 }},
		{name: "modified signature", body: installer, mutate: func(b *bundle) { b.signature[0] ^= 1 }},
		{name: "signature from another key", body: installer, mutate: func(b *bundle) { b.signature = ed25519.Sign(otherPrivateKey, b.manifest) }},
		{name: "truncated signature", body: installer, mutate: func(b *bundle) { b.signature = b.signature[:63] }},
		{name: "signed manifest names another asset", body: installer, mutate: func(b *bundle) {
			signManifest(b, fmt.Sprintf("%x  unrelated.sh\n", sha256.Sum256(b.script)))
		}},
		{name: "signed manifest has extra entry", body: installer, mutate: func(b *bundle) { signManifest(b, string(b.manifest)+string(b.manifest)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assets := signed(test.body)
			if test.mutate != nil {
				test.mutate(&assets)
			}
			root := t.TempDir()
			for name, data := range map[string][]byte{
				"install.sh": assets.script, "install.sh.sha256": assets.manifest, "install.sh.sha256.sig": assets.signature,
			} {
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixture := verifier + `
BOOTSTRAP_RELEASE_VERSION="$FIXTURE_RELEASE_VERSION"
RELEASE_PUBLIC_KEY_PEM="$FIXTURE_PUBLIC_KEY_PEM"
PUBLIC_KEY_FILE="$FIXTURE_ROOT/verification-public-key.pem"
verify_install_script_bundle "$FIXTURE_ROOT/install.sh" "$FIXTURE_ROOT/install.sh.sha256" "$FIXTURE_ROOT/install.sh.sha256.sig"
`
			cmd := exec.Command(bash, "-c", fixture)
			cmd.Env = append(os.Environ(), "FIXTURE_RELEASE_VERSION="+version, "FIXTURE_PUBLIC_KEY_PEM="+string(publicPEM), "FIXTURE_ROOT="+filepath.ToSlash(root))
			output, runErr := cmd.CombinedOutput()
			if (runErr == nil) != test.accept {
				t.Fatalf("actual bootstrap verifier accepted=%t, want %t: %v\n%s", runErr == nil, test.accept, runErr, output)
			}
		})
	}
}
