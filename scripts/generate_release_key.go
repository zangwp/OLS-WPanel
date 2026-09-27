//go:build ignore

// generate_release_key creates an Ed25519 PKCS#8 private key and its SPKI
// public key. The output directory must be outside the repository and private.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/generate_release_key.go OUTPUT_DIR")
		os.Exit(2)
	}
	dir, err := filepath.Abs(os.Args[1])
	if err != nil { panic(err) }
	if err := os.MkdirAll(dir, 0700); err != nil { panic(err) }
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { panic(err) }
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil { panic(err) }
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil { panic(err) }
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.WriteFile(filepath.Join(dir, "release-signing-key.pem"), privatePEM, 0600); err != nil { panic(err) }
	if err := os.WriteFile(filepath.Join(dir, "release-signing-public.pem"), publicPEM, 0644); err != nil { panic(err) }
	if err := os.WriteFile(filepath.Join(dir, "release-signing-key.b64"), []byte(base64.StdEncoding.EncodeToString(privatePEM)), 0600); err != nil { panic(err) }
	fmt.Printf("PUBLIC_HEX=%s\n", hex.EncodeToString(pub))
	fmt.Printf("PUBLIC_SPKI_B64=%s\n", base64.StdEncoding.EncodeToString(publicDER))
	fmt.Printf("PUBLIC_PEM=%s", publicPEM)
}
