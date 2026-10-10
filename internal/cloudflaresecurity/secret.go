package cloudflaresecurity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var keyMu sync.Mutex

func secretKey(db *sql.DB, create bool) ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	var seq int
	var name, path string
	if err := db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil || path == "" {
		return nil, errors.New("Cloudflare 凭据密钥不可用")
	}
	path = filepath.Join(filepath.Dir(path), "cloudflare-security.key")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("Cloudflare 凭据密钥文件权限异常")
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) != 32 {
			return nil, errors.New("Cloudflare 凭据密钥损坏；请恢复原密钥")
		}
		return data, nil
	}
	if !os.IsNotExist(err) || !create {
		return nil, errors.New("Cloudflare 凭据密钥缺失；请恢复原密钥")
	}
	var existing int
	if err = db.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security WHERE token_ciphertext<>''`).Scan(&existing); err != nil {
		return nil, errors.New("无法检查已有 Cloudflare 凭据，未创建新密钥")
	}
	if existing > 0 {
		return nil, errors.New("已有 Cloudflare 凭据但密钥缺失；请恢复原密钥，不能自动替换")
	}
	data := make([]byte, 32)
	if _, err = rand.Read(data); err != nil {
		return nil, errors.New("Cloudflare 凭据密钥创建失败")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cloudflare-key-")
	if err != nil {
		return nil, errors.New("Cloudflare 凭据密钥创建失败")
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		return nil, errors.New("Cloudflare 凭据密钥创建失败")
	}
	// Hard-link installation never overwrites an existing key.
	if err = os.Link(tmp.Name(), path); err != nil && !os.IsExist(err) {
		return nil, errors.New("Cloudflare 凭据密钥创建失败")
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Cloudflare 凭据密钥文件权限异常")
	}
	data, err = os.ReadFile(path)
	if err != nil || len(data) != 32 {
		return nil, errors.New("Cloudflare 凭据密钥不可用")
	}
	return data, nil
}
func sealToken(db *sql.DB, id int, token string) (string, error) {
	key, err := secretKey(db, true)
	if err != nil {
		return "", err
	}
	return sealWithKey(key, id, token)
}
func openToken(db *sql.DB, id int, text string) (string, error) {
	key, err := secretKey(db, false)
	if err != nil {
		return "", err
	}
	return openWithKey(key, id, text)
}
func sealWithKey(key []byte, id int, token string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("Cloudflare 凭据加密失败")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("Cloudflare 凭据加密失败")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", errors.New("Cloudflare 凭据加密失败")
	}
	data := gcm.Seal(nonce, nonce, []byte(token), []byte(fmt.Sprintf("cloudflare-security:v1:%d", id)))
	return base64.StdEncoding.EncodeToString(data), nil
}
func openWithKey(key []byte, id int, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("Cloudflare 凭据解密失败")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("Cloudflare 凭据解密失败")
	}
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(data) < gcm.NonceSize() {
		return "", errors.New("Cloudflare 凭据解密失败")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(fmt.Sprintf("cloudflare-security:v1:%d", id)))
	if err != nil {
		return "", errors.New("Cloudflare 凭据解密失败")
	}
	return string(plain), nil
}
