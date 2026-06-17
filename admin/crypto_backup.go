package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	BackupMagic = "SDNS_ENCRYPT"
	SaltSize    = 16
	NonceSize   = 12
	PBKDF2Iter  = 50000
)

func IsBackupEncrypted(data []byte) bool {
	return len(data) >= len(BackupMagic) && string(data[:len(BackupMagic)]) == BackupMagic
}

func EncryptBackup(data []byte, password string) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iter, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	out := make([]byte, 0, len(BackupMagic)+SaltSize+NonceSize+len(ciphertext))
	out = append(out, []byte(BackupMagic)...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func DecryptBackup(data []byte, password string) ([]byte, error) {
	if !IsBackupEncrypted(data) {
		return nil, errors.New("not encrypted or invalid magic")
	}

	headerLen := len(BackupMagic) + SaltSize + NonceSize
	if len(data) < headerLen {
		return nil, errors.New("ciphertext too short")
	}

	salt := data[len(BackupMagic) : len(BackupMagic)+SaltSize]
	nonce := data[len(BackupMagic)+SaltSize : headerLen]
	ciphertext := data[headerLen:]

	key := pbkdf2.Key([]byte(password), salt, PBKDF2Iter, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: incorrect password")
	}

	return plaintext, nil
}
