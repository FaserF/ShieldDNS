package main

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptBackup(t *testing.T) {
	plainText := []byte("secret backup payload data")
	password := "my-secure-password"

	encrypted, err := EncryptBackup(plainText, password)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if !IsBackupEncrypted(encrypted) {
		t.Fatalf("Backup should be identified as encrypted")
	}

	decrypted, err := DecryptBackup(encrypted, password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plainText, decrypted) {
		t.Fatalf("Decrypted content mismatch. Expected %q, got %q", plainText, decrypted)
	}

	// Try wrong password
	_, err = DecryptBackup(encrypted, "wrong-password")
	if err == nil {
		t.Fatalf("Decryption should fail with incorrect password")
	}
}
