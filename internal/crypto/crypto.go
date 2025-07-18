package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32 // 32 bytes for X25519 keys
)

// GenerateKeys membuat pasangan kunci privat dan publik untuk X25519.
func GenerateKeys() ([KeySize]byte, [KeySize]byte, error) {
	var privateKey, publicKey [KeySize]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return [KeySize]byte{}, [KeySize]byte{}, fmt.Errorf("gagal membuat kunci privat: %w", err)
	}

	// Sesuai dengan konvensi RFC 7748
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return privateKey, publicKey, nil
}

// SharedSecret menghitung shared secret menggunakan kunci privat lokal dan kunci publik dari peer.
func SharedSecret(privateKey, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var sharedKey [KeySize]byte
	curve25519.ScalarMult(&sharedKey, &privateKey, &peerPublicKey)
	return sharedKey, nil
}

// Encrypt mengenkripsi plaintext menggunakan ChaCha20-Poly1305.
// Nonce harus unik untuk setiap pesan dengan kunci yang sama.
func Encrypt(key [KeySize]byte, plaintext []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat AEAD cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("gagal membuat nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt mendekripsi ciphertext menggunakan ChaCha20-Poly1305.
func Decrypt(key [KeySize]byte, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("gagal membuat AEAD cipher: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("panjang nonce salah: %d", len(nonce))
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gagal mendekripsi paket: %w", err)
	}

	return plaintext, nil
}

// TODO: Implementasi Hybrid Key Exchange
// func GenerateHybridKeys() (*PQCKeys, error) { ... }
// func HybridSharedSecret(...) ([]byte, error) { ... }
