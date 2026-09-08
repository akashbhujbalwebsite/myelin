/*
Copyright 2026 Myelin Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package crypto implements hybrid envelope encryption for Myelin secrets.
//
// Encryption scheme (per secret key-value):
//
//	1. Generate a fresh 256-bit AES key (crypto/rand).
//	2. Encrypt the plaintext with AES-256-GCM.
//	   - A fresh 96-bit nonce is generated per encryption.
//	   - The OAEP label (namespace/name) is used as GCM additional data (AAD),
//	     binding the ciphertext to the specific secret identity.
//	   - GCM provides authenticated encryption — tampering is detected, not hidden.
//	3. Encrypt the AES key with RSA-4096-OAEP (SHA-256), using the same label.
//	4. The wire format is: base64( len(encryptedKey)[4 bytes big-endian]
//	                                || encryptedKey
//	                                || nonce[12 bytes]
//	                                || aesCiphertext )
//
// This approach has no plaintext size limit (unlike raw RSA which caps at 446 bytes
// for RSA-4096-OAEP-SHA256) and provides IND-CCA2 security for the key wrapping
// combined with IND-CPA + authenticity from GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	// RSAKeyBits is the key size for the operator RSA key pair.
	RSAKeyBits = 4096

	aesKeyLen  = 32 // AES-256
	gcmNonceLen = 12 // standard GCM nonce size
)

// GenerateKeyPair creates a new RSA-4096 key pair for the operator.
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeyBits)
}

// EncodePublicKeyPEM encodes an RSA public key to PKIX PEM format.
func EncodePublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePrivateKeyPEM encodes an RSA private key to PKCS8 PEM format.
func EncodePrivateKeyPEM(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodePublicKeyPEM parses a PKIX PEM-encoded RSA public key.
func DecodePublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM does not contain an RSA public key")
	}
	return rsaPub, nil
}

// DecodePrivateKeyPEM parses a PKCS8 PEM-encoded RSA private key.
func DecodePrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM does not contain an RSA private key")
	}
	return rsaKey, nil
}

// Encrypt encrypts arbitrary-length plaintext using hybrid AES-256-GCM + RSA-4096-OAEP.
//
// label binds the ciphertext to a specific secret identity (namespace/name).
// Decrypting with a different label will fail — preventing ciphertext reuse across secrets.
//
// Returns a base64-encoded blob safe to store in a MyelinSecret CRD.
func Encrypt(pub *rsa.PublicKey, plaintext []byte, label []byte) (string, error) {
	// Step 1: generate a fresh AES-256 key.
	aesKey := make([]byte, aesKeyLen)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", fmt.Errorf("generate aes key: %w", err)
	}

	// Step 2: encrypt the AES key with RSA-OAEP.
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, label)
	if err != nil {
		return "", fmt.Errorf("rsa encrypt aes key: %w", err)
	}

	// Step 3: encrypt plaintext with AES-256-GCM.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Use label as GCM additional authenticated data so the ciphertext is
	// bound to this specific secret identity at the symmetric layer too.
	aesCiphertext := gcm.Seal(nil, nonce, plaintext, label)

	// Step 4: pack into wire format:
	//   [4-byte big-endian encryptedKeyLen][encryptedKey][nonce][aesCiphertext]
	keyLen := len(encryptedKey)
	buf := make([]byte, 4+keyLen+gcmNonceLen+len(aesCiphertext))
	binary.BigEndian.PutUint32(buf[:4], uint32(keyLen))
	copy(buf[4:], encryptedKey)
	copy(buf[4+keyLen:], nonce)
	copy(buf[4+keyLen+gcmNonceLen:], aesCiphertext)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// Decrypt decrypts a base64-encoded blob produced by Encrypt.
// label must exactly match the value used during encryption.
func Decrypt(priv *rsa.PrivateKey, ciphertext64 string, label []byte) ([]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(ciphertext64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if len(buf) < 4 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Unpack wire format.
	keyLen := int(binary.BigEndian.Uint32(buf[:4]))
	if len(buf) < 4+keyLen+gcmNonceLen {
		return nil, fmt.Errorf("ciphertext truncated (expected key+nonce, got %d bytes)", len(buf)-4)
	}

	encryptedKey := buf[4 : 4+keyLen]
	nonce := buf[4+keyLen : 4+keyLen+gcmNonceLen]
	aesCiphertext := buf[4+keyLen+gcmNonceLen:]

	// Step 1: unwrap the AES key.
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, label)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt aes key: %w", err)
	}

	// Step 2: decrypt + verify the GCM ciphertext.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, aesCiphertext, label)
	if err != nil {
		// GCM authentication failure — ciphertext was tampered with or label mismatch.
		return nil, fmt.Errorf("gcm authentication failed (tampered ciphertext or wrong label): %w", err)
	}

	return plaintext, nil
}

// Label returns the OAEP/GCM AAD label for a given secret name and namespace.
// Binding ciphertext to name+namespace prevents the same encrypted value from
// being reused in a different secret or namespace.
func Label(name, namespace string) []byte {
	return []byte(fmt.Sprintf("%s/%s", namespace, name))
}
