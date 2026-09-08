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

package crypto_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/myelinio/myelin/internal/crypto"
)

// sharedKey is generated once for the test binary — key generation is slow (RSA-4096).
var sharedKey, _ = crypto.GenerateKeyPair()

func TestEncryptDecryptRoundtrip(t *testing.T) {
	plaintext := []byte("super-secret-password-123")
	label := crypto.Label("db-creds", "prod")

	ciphertext, err := crypto.Encrypt(&sharedKey.PublicKey, plaintext, label)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := crypto.Decrypt(sharedKey, ciphertext, label)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

// TestLargePayload proves the hybrid scheme handles secrets well beyond the
// 446-byte RSA-OAEP plaintext limit. A 10 KB secret is a realistic worst case
// (e.g. a TLS certificate or a large JSON config).
func TestLargePayload(t *testing.T) {
	sizes := []int{447, 1024, 4096, 10240} // 447 is the first byte that breaks raw RSA-OAEP
	label := crypto.Label("big-secret", "default")

	for _, size := range sizes {
		t.Run(strings.Repeat("0", 0)+string(rune('0'+size/1000))+"KB", func(t *testing.T) {
			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			ciphertext, err := crypto.Encrypt(&sharedKey.PublicKey, plaintext, label)
			if err != nil {
				t.Fatalf("Encrypt(%d bytes): %v", size, err)
			}

			got, err := crypto.Decrypt(sharedKey, ciphertext, label)
			if err != nil {
				t.Fatalf("Decrypt(%d bytes): %v", size, err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("payload size %d: roundtrip mismatch", size)
			}
		})
	}
}

func TestDecryptFailsWithWrongLabel(t *testing.T) {
	label := crypto.Label("db-creds", "prod")
	wrongLabel := crypto.Label("db-creds", "staging")

	ciphertext, err := crypto.Encrypt(&sharedKey.PublicKey, []byte("secret"), label)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = crypto.Decrypt(sharedKey, ciphertext, wrongLabel)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong label but it succeeded")
	}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
	wrongKey, _ := crypto.GenerateKeyPair()
	label := crypto.Label("my-secret", "default")

	ciphertext, err := crypto.Encrypt(&sharedKey.PublicKey, []byte("secret"), label)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = crypto.Decrypt(wrongKey, ciphertext, label)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong key but it succeeded")
	}
}

// TestTamperedCiphertext verifies that GCM authentication catches bit-flipping.
// This is only possible because we use authenticated encryption (AES-GCM),
// not plain CBC which would silently decrypt corrupted data.
func TestTamperedCiphertext(t *testing.T) {
	label := crypto.Label("tamper-test", "default")
	ciphertext64, err := crypto.Encrypt(&sharedKey.PublicKey, []byte("sensitive-value"), label)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	raw, _ := base64.StdEncoding.DecodeString(ciphertext64)
	// Flip a byte in the AES ciphertext portion (after the RSA-encrypted key and nonce).
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = crypto.Decrypt(sharedKey, tampered, label)
	if err == nil {
		t.Fatal("expected decrypt to fail with tampered ciphertext but it succeeded — GCM auth broken")
	}
}

// TestMalformedCiphertext verifies graceful failure, not a panic.
func TestMalformedCiphertext(t *testing.T) {
	label := crypto.Label("test", "default")
	cases := []string{
		"",                          // empty
		"not-base64!!!",             // invalid base64
		base64.StdEncoding.EncodeToString([]byte("short")), // too short
	}
	for _, c := range cases {
		_, err := crypto.Decrypt(sharedKey, c, label)
		if err == nil {
			t.Errorf("expected error for malformed input %q, got nil", c)
		}
	}
}

func TestPEMRoundtrip(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	privPEM, err := crypto.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	pubPEM, err := crypto.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM: %v", err)
	}

	decodedPriv, err := crypto.DecodePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("DecodePrivateKeyPEM: %v", err)
	}
	decodedPub, err := crypto.DecodePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("DecodePublicKeyPEM: %v", err)
	}

	label := crypto.Label("test", "default")
	ciphertext, err := crypto.Encrypt(decodedPub, []byte("hello"), label)
	if err != nil {
		t.Fatalf("Encrypt with decoded public key: %v", err)
	}
	plaintext, err := crypto.Decrypt(decodedPriv, ciphertext, label)
	if err != nil {
		t.Fatalf("Decrypt with decoded private key: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Errorf("got %q, want %q", plaintext, "hello")
	}
}

func TestLabelBindsToNameAndNamespace(t *testing.T) {
	l1 := crypto.Label("secret-a", "ns-1")
	l2 := crypto.Label("secret-a", "ns-2")
	l3 := crypto.Label("secret-b", "ns-1")

	if string(l1) == string(l2) {
		t.Error("labels for different namespaces must differ")
	}
	if string(l1) == string(l3) {
		t.Error("labels for different secret names must differ")
	}
}

// TestEncryptProducesDifferentCiphertexts verifies fresh nonce per encryption —
// same plaintext encrypted twice must not produce identical ciphertexts.
func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	label := crypto.Label("nonce-test", "default")
	plaintext := []byte("same-value")

	c1, err := crypto.Encrypt(&sharedKey.PublicKey, plaintext, label)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	c2, err := crypto.Encrypt(&sharedKey.PublicKey, plaintext, label)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	if c1 == c2 {
		t.Error("two encryptions of the same value produced identical ciphertext — nonce is not random")
	}
}
