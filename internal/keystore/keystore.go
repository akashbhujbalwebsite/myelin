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

// Package keystore handles persistent storage of the operator RSA key pair
// inside a Kubernetes Secret. On first boot the key is generated and stored.
// On subsequent boots the existing key is loaded so previously encrypted
// MyelinSecrets remain decryptable after pod restarts.
package keystore

import (
	"context"
	"crypto/rsa"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/myelinio/myelin/internal/crypto"
)

const (
	privateKeyField = "tls.key"
	publicKeyField  = "tls.crt"
)

// KeyStore loads and persists the operator RSA key pair in a Kubernetes Secret.
type KeyStore struct {
	client    client.Client
	name      string
	namespace string
}

// New returns a KeyStore that persists the key in the named Secret.
func New(c client.Client, name, namespace string) *KeyStore {
	return &KeyStore{client: c, name: name, namespace: namespace}
}

// LoadOrGenerate returns the existing private key if the Secret exists,
// or generates a fresh key pair, persists it, and returns the private key.
func (ks *KeyStore) LoadOrGenerate(ctx context.Context, generate func() (*rsa.PrivateKey, error)) (*rsa.PrivateKey, error) {
	secret := &corev1.Secret{}
	err := ks.client.Get(ctx, types.NamespacedName{Name: ks.name, Namespace: ks.namespace}, secret)
	if err == nil {
		return ks.decode(secret)
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get key secret: %w", err)
	}

	// First boot: generate and persist.
	priv, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	if err := ks.persist(ctx, priv); err != nil {
		return nil, fmt.Errorf("persist key pair: %w", err)
	}
	return priv, nil
}

// PublicKeyPEM returns the PEM-encoded public key from the stored Secret.
// Used by the myelin CLI to encrypt secrets without network access to the operator.
func (ks *KeyStore) PublicKeyPEM(ctx context.Context) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := ks.client.Get(ctx, types.NamespacedName{Name: ks.name, Namespace: ks.namespace}, secret); err != nil {
		return nil, fmt.Errorf("get key secret: %w", err)
	}
	pem, ok := secret.Data[publicKeyField]
	if !ok {
		return nil, fmt.Errorf("public key field %q not found in secret", publicKeyField)
	}
	return pem, nil
}

func (ks *KeyStore) decode(secret *corev1.Secret) (*rsa.PrivateKey, error) {
	privPEM, ok := secret.Data[privateKeyField]
	if !ok {
		return nil, fmt.Errorf("private key field %q not found in key secret", privateKeyField)
	}
	return crypto.DecodePrivateKeyPEM(privPEM)
}

func (ks *KeyStore) persist(ctx context.Context, priv *rsa.PrivateKey) error {
	privPEM, err := crypto.EncodePrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	pubPEM, err := crypto.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ks.name,
			Namespace: ks.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "myelin",
				"app.kubernetes.io/component":  "operator-key",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			privateKeyField: privPEM,
			publicKeyField:  pubPEM,
		},
	}
	return ks.client.Create(ctx, secret)
}
