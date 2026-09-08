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

// Package kubeclient provides a thin Kubernetes client for CLI use.
package kubeclient

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// Client wraps a controller-runtime client for CLI operations.
type Client struct {
	c client.Client
}

// New builds a Client using the kubeconfig from the default discovery chain
// (~/.kube/config → KUBECONFIG env → in-cluster).
func New() (*Client, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, &clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create kube client: %w", err)
	}
	return &Client{c: c}, nil
}

// PublicKeyPEM fetches the operator's RSA public key PEM from the named Secret.
func (kc *Client) PublicKeyPEM(ctx context.Context, secretName, namespace string) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := kc.c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, secretName, err)
	}
	pem, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("field tls.crt not found in secret %s/%s", namespace, secretName)
	}
	return pem, nil
}
