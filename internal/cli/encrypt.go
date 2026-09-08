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

package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	myelinv1alpha1 "github.com/akashbhujbalwebsite/myelin/api/v1alpha1"
	"github.com/akashbhujbalwebsite/myelin/internal/crypto"
	"github.com/akashbhujbalwebsite/myelin/internal/kubeclient"
)

func newEncryptCmd() *cobra.Command {
	var (
		name          string
		namespace     string
		literals      []string
		fromFile      string
		keySecretName string
		keySecretNS   string
		pubKeyFile    string
	)

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt secret values and emit a MyelinSecret manifest",
		Long: `Fetch the operator public key, encrypt each secret value with RSA-OAEP,
and print a ready-to-apply MyelinSecret YAML to stdout.

The output is safe to commit to Git — plaintext is never written anywhere.`,
		Example: `  # Single literal value
  myelin encrypt --name db-creds --namespace prod --from-literal password=s3cr3t

  # Multiple literals
  myelin encrypt --name app-keys --namespace prod \
    --from-literal db_password=abc \
    --from-literal api_key=xyz

  # From a .env file (KEY=VALUE lines)
  myelin encrypt --name app-secrets --namespace staging --from-file .env

  # Using a locally saved public key (no cluster access needed)
  myelin encrypt --name db-creds --namespace prod \
    --from-literal password=s3cr3t --public-key-file ./myelin-pub.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if namespace == "" {
				return fmt.Errorf("--namespace is required")
			}
			if len(literals) == 0 && fromFile == "" {
				return fmt.Errorf("at least one of --from-literal or --from-file is required")
			}

			// Collect plaintext key-value pairs.
			plaintexts := map[string]string{}
			for _, lit := range literals {
				k, v, ok := strings.Cut(lit, "=")
				if !ok {
					return fmt.Errorf("invalid --from-literal %q: expected key=value", lit)
				}
				plaintexts[k] = v
			}
			if fromFile != "" {
				pairs, err := parseEnvFile(fromFile)
				if err != nil {
					return fmt.Errorf("read --from-file %q: %w", fromFile, err)
				}
				for k, v := range pairs {
					plaintexts[k] = v
				}
			}

			// Obtain the operator public key.
			var pubKeyPEM []byte
			if pubKeyFile != "" {
				data, err := os.ReadFile(pubKeyFile)
				if err != nil {
					return fmt.Errorf("read --public-key-file: %w", err)
				}
				pubKeyPEM = data
			} else {
				kc, err := kubeclient.New()
				if err != nil {
					return fmt.Errorf("build kube client: %w", err)
				}
				pubKeyPEM, err = kc.PublicKeyPEM(context.Background(), keySecretName, keySecretNS)
				if err != nil {
					return fmt.Errorf("fetch operator public key: %w\n\nTip: save it locally with: myelin pubkey > myelin-pub.pem", err)
				}
			}

			pubKey, err := crypto.DecodePublicKeyPEM(pubKeyPEM)
			if err != nil {
				return fmt.Errorf("decode public key: %w", err)
			}

			// Encrypt each value.
			label := crypto.Label(name, namespace)
			encryptedData := make(map[string]string, len(plaintexts))
			for k, v := range plaintexts {
				enc, err := crypto.Encrypt(pubKey, []byte(v), label)
				if err != nil {
					return fmt.Errorf("encrypt key %q: %w", k, err)
				}
				encryptedData[k] = enc
			}

			// Emit MyelinSecret YAML.
			ms := &myelinv1alpha1.MyelinSecret{
				TypeMeta: metav1.TypeMeta{
					APIVersion: myelinv1alpha1.GroupVersion.String(),
					Kind:       "MyelinSecret",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: myelinv1alpha1.MyelinSecretSpec{
					EncryptedData: encryptedData,
				},
			}

			out, err := yaml.Marshal(ms)
			if err != nil {
				return fmt.Errorf("marshal yaml: %w", err)
			}

			fmt.Print(string(out))
			fmt.Fprintln(os.Stderr, "\n# Apply with: kubectl apply -f <file> or pipe directly:")
			fmt.Fprintln(os.Stderr, "# myelin encrypt ... | kubectl apply -f -")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Name for the MyelinSecret (required)")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Namespace for the MyelinSecret (required)")
	cmd.Flags().StringArrayVar(&literals, "from-literal", nil, "key=value pair to encrypt (repeatable)")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "Path to a .env file with KEY=VALUE lines")
	cmd.Flags().StringVar(&keySecretName, "key-secret-name", "myelin-operator-key", "Name of the operator key Secret")
	cmd.Flags().StringVar(&keySecretNS, "key-secret-namespace", "myelin-system", "Namespace of the operator key Secret")
	cmd.Flags().StringVar(&pubKeyFile, "public-key-file", "", "Path to a local PEM public key (skips cluster lookup)")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("namespace")

	return cmd
}

// parseEnvFile reads KEY=VALUE lines from an env file, ignoring comments and blank lines.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := map[string]string{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE, got %q", lineNo, line)
		}
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result, scanner.Err()
}
