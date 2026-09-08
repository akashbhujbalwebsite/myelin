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
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/myelinio/myelin/internal/kubeclient"
)

func newPubkeyCmd() *cobra.Command {
	var keySecretName string
	var keySecretNS string

	cmd := &cobra.Command{
		Use:   "pubkey",
		Short: "Print the operator's RSA public key in PEM format",
		Long: `Fetch and print the Myelin operator's RSA public key.

Save it locally to encrypt secrets without cluster access:
  myelin pubkey > myelin-pub.pem
  myelin encrypt --name db-creds --namespace prod \
    --from-literal password=s3cr3t --public-key-file ./myelin-pub.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := kubeclient.New()
			if err != nil {
				return fmt.Errorf("build kube client: %w", err)
			}
			pem, err := kc.PublicKeyPEM(context.Background(), keySecretName, keySecretNS)
			if err != nil {
				return fmt.Errorf("fetch public key: %w", err)
			}
			fmt.Print(string(pem))
			return nil
		},
	}

	cmd.Flags().StringVar(&keySecretName, "key-secret-name", "myelin-operator-key", "Name of the operator key Secret")
	cmd.Flags().StringVar(&keySecretNS, "key-secret-namespace", "myelin-system", "Namespace of the operator key Secret")

	return cmd
}
