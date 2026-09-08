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

// Package cli implements the myelin command-line tool.
package cli

import (
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// NewRootCmd builds the root cobra command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "myelin",
		Short: "Myelin — Secure Secret Access & Lifecycle for Kubernetes",
		Long: `myelin is the CLI for the Myelin operator.

It encrypts secrets locally using the operator's public key so that
plaintext never leaves your machine or appears in any Kubernetes resource.

Examples:
  # Encrypt a literal value and emit a MyelinSecret manifest
  myelin encrypt --name db-creds --namespace prod --from-literal password=supersecret

  # Encrypt all values from a .env file
  myelin encrypt --name app-secrets --namespace prod --from-file .env

  # Fetch the operator public key (useful for offline encryption)
  myelin pubkey

  # Show version
  myelin version`,
		SilenceUsage: true,
	}

	root.AddCommand(
		newEncryptCmd(),
		newPubkeyCmd(),
		newVersionCmd(),
	)
	return root
}
