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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MyelinSecretConditionType describes the type of a MyelinSecret condition.
type MyelinSecretConditionType string

const (
	// MyelinSecretConditionReady means the Secret has been decrypted and created successfully.
	MyelinSecretConditionReady MyelinSecretConditionType = "Ready"
)

const (
	// ReasonDecryptFailed is set when the operator cannot decrypt encryptedData.
	ReasonDecryptFailed = "DecryptFailed"
	// ReasonSecretSynced is set when the underlying Secret is up to date.
	ReasonSecretSynced = "SecretSynced"
	// ReasonSecretSyncFailed is set when the underlying Secret could not be created or updated.
	ReasonSecretSyncFailed = "SecretSyncFailed"
)

// SecretTemplateSpec defines metadata to apply to the generated Secret.
type SecretTemplateSpec struct {
	// Labels to add to the generated Secret.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to add to the generated Secret.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Type of the Secret. Defaults to Opaque.
	// +optional
	// +kubebuilder:default=Opaque
	Type corev1.SecretType `json:"type,omitempty"`
}

// MyelinSecretSpec defines the desired state of MyelinSecret.
type MyelinSecretSpec struct {
	// EncryptedData holds per-key RSA+OAEP encrypted values, base64-encoded.
	// Encrypt using: securectl encrypt --name <secret-name> --namespace <ns>
	// +kubebuilder:validation:MinProperties=1
	EncryptedData map[string]string `json:"encryptedData"`

	// Template defines metadata for the generated Secret.
	// +optional
	Template SecretTemplateSpec `json:"template,omitempty"`
}

// MyelinSecretStatus defines the observed state of MyelinSecret.
type MyelinSecretStatus struct {
	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SecretName is the name of the generated Kubernetes Secret (always matches MyelinSecret name).
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// LastSyncTime is when the Secret was last successfully updated.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Conditions reflect the current state of the MyelinSecret.
	// Known condition types: Ready
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ms,categories=myelin
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MyelinSecret holds RSA-encrypted secret data that the Myelin operator
// decrypts and materialises as a standard Kubernetes Secret.
// Plaintext is never stored in this resource — only in the generated Secret
// and momentarily in the controller's memory during decryption.
type MyelinSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MyelinSecretSpec   `json:"spec"`
	Status MyelinSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MyelinSecretList contains a list of MyelinSecret.
type MyelinSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MyelinSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MyelinSecret{}, &MyelinSecretList{})
}
