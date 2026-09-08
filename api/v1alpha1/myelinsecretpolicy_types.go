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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyConditionType describes the type of a MyelinSecretPolicy condition.
type PolicyConditionType string

const (
	// PolicyConditionRBACReady means the Role and RoleBinding are in sync with the policy.
	PolicyConditionRBACReady PolicyConditionType = "RBACReady"
)

const (
	// ReasonRBACCreated means Role + RoleBinding were created/updated successfully.
	ReasonRBACCreated = "RBACCreated"
	// ReasonRBACFailed means the operator could not create/update Role or RoleBinding.
	ReasonRBACFailed = "RBACFailed"
	// ReasonSecretRefNotFound means the referenced MyelinSecret does not exist.
	ReasonSecretRefNotFound = "SecretRefNotFound"
)

// SecretRef identifies the MyelinSecret this policy governs.
type SecretRef struct {
	// Name of the MyelinSecret in the same namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// PolicySubject identifies a Kubernetes identity that should be granted access.
type PolicySubject struct {
	// Kind of the subject. Must be ServiceAccount.
	// +kubebuilder:validation:Enum=ServiceAccount
	Kind string `json:"kind"`

	// Name of the ServiceAccount.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the ServiceAccount.
	// If omitted, defaults to the MyelinSecretPolicy namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// PolicyPermissions defines what API verbs the subject is granted on the Secret.
type PolicyPermissions struct {
	// Verbs is the list of allowed verbs on the Secret.
	// Only "get" and "watch" are safe with resourceNames scoping.
	// "list" cannot be scoped per-secret and is intentionally excluded.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum=get;watch
	Verbs []string `json:"verbs"`
}

// MyelinSecretPolicySpec declares which identities may access a Secret and how.
type MyelinSecretPolicySpec struct {
	// SecretRef names the MyelinSecret this policy governs.
	SecretRef SecretRef `json:"secretRef"`

	// Subjects lists the ServiceAccounts that should receive access.
	// +kubebuilder:validation:MinItems=1
	Subjects []PolicySubject `json:"subjects"`

	// Permissions defines the allowed verbs.
	// +kubebuilder:default={verbs:{"get"}}
	Permissions PolicyPermissions `json:"permissions"`
}

// MyelinSecretPolicyStatus defines the observed state of MyelinSecretPolicy.
type MyelinSecretPolicyStatus struct {
	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RoleName is the name of the Role managed by this policy.
	// +optional
	RoleName string `json:"roleName,omitempty"`

	// RoleBindingName is the name of the RoleBinding managed by this policy.
	// +optional
	RoleBindingName string `json:"roleBindingName,omitempty"`

	// LastSyncTime is when the RBAC was last successfully reconciled.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Conditions reflect the current state of the policy.
	// Known condition types: RBACReady
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=msp,categories=myelin
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretRef.name`
// +kubebuilder:printcolumn:name="RBACReady",type=string,JSONPath=`.status.conditions[?(@.type=="RBACReady")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="RBACReady")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MyelinSecretPolicy declares which identities may access a MyelinSecret.
// The operator continuously reconciles this intent into a Role + RoleBinding,
// scoped to the specific Secret via resourceNames.
type MyelinSecretPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MyelinSecretPolicySpec   `json:"spec"`
	Status MyelinSecretPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MyelinSecretPolicyList contains a list of MyelinSecretPolicy.
type MyelinSecretPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MyelinSecretPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MyelinSecretPolicy{}, &MyelinSecretPolicyList{})
}
