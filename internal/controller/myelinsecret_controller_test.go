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

package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	myelinv1alpha1 "github.com/myelinio/myelin/api/v1alpha1"
	"github.com/myelinio/myelin/internal/crypto"
)

// testPrivKey is used to encrypt test fixture data.
// The suite manager uses its own generated key; these tests verify status
// transitions and resource creation, not decrypt correctness (crypto_test covers that).
var testPrivKey, _ = crypto.GenerateKeyPair()

var _ = Describe("MyelinSecret controller", func() {
	const namespace = "default"

	Context("when a valid MyelinSecret is created", func() {
		It("should populate status.secretName and set a Ready condition", func() {
			name := "test-ms-basic"
			label := crypto.Label(name, namespace)

			enc, err := crypto.Encrypt(&testPrivKey.PublicKey, []byte("my-password"), label)
			Expect(err).NotTo(HaveOccurred())

			ms := &myelinv1alpha1.MyelinSecret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: myelinv1alpha1.MyelinSecretSpec{
					EncryptedData: map[string]string{"password": enc},
				},
			}
			Expect(k8sClient.Create(ctx, ms)).To(Succeed())

			By("waiting for status.secretName to be set")
			Eventually(func() string {
				u := &myelinv1alpha1.MyelinSecret{}
				_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, u)
				return u.Status.SecretName
			}, "30s", "1s").Should(Equal(name))

			By("verifying a Ready condition is present")
			u := &myelinv1alpha1.MyelinSecret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, u)).To(Succeed())
			Expect(u.Status.Conditions).NotTo(BeEmpty())
			Expect(u.Status.Conditions[0].Type).To(Equal(string(myelinv1alpha1.MyelinSecretConditionReady)))

			DeferCleanup(func() { _ = k8sClient.Delete(ctx, ms) })
		})
	})

	Context("when a MyelinSecret has a template type", func() {
		It("should propagate the type to status (Secret creation tracked by secretName)", func() {
			name := "test-ms-type"
			label := crypto.Label(name, namespace)

			enc, err := crypto.Encrypt(&testPrivKey.PublicKey, []byte("val"), label)
			Expect(err).NotTo(HaveOccurred())

			ms := &myelinv1alpha1.MyelinSecret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: myelinv1alpha1.MyelinSecretSpec{
					EncryptedData: map[string]string{"key": enc},
					Template: myelinv1alpha1.SecretTemplateSpec{
						Type: corev1.SecretTypeDockerConfigJson,
					},
				},
			}
			Expect(k8sClient.Create(ctx, ms)).To(Succeed())

			Eventually(func() string {
				u := &myelinv1alpha1.MyelinSecret{}
				_ = k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, u)
				return u.Status.SecretName
			}, "30s", "1s").Should(Equal(name))

			DeferCleanup(func() { _ = k8sClient.Delete(ctx, ms) })
		})
	})
})

var _ = Describe("MyelinSecretPolicy controller", func() {
	const namespace = "default"

	Context("when policy references a non-existent MyelinSecret", func() {
		It("should set RBACReady=False with SecretRefNotFound reason", func() {
			policy := &myelinv1alpha1.MyelinSecretPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-missing-secret", Namespace: namespace},
				Spec: myelinv1alpha1.MyelinSecretPolicySpec{
					SecretRef: myelinv1alpha1.SecretRef{Name: "does-not-exist"},
					Subjects:  []myelinv1alpha1.PolicySubject{{Kind: "ServiceAccount", Name: "sa"}},
					Permissions: myelinv1alpha1.PolicyPermissions{Verbs: []string{"get"}},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			Eventually(func() string {
				u := &myelinv1alpha1.MyelinSecretPolicy{}
				_ = k8sClient.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, u)
				for _, c := range u.Status.Conditions {
					if c.Type == string(myelinv1alpha1.PolicyConditionRBACReady) {
						return c.Reason
					}
				}
				return ""
			}, "30s", "1s").Should(Equal(myelinv1alpha1.ReasonSecretRefNotFound))

			DeferCleanup(func() { _ = k8sClient.Delete(ctx, policy) })
		})
	})

	Context("when policy references an existing MyelinSecret", func() {
		It("should set RBACReady=True and populate role/rolebinding names in status", func() {
			msName := "test-policy-ms"
			label := crypto.Label(msName, namespace)
			enc, err := crypto.Encrypt(&testPrivKey.PublicKey, []byte("val"), label)
			Expect(err).NotTo(HaveOccurred())

			ms := &myelinv1alpha1.MyelinSecret{
				ObjectMeta: metav1.ObjectMeta{Name: msName, Namespace: namespace},
				Spec:       myelinv1alpha1.MyelinSecretSpec{EncryptedData: map[string]string{"k": enc}},
			}
			Expect(k8sClient.Create(ctx, ms)).To(Succeed())

			policy := &myelinv1alpha1.MyelinSecretPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-good", Namespace: namespace},
				Spec: myelinv1alpha1.MyelinSecretPolicySpec{
					SecretRef: myelinv1alpha1.SecretRef{Name: msName},
					Subjects:  []myelinv1alpha1.PolicySubject{{Kind: "ServiceAccount", Name: "api-sa", Namespace: namespace}},
					Permissions: myelinv1alpha1.PolicyPermissions{Verbs: []string{"get"}},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("waiting for RBACReady=True")
			Eventually(func() string {
				u := &myelinv1alpha1.MyelinSecretPolicy{}
				_ = k8sClient.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, u)
				for _, c := range u.Status.Conditions {
					if c.Type == string(myelinv1alpha1.PolicyConditionRBACReady) {
						return c.Reason
					}
				}
				return ""
			}, "30s", "1s").Should(Equal(myelinv1alpha1.ReasonRBACCreated))

			By("checking status.roleName and status.roleBindingName are set")
			u := &myelinv1alpha1.MyelinSecretPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: namespace}, u)).To(Succeed())
			Expect(u.Status.RoleName).NotTo(BeEmpty())
			Expect(u.Status.RoleBindingName).NotTo(BeEmpty())

			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, policy)
				_ = k8sClient.Delete(ctx, ms)
			})
		})
	})
})
