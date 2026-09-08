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
	"context"
	"crypto/rsa"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	myelinv1alpha1 "github.com/myelinio/myelin/api/v1alpha1"
	"github.com/myelinio/myelin/internal/crypto"
)

const myelinSecretFinalizer = "myelin.io/secret-finalizer"

// MyelinSecretReconciler reconciles MyelinSecret objects.
type MyelinSecretReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	PrivateKey *rsa.PrivateKey
}

// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *MyelinSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	ms := &myelinv1alpha1.MyelinSecret{}
	if err := r.Get(ctx, req.NamespacedName, ms); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion via finalizer so the managed Secret is cleaned up.
	if !ms.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, ms)
	}

	if !controllerutil.ContainsFinalizer(ms, myelinSecretFinalizer) {
		controllerutil.AddFinalizer(ms, myelinSecretFinalizer)
		if err := r.Update(ctx, ms); err != nil {
			return ctrl.Result{}, err
		}
		// Return here — the Update bumps resourceVersion; continuing with a stale
		// object causes a 409 on Status().Update(). The object change auto-requeues.
		return ctrl.Result{}, nil
	}

	// Decrypt all keys.
	label := crypto.Label(ms.Name, ms.Namespace)
	decrypted := make(map[string][]byte, len(ms.Spec.EncryptedData))
	for key, ciphertext := range ms.Spec.EncryptedData {
		plaintext, err := crypto.Decrypt(r.PrivateKey, ciphertext, label)
		if err != nil {
			log.Error(err, "failed to decrypt key", "key", key)
			return ctrl.Result{}, r.setConditionReady(ctx, ms, metav1.ConditionFalse,
				myelinv1alpha1.ReasonDecryptFailed,
				fmt.Sprintf("failed to decrypt key %q: %v", key, err))
		}
		decrypted[key] = plaintext
	}

	// Create or update the managed Secret.
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: ms.Name, Namespace: ms.Namespace}, secret)
	if apierrors.IsNotFound(err) {
		secret = r.buildSecret(ms, decrypted)
		if err := controllerutil.SetControllerReference(ms, secret, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, secret); err != nil {
			log.Error(err, "failed to create Secret", "secret", ms.Name)
			return ctrl.Result{}, r.setConditionReady(ctx, ms, metav1.ConditionFalse,
				myelinv1alpha1.ReasonSecretSyncFailed, err.Error())
		}
		log.Info("created Secret", "secret", secret.Name)
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		// Update data in-place; preserve existing labels/annotations not managed by us.
		secret.Data = decrypted
		if ms.Spec.Template.Type != "" {
			secret.Type = ms.Spec.Template.Type
		}
		if err := r.Update(ctx, secret); err != nil {
			return ctrl.Result{}, r.setConditionReady(ctx, ms, metav1.ConditionFalse,
				myelinv1alpha1.ReasonSecretSyncFailed, err.Error())
		}
		log.Info("updated Secret", "secret", secret.Name)
	}

	now := metav1.Now()
	ms.Status.SecretName = ms.Name
	ms.Status.LastSyncTime = &now
	return ctrl.Result{}, r.setConditionReady(ctx, ms, metav1.ConditionTrue,
		myelinv1alpha1.ReasonSecretSynced, "secret synced successfully")
}

func (r *MyelinSecretReconciler) buildSecret(ms *myelinv1alpha1.MyelinSecret, data map[string][]byte) *corev1.Secret {
	secretType := corev1.SecretTypeOpaque
	if ms.Spec.Template.Type != "" {
		secretType = ms.Spec.Template.Type
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ms.Name,
			Namespace:   ms.Namespace,
			Labels:      ms.Spec.Template.Labels,
			Annotations: ms.Spec.Template.Annotations,
		},
		Type: secretType,
		Data: data,
	}
}

func (r *MyelinSecretReconciler) handleDeletion(ctx context.Context, ms *myelinv1alpha1.MyelinSecret) error {
	if controllerutil.ContainsFinalizer(ms, myelinSecretFinalizer) {
		// The managed Secret is already garbage-collected via OwnerReference.
		controllerutil.RemoveFinalizer(ms, myelinSecretFinalizer)
		return r.Update(ctx, ms)
	}
	return nil
}

// setConditionReady updates the Ready condition and patches status.
func (r *MyelinSecretReconciler) setConditionReady(ctx context.Context, ms *myelinv1alpha1.MyelinSecret, status metav1.ConditionStatus, reason, msg string) error {
	ms.Status.ObservedGeneration = ms.Generation
	cond := metav1.Condition{
		Type:               string(myelinv1alpha1.MyelinSecretConditionReady),
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ms.Generation,
	}
	// Replace or append the condition.
	found := false
	for i, c := range ms.Status.Conditions {
		if c.Type == cond.Type {
			if c.Status != cond.Status {
				cond.LastTransitionTime = metav1.Now()
			} else {
				cond.LastTransitionTime = c.LastTransitionTime
			}
			ms.Status.Conditions[i] = cond
			found = true
			break
		}
	}
	if !found {
		cond.LastTransitionTime = metav1.Now()
		ms.Status.Conditions = append(ms.Status.Conditions, cond)
	}
	return r.Status().Update(ctx, ms)
}

// SetupWithManager sets up the controller with the Manager.
func (r *MyelinSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myelinv1alpha1.MyelinSecret{}).
		Owns(&corev1.Secret{}).
		Named("myelinsecret").
		Complete(r)
}
