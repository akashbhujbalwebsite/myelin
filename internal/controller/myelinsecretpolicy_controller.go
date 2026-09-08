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
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	myelinv1alpha1 "github.com/myelinio/myelin/api/v1alpha1"
)

const policyFinalizer = "myelin.io/policy-finalizer"

// MyelinSecretPolicyReconciler reconciles MyelinSecretPolicy objects.
type MyelinSecretPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecretpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecretpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=myelin.myelin.io,resources=myelinsecretpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

func (r *MyelinSecretPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &myelinv1alpha1.MyelinSecretPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !policy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDeletion(ctx, policy)
	}

	if !controllerutil.ContainsFinalizer(policy, policyFinalizer) {
		controllerutil.AddFinalizer(policy, policyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Verify the referenced MyelinSecret exists.
	ms := &myelinv1alpha1.MyelinSecret{}
	msKey := types.NamespacedName{Name: policy.Spec.SecretRef.Name, Namespace: policy.Namespace}
	if err := r.Get(ctx, msKey, ms); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.setConditionRBACReady(ctx, policy, metav1.ConditionFalse,
				myelinv1alpha1.ReasonSecretRefNotFound,
				fmt.Sprintf("MyelinSecret %q not found in namespace %q", policy.Spec.SecretRef.Name, policy.Namespace))
		}
		return ctrl.Result{}, err
	}

	// Both Role and RoleBinding are named after the policy, not the secret.
	// This prevents ownership conflicts when multiple policies reference the same secret —
	// each policy manages its own independent Role+RoleBinding pair.
	roleName := fmt.Sprintf("myelin-%s", policy.Name)
	roleBindingName := fmt.Sprintf("myelin-%s", policy.Name)

	// Reconcile the Role.
	if err := r.reconcileRole(ctx, policy, roleName); err != nil {
		log.Error(err, "failed to reconcile Role")
		return ctrl.Result{}, r.setConditionRBACReady(ctx, policy, metav1.ConditionFalse,
			myelinv1alpha1.ReasonRBACFailed, err.Error())
	}

	// Reconcile the RoleBinding.
	if err := r.reconcileRoleBinding(ctx, policy, roleName, roleBindingName); err != nil {
		log.Error(err, "failed to reconcile RoleBinding")
		return ctrl.Result{}, r.setConditionRBACReady(ctx, policy, metav1.ConditionFalse,
			myelinv1alpha1.ReasonRBACFailed, err.Error())
	}

	log.Info("RBAC reconciled", "role", roleName, "rolebinding", roleBindingName)

	now := metav1.Now()
	policy.Status.RoleName = roleName
	policy.Status.RoleBindingName = roleBindingName
	policy.Status.LastSyncTime = &now
	return ctrl.Result{}, r.setConditionRBACReady(ctx, policy, metav1.ConditionTrue,
		myelinv1alpha1.ReasonRBACCreated, "Role and RoleBinding are in sync")
}

// reconcileRole creates or updates the Role that grants access to the specific Secret.
// We use resourceNames to scope the Role to only the target secret.
// IMPORTANT: only "get" and "watch" work correctly with resourceNames.
// "list" cannot be scoped per-resource and is intentionally excluded.
// "create" with resourceNames is broken upstream (k8s issue) — never include it.
func (r *MyelinSecretPolicyReconciler) reconcileRole(ctx context.Context, policy *myelinv1alpha1.MyelinSecretPolicy, roleName string) error {
	desired := r.buildRole(policy, roleName)

	existing := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Name: roleName, Namespace: policy.Namespace}, existing)
	if apierrors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(policy, desired, r.Scheme); err != nil {
			return err
		}
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	// Always overwrite Rules entirely — ensures a manually widened rule
	// (e.g. removed ResourceNames) is corrected back to the declared policy.
	existing.Rules = desired.Rules
	existing.Labels = desired.Labels
	return r.Update(ctx, existing)
}

func (r *MyelinSecretPolicyReconciler) buildRole(policy *myelinv1alpha1.MyelinSecretPolicy, roleName string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: policy.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "myelin",
				"myelin.io/policy":             policy.Name,
				"myelin.io/secret":             policy.Spec.SecretRef.Name,
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{policy.Spec.SecretRef.Name},
				Verbs:         policy.Spec.Permissions.Verbs,
			},
		},
	}
}

// reconcileRoleBinding creates or updates the RoleBinding that binds the Role to all subjects.
func (r *MyelinSecretPolicyReconciler) reconcileRoleBinding(ctx context.Context, policy *myelinv1alpha1.MyelinSecretPolicy, roleName, roleBindingName string) error {
	desired := r.buildRoleBinding(policy, roleName, roleBindingName)

	existing := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Name: roleBindingName, Namespace: policy.Namespace}, existing)
	if apierrors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(policy, desired, r.Scheme); err != nil {
			return err
		}
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	existing.Subjects = desired.Subjects
	existing.RoleRef = desired.RoleRef
	return r.Update(ctx, existing)
}

func (r *MyelinSecretPolicyReconciler) buildRoleBinding(policy *myelinv1alpha1.MyelinSecretPolicy, roleName, roleBindingName string) *rbacv1.RoleBinding {
	subjects := make([]rbacv1.Subject, 0, len(policy.Spec.Subjects))
	for _, s := range policy.Spec.Subjects {
		ns := s.Namespace
		if ns == "" {
			ns = policy.Namespace
		}
		subjects = append(subjects, rbacv1.Subject{
			Kind:      s.Kind,
			Name:      s.Name,
			Namespace: ns,
		})
	}

	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: policy.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "myelin",
				"myelin.io/policy":             policy.Name,
				"myelin.io/secret":             policy.Spec.SecretRef.Name,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
		Subjects: subjects,
	}
}

func (r *MyelinSecretPolicyReconciler) handleDeletion(ctx context.Context, policy *myelinv1alpha1.MyelinSecretPolicy) error {
	if controllerutil.ContainsFinalizer(policy, policyFinalizer) {
		// Role and RoleBinding are garbage-collected via OwnerReference.
		controllerutil.RemoveFinalizer(policy, policyFinalizer)
		return r.Update(ctx, policy)
	}
	return nil
}

func (r *MyelinSecretPolicyReconciler) setConditionRBACReady(ctx context.Context, policy *myelinv1alpha1.MyelinSecretPolicy, status metav1.ConditionStatus, reason, msg string) error {
	policy.Status.ObservedGeneration = policy.Generation
	cond := metav1.Condition{
		Type:               string(myelinv1alpha1.PolicyConditionRBACReady),
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: policy.Generation,
	}
	found := false
	for i, c := range policy.Status.Conditions {
		if c.Type == cond.Type {
			if c.Status != cond.Status {
				cond.LastTransitionTime = metav1.Now()
			} else {
				cond.LastTransitionTime = c.LastTransitionTime
			}
			policy.Status.Conditions[i] = cond
			found = true
			break
		}
	}
	if !found {
		cond.LastTransitionTime = metav1.Now()
		policy.Status.Conditions = append(policy.Status.Conditions, cond)
	}
	return r.Status().Update(ctx, policy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *MyelinSecretPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&myelinv1alpha1.MyelinSecretPolicy{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Named("myelinsecretpolicy").
		Complete(r)
}
