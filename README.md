# Myelin — Secure Secret Access & Lifecycle for Kubernetes

> Declarative secret access intent, automatically enforced as Kubernetes RBAC.

[![CI](https://github.com/akashbhujbalwebsite/myelin/actions/workflows/ci.yaml/badge.svg)](https://github.com/akashbhujbalwebsite/myelin/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What problem does Myelin solve?

After a secret lands in Kubernetes, someone still has to manually write a `Role` and `RoleBinding` to control who can read it. This is tedious, error-prone, and drifts over time.

**Myelin fills that gap:** declare who should have access to a secret in a single CRD, and the operator continuously reconciles that intent into Kubernetes RBAC — no Vault required, ciphertext is safe to Git-commit, no approval workflow.

## How it works

```
myelin encrypt --name db-creds --namespace prod --from-literal password=s3cr3t
       ↓
MyelinSecret (encrypted, safe to Git-commit)
MyelinSecretPolicy (declares who gets access)
       ↓
Myelin Operator
  → decrypts MyelinSecret → creates k8s Secret
  → reads MyelinSecretPolicy → creates Role + RoleBinding (scoped via resourceNames)
  → reconciles continuously — drift is corrected automatically
```

## Quick start

### Install the CLI

Download the latest `myelin` binary from the [Releases page](https://github.com/akashbhujbalwebsite/myelin/releases/latest) and place it on your `$PATH`, or build from source:

```bash
git clone https://github.com/akashbhujbalwebsite/myelin.git
cd myelin
go install ./cmd/myelin
```

### Install the operator

```bash
kubectl apply -f https://github.com/akashbhujbalwebsite/myelin/releases/latest/download/install.yaml
```

### Encrypt and apply a secret

```bash
# Save the operator public key locally (no cluster writes needed after this)
myelin pubkey > myelin-pub.pem

# Encrypt — plaintext never leaves your machine
myelin encrypt \
  --name db-creds \
  --namespace prod \
  --from-literal password=supersecret \
  --public-key-file ./myelin-pub.pem | kubectl apply -f -

# Declare access policy
kubectl apply -f - <<EOF
apiVersion: myelin.myelin.io/v1alpha1
kind: MyelinSecretPolicy
metadata:
  name: db-creds-policy
  namespace: prod
spec:
  secretRef:
    name: db-creds
  subjects:
    - kind: ServiceAccount
      name: api-server
      namespace: prod
  permissions:
    verbs: ["get"]
EOF

# Verify scoping
kubectl auth can-i get secret/db-creds \
  --as=system:serviceaccount:prod:api-server -n prod
# yes

kubectl auth can-i list secrets \
  --as=system:serviceaccount:prod:api-server -n prod
# no  ← scoped to exactly one secret
```

## Encryption scheme

Myelin uses **hybrid envelope encryption** — the encryption scheme does not impose an RSA plaintext-size limit; large values are encrypted with AES-256-GCM and only the AES key is RSA-wrapped:

1. A fresh **AES-256** key is generated per encryption (`crypto/rand`).
2. The secret value is encrypted with **AES-256-GCM** (authenticated encryption — tampering is detected).
3. The AES key is wrapped with **RSA-4096-OAEP** (SHA-256).
4. The OAEP label (`namespace/name`) is also used as GCM additional authenticated data (AAD), binding the ciphertext to this specific secret identity at both layers.

The encrypted blob is base64-encoded and stored in `spec.encryptedData`. The operator's private key never leaves the cluster.

## Prior art & comparison

Several tools address overlapping or adjacent problems. Myelin focuses on a specific combination of these capabilities:

| Capability | Sealed Secrets | ESO | KubeVault SAR | access-manager | **Myelin** |
|---|---|---|---|---|---|
| Git-safe client-side encryption | ✅ | ❌ | ❌ | ❌ | ✅ |
| No Vault dependency | ✅ | ⚠️ | ❌ * | ✅ | ✅ |
| Declarative per-secret RBAC | ❌ | ❌ | ✅ | ⚠️ | ✅ |
| Continuous reconciliation of generated per-secret RBAC | ❌ | ❌ | ⚠️ | ⚠️ | ✅ |
| No approval workflow required | ✅ | ✅ | ❌ | ✅ | ✅ |

\* KubeVault's `SecretAccessRequest` flow uses Vault-backed secret engines.

ESO primarily synchronizes secrets from external providers; it also supports Kubernetes as a provider but does not generate per-secret RBAC.

access-manager reconciles RBAC definitions cluster-wide but is not scoped to individual secrets via `resourceNames`. **Note: access-manager was archived on December 8, 2025 and is no longer maintained.**

**Myelin's proposed differentiation** is the combination of Git-safe client-side encryption, no Vault dependency, declarative per-secret RBAC, and continuous reconciliation of the RBAC generated from that policy. No tool in the comparison above provides this exact combination based on the documented capabilities reviewed. This is a fast-moving ecosystem, so the comparison should be revalidated as projects evolve.

## Threat model

### What Myelin protects against

| Threat | Protection |
|---|---|
| Plaintext secrets committed to Git | Encrypted CRD is safe to commit |
| Overly broad RBAC (all secrets in namespace) | `resourceNames` scopes Role to exactly one secret |
| Policy drift (RBAC manually widened) | Operator corrects it back on every reconcile |
| Ciphertext reuse across secrets | OAEP label + GCM AAD bind ciphertext to `namespace/name` |
| Ciphertext tampering | AES-GCM authentication tag detects any modification |

### What Myelin does NOT protect against

- **Plaintext briefly in memory**: decrypted values exist in the controller's memory during reconciliation, and on the CLI before encryption. This is unavoidable and intentionally documented.
- **Cluster-admin access**: a user with `cluster-admin` or direct `secrets:get` on the namespace can read the generated Secret regardless of Myelin policy.
- **Workload-level enforcement**: Myelin controls Kubernetes API access to the Secret. It does not prevent a pod that already has the secret mounted from reading it after policy is changed. Workload-level enforcement is outside V1 scope; admission policy and webhooks are a possible future direction.
- **Key store compromise**: if the `myelin-operator-key` Secret in `myelin-system` is compromised, all encrypted secrets can be decrypted. Protect this secret accordingly.

## Key rotation

Myelin uses a single operator key pair stored in the `myelin-operator-key` Secret in `myelin-system`.

**Rotating the key:**
1. Generate a new key pair and update `myelin-operator-key`.
2. Re-encrypt all `MyelinSecret` objects: `myelin encrypt ... | kubectl apply -f -` for each.
3. After the operator is restarted with the new key, it reconciles using the new key.

Old `MyelinSecret` objects encrypted with the previous key will set `Ready=False` (reason: `DecryptFailed`) until re-encrypted. Multi-key rotation support is planned for V2.

## CRDs

### MyelinSecret

```yaml
apiVersion: myelin.myelin.io/v1alpha1
kind: MyelinSecret
metadata:
  name: db-creds
  namespace: prod
spec:
  encryptedData:
    password: "<base64 hybrid ciphertext>"
  template:
    type: Opaque
```

### MyelinSecretPolicy

```yaml
apiVersion: myelin.myelin.io/v1alpha1
kind: MyelinSecretPolicy
metadata:
  name: db-creds-policy
  namespace: prod
spec:
  secretRef:
    name: db-creds
  subjects:
    - kind: ServiceAccount
      name: api-server
      namespace: prod
  permissions:
    verbs: ["get"]    # only "get" and "watch" allowed (enforced at admission)
```

> **Note on `list`:** Kubernetes `resourceNames` scoping does not apply to `list` — it is intentionally excluded from allowed verbs.

## Roadmap

| Version | Goal |
|---|---|
| **V1** (now) | Single-cluster operator, CLI, continuous RBAC reconciliation |
| V1.1 | Admission webhook: block direct `kubectl create secret` |
| V2 | Secret expiry, rotation, namespace replication |
| V3 | OpenShift validation, multi-cluster sync |
| V4 | External store integrations (AWS SM, Azure KV, Vault) |
| V5 | Broader policy/lifecycle control plane |

## License

Apache 2.0 — see [LICENSE](LICENSE).
