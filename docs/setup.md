# Setup

Use a **new deployment**, not private state from another installation. No cloud
deployment or Windows acceptance is claimed for this export. Offline results do
not establish entitlement, connectivity, quota, licensing, or service readiness.

## Prerequisites and offline checks

The operator host is Linux with Python 3.9+, OpenSSL, and owner-only POSIX file
permissions. Deployment additionally needs Azure CLI, Bicep, kubectl, kubelogin,
an approved Azure CLI **user** login, and appropriate deployment/role-assignment
permissions. Docker runners require UID/GID 1000; they fail rather than loosen
secret permissions for another user. No Python dependencies are installed on
the operator host; gateway dependencies come from the pinned LiteLLM image.

```bash
unset CCVIAGHCP_SUBSCRIPTION_ID CCVIAGHCP_TENANT_ID
python3 -m unittest discover -s tests -p test_kit.py -v
python3 -m compileall -q scripts tests
bicep build infra/main.bicep --stdout --no-restore > /dev/null
python3 tests/container_offline.py
```

The standalone compiler needs no Azure login. If using Azure CLI's installed
compiler instead, invoke `az bicep build --file infra/main.bicep --stdout`
directly, **not** through `common.az()`: compiling is local, not an ARM operation.
Use an already installed compiler/image; the offline harness never pulls an image.

Optional Linux PowerShell checks use a preloaded, pinned runtime and fake native
executables, **not Windows/Schannel or native Claude runtime acceptance**:

```bash
for test in windows_launcher.ps1 manual_windows.ps1; do
  docker run --rm --pull never --network none --user 1000:1000 --read-only \
    --cap-drop ALL --security-opt no-new-privileges --env HOME=/tmp \
    --mount "type=bind,source=$PWD/windows,target=/kit/windows,readonly" \
    --mount "type=bind,source=$PWD/tests,target=/kit/tests,readonly" \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=128m \
    --entrypoint pwsh \
    mcr.microsoft.com/dotnet/sdk@sha256:f7e28a0a3f6f9235929ec19274fd0ddf8534e9159f99fac602ac73304f1ce99f \
    -NoLogo -NoProfile -File "/kit/tests/$test"
done
```

The full proxy harness tests strict CA/hostname TLS, authentication failures,
native JSON/SSE/tools, transport/header override rejection, health without provider
calls, redirects, classification, and startup/restart with synthetic credentials.
It publishes no port and mounts no host credential stores. Its temporary data is
synthetic; on failure it may leave a diagnostic log in the platform temporary
directory. Do not substitute a real token into this harness.

## Example topology and pins

These are **public example choices**, not verified availability or licensing
claims. Before spending money, review region, image/SKU/Kubernetes availability,
quota, Windows hosting rights, RBAC, and address overlap for your own deployment.

| Item | Example |
| --- | --- |
| Region / resource group | `swedencentral` / `ccviaghcp-rg` |
| AKS / kube context | `ccviaghcp-aks` |
| AKS-managed node resource group | `ccviaghcp-aks-nodes-rg` (created by AKS) |
| Kubernetes / nodes | `1.36.4`, Base/Free, two `Standard_D4s_v5`, Cilium overlay |
| Windows VM / computer / administrator | `ccviaghcp-windows` / `ccviaghcp-win` / `ccviaghcpuser` |
| Windows SKU | `Standard_D2s_v5`, Windows 11 Enterprise single-session |
| Marketplace image | `MicrosoftWindowsDesktop:windows-11:win11-25h2-ent:26200.9711.261011` |
| VNet / AKS subnet | `10.77.0.0/16` / `10.77.0.0/24` |
| Windows subnet / private NIC | `10.77.1.0/27` / `10.77.1.4` |
| Gateway ILB / DNS | `10.77.0.240` / `litellm.ccviaghcp.test` |
| Private DNS zone / Kubernetes namespace | `ccviaghcp.test` / `ccviaghcp` |
| Pod / service / DNS-service ranges | `10.78.0.0/16` / `10.79.0.0/16` / `10.79.0.10` |
| LiteLLM | `1.106.0`, image digest below |
| Native Claude Code | `2.1.284`, automatic updates disabled by launcher |

```text
ghcr.io/berriai/litellm@sha256:2e4c0371f3a8c28e4da131d77abaa8341cd3b0c2fcc4d34d7c5900431af7b9d0
```

The foundation creates a shared Standard NAT Gateway and outbound-only public IP.
The AKS phase reads **that new foundation's actual NAT address** for its API
allowlist; no public IP is hardcoded. The API allows only the supplied operator
public `/32` and that NAT `/32`. Workload traffic stays on the private ILB.
Windows uses Trusted Launch, Secure Boot, vTPM, and `Windows_Client`; the template
does not establish your hosting rights. Two nodes plus one surge node and the
Windows VM need up to 14 Dsv5-family cores for these example sizes.

## 1. Choose and bind the Azure target

Set **both** known target identifiers explicitly; do not infer them from the
CLI default account. These are inputs, not values provided by this repository:

```bash
read -r -p 'Target subscription UUID: ' CCVIAGHCP_SUBSCRIPTION_ID
read -r -p 'Target tenant UUID: ' CCVIAGHCP_TENANT_ID
export CCVIAGHCP_SUBSCRIPTION_ID CCVIAGHCP_TENANT_ID
read -r -p 'Current operator public IPv4: ' OPERATOR_PUBLIC_IPV4
python3 scripts/lab.py prepare --operator-ip "$OPERATOR_PUBLIC_IPV4"
```

Establish a genuine Azure CLI user login in that tenant before default object-ID
discovery. The helper checks the target-scoped account and decodes its CLI-issued
management token's `tid`/`oid` in memory. It requires a user login, not a service
principal. This is trusted CLI metadata, **not independent JWT verification**.
Alternatively add `--operator-object-id YOUR_ENTRA_USER_OBJECT_UUID` using your
actual user object ID, never an app/client ID.

`prepare` normalizes UUIDs and saves `expectedSubscriptionId` and
`expectedTenantId` in protected `deployment-inputs.json`. Missing, partial,
malformed, empty, or nil target settings fail without invoking Azure. Every
supported `common.az()` call first checks `az account show --subscription` for
the **same explicit subscription**, exact tenant, and `Enabled` state. It never
changes the global Azure account selection.

For **local-only** preparation, leave both variables absent and supply an explicit
operator object ID. An empty variable is not absent. Local-only inputs are unbound
and cannot generate cloud parameters, deploy, or apply Kubernetes resources.
Supplying a target later does **not** upgrade/migrate that state: use a new
independent directory with fresh private inputs. Likewise a changed target or
removed binding is rejected; do not edit/copy state to retarget a deployment.

`.local/` is 0700 and private files are 0600. It contains the VM password, separate
gateway key, new CA/server material, deployment inputs/parameters, designated OAuth
state, model discovery/selection/config, kubeconfig, and private gate attestations.
Creation is exclusive; reruns compare inputs and preserve existing secrets. Review
any mismatch or incomplete material rather than deleting secrets to make a rerun
pass. Never print or commit this directory. Read secrets only through a trusted
local editor/password-manager workflow. The **CA private key stays on this host**.

## 2. Genuine Copilot consent and live selection

Proceed only with permitted vendor/organization policy, a valid entitlement, and
the human's explicit consent. The helper never harvests other tools' credentials.
An already authorized credential may be placed privately in the designated
`.local/access-token` by its owner; otherwise use the split consent flow:

```bash
python3 scripts/copilot_auth.py start
# Human authorizes the displayed code at https://github.com/login/device.
python3 scripts/copilot_auth.py finish
python3 scripts/copilot_auth.py discover
```

`start` prints only the verification URL/user code and exits without polling.
`finish` handles pending, slow-down, denial, and expiry without echoing tokens.
Existing files are not overwritten. A failed/expired flow requires operator review
of only its device-state file before another attempt; never bypass human consent.

Discovery checks entitlement and stores the live catalog privately. Only the exact
GitHub-returned endpoint `https://api.enterprise.githubcopilot.com` is accepted.
It uses the designated OAuth bearer directly, not a legacy token exchange. A
different endpoint, schema, policy, or capability is a stop, not a fallback.

In a trusted local editor, create `.local/selection.json`: a JSON object with
exactly `sonnet`, `opus`, and `haiku` keys, each mapping to an actually discovered,
enabled Claude model ID. Reusing one entitled ID is allowed. Do not copy the test
fixtures as evidence. Each selected entry must advertise native `/v1/messages`,
streaming, tool calls, adaptive thinking, and positive input/output limits.

```bash
chmod 600 .local/selection.json
python3 scripts/lab.py render
python3 scripts/lab.py local
```

The local container runs in the foreground on **127.0.0.1:4000 only**. In another
terminal at the same repository root:

```bash
python3 scripts/smoke.py
# Optional token-count compatibility check, not billing accuracy:
python3 scripts/smoke.py --count-tokens
```

**These are live inference calls and may consume allowance.** Smoke verifies the
generated CA and `litellm.ccviaghcp.test` hostname while connecting to loopback;
it tests native JSON, SSE, AUTO tool results, and missing/wrong authentication.
An unknown key may return the pinned database-free proxy's `400 / No connected
db.` rejection. Do not add a database or weaken authentication to change that code.
Stop the foreground local container with Ctrl-C when finished.

Before either paid create phase, the operator must privately record real,
nonempty, reviewed evidence in these 0600 files:

- `.local/gate-local-smoke.txt`: real smoke success against this kit and selection.
- `.local/gate-review.txt`: independent review and resolution of blocking findings.
- `.local/gate-claude.txt`: actual native Claude Code 2.1.284 invocation against
  this pinned gateway, with strict CA/hostname TLS and no key in arguments.

The pre-deployment native check uses an already approved client. For a local
client, arrange an operator-reviewed hostname route to loopback and port 4000,
use the new CA, and pass credentials privately in the client process; never use a
TLS bypass. No Linux client installer or host DNS modification is automated here.
If a genuine check cannot be performed, stop instead of fabricating its gate.
Attestations contain UTC time, selected IDs/version, result and reviewer context,
not keys or prompt bodies. They are operator attestations, not cryptographic proof.

## 3. Review and deploy in phases

Cloud commands below are **not offline checks**. Confirm authorization, costs,
readiness, and gates first. All parameter generation and Azure operations require
the current environment to match the protected target binding.

```bash
python3 scripts/lab.py infra validate foundation
python3 scripts/lab.py infra what-if foundation
python3 scripts/lab.py infra create foundation
python3 scripts/lab.py infra validate aks
python3 scripts/lab.py infra what-if aks
python3 scripts/lab.py infra create aks
python3 scripts/lab.py apply
```

Review each phase's what-if **before** its create. What-if prints only change type
and resource ID; do not publish those deployment-specific results. Foundation
creates the network, DNS, Windows VM, deny-only NSG, Developer Bastion, and control
identity with Network Contributor on this VNet only. **Manual Windows access is
not enabled by the deny-only template**; it needs separate operator review.

The AKS phase consumes the existing foundation NAT/identity without redeploying
Windows/network resources. Missing foundation state fails; there is no repair or
fallback address. Only specified identity-propagation authorization failures
retry, at most three attempts with 60/120-second waits and no privilege escalation.
The secure VM password remains in protected parameter files for both phases,
though the AKS phase does not use it. Parameters travel by protected `@` file,
never a literal secret argument. No complete-mode or cloud deletion is supplied.

`infra/main.bicep` requires explicit expected subscription/tenant parameters.
Its resource/module conditions prevent creation when actual ARM scope differs.
**A false condition does not necessarily make ARM validation fail**; it can mean
no resources are created. The NAT reference is conditional too. Use the wrappers'
binding/account guards; a successful raw ARM validation is not scope proof.

`apply` checks the binding **before rendering config or touching runtime secrets
or kubeconfig**. It fetches fresh Entra credentials into a dedicated protected
kubeconfig, verifies the API FQDN and TLS CA presence, and sends Kubernetes Secrets
on stdin using server-side apply. NetworkPolicy precedes the pod. Do not use local
admin credentials or a TLS exception when access fails.

## 4. Verify the new private deployment and Windows client

Verify actual AKS nodes/pod readiness, private DNS, ILB frontend and default node
HTTP `/healthz` probes, and VNet-only access. Do not redirect load-balancer probes
to the TLS port or broaden ingress to work around a failure. `smoke.py --private`
needs existing approved VNet access; it performs real inference.

Then follow [manual Windows setup](../windows/README.md). Genuine browser login,
your new public-CA handoff, strict native-client TLS/authentication/model/tool
acceptance, and real classification/restart checks remain your responsibility.
Windows acceptance is **after** backend deployment, not an additional create gate.
See [security and maintenance](security.md) before operating or sharing artifacts.
