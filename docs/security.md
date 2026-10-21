# Security boundaries and limits

This is a single-user reference kit, not a production security service or an
official vendor integration. Use only legitimate consent and entitlements within
vendor and organization policy. No free, unlimited, or billing-exempt usage is
promised. Source is [MIT licensed](../LICENSE); vendor binaries/services keep
their own licenses and terms.

**This public export has not been cloud-deployed or accepted on Windows.**
Prior private proof does not transfer. Synthetic tests cannot establish real
entitlement, API compatibility, private routing, Windows trust, or hosting rights.

## Target and operator trust

- `CCVIAGHCP_SUBSCRIPTION_ID` and `CCVIAGHCP_TENANT_ID` are explicit, non-nil UUID
  inputs. Resolution is lazy: importing common code, running the gateway, consent
  helper, or smoke code does not require Azure settings. Invalid-input errors name
  the setting, not its value.
- Every supported Azure wrapper call first checks the same explicitly scoped
  account for exact subscription, tenant, and `Enabled` state. There is no trust
  of an ambient default account or automatic target discovery.
- Azure preparation binds both IDs to protected deployment inputs. Cloud parameter
  generation, deployment, and Kubernetes apply reject missing/changed bindings.
  Local-only preparation with an explicit operator ID and both settings absent
  stays unbound. There is no automatic migration or retargeting.
- Default object-ID discovery requires a CLI user login and compares the decoded
  target-scoped management token tenant to the configured tenant. Token data is
  neither logged nor persisted. Decoding CLI output is not JWT signature validation.
- The operator, host, environment, and owned local files are trusted. Binding
  prevents accidental retargeting; it is not protection against an owner who edits
  the code, environment, or private inputs. Evidence gates check nonempty files;
  humans must ensure those attestations are authentic and current.
- Main Bicep parameters have no expected-target defaults. Actual ARM scope must
  match for resource/module creation; a mismatch may skip deployment rather than
  fail validation. The conditional NAT lookup avoids reading another scope's
  foundation. See the official [conditional deployment semantics](https://learn.microsoft.com/azure/azure-resource-manager/bicep/conditional-resource-deployment).

## Private artifacts and publication

All active source is included. Retired, unreviewed automation and private history
are intentionally excluded with owner approval. No historical deployment evidence,
source-lab fingerprints, credentials, certificates (including public CA bytes),
generated configuration, logs, screenshots, or binaries belong in the public tree.
The ignore rules are defense in depth, **not a substitute for tree/secret review**.

The operator generates a new `.local/` directory for each independent deployment:
0700 directories, owned regular files at 0600, no symlink reads, and exclusive
creation to avoid silent rotation. Keep deployment inputs, parameter files,
catalogs/selections/config, gate attestations, kubeconfig, and authorization state
private even when a particular file contains no password. Never publish resource
IDs or discovery results as example data.

Three credentials have distinct jobs:

1. VM administrator password: protected local input and secure ARM parameter.
2. Gateway key: client-to-gateway authentication, never upstream Copilot auth.
3. Designated Copilot OAuth grant: server-side only, never given to Windows.

The CA private key never enters Kubernetes or the Windows handoff. Only the server
TLS key/cert, OAuth credential, and gateway key become Kubernetes Secrets. Secret
objects go over kubectl stdin with server-side apply, not command arguments,
intermediate manifests, output, or last-applied annotations. A dedicated kubeconfig
is used; the normal operator kubeconfig is not rewritten. API server FQDN and
certificate presence are checked, but the CA fingerprint is not independently
compared with a second source.

Never scrape credential stores, enable ad hoc credential-bearing debug output, or
disable organization auditing. CLI errors are intentionally redacted. Inspect
failures privately in the intended service, without dumping secure parameters.

## Native request boundary

The image digest, native CLI version, public OAuth client ID, API versions, and
transport selectors are pinned. They are not promises of ongoing vendor support.
No gateway device authorization, token-exchange cache, database, or Redis is added.

The configured `openai/<discovered-Claude-id>` selector uses LiteLLM's native
Messages passthrough in this pinned image; it does **not** translate requests into
OpenAI chat/Responses. The `github_copilot/` exchange path is not used. Discovery
must substantiate enabled policy, native Messages, streaming/tools/adaptive
capabilities, and limits. There is no wildcard, guessed entitlement, stale-catalog
fallback, or implicit newest-model alias. Config caps are at most 200,000 input
and 8,192 output tokens, bounded further by the live catalog.

The existing LiteLLM policy hook rejects non-Messages inference, unlisted models,
body credentials/headers/transport overrides, and passthrough headers. It rebuilds
upstream headers and separates gateway authentication from the designated OAuth
bearer. The exact upstream host is `https://api.enterprise.githubcopilot.com`;
discovery and both streaming/nonstreaming upstream clients refuse redirects.
Native JSON, SSE, tools, adaptive thinking, and supported beta data remain intact.
Unverified cache TTL opt-in is not enabled; optional token counting is not exact
provider billing/tokenization evidence.

Both `disable_background_health_check` per model and
`health_check_skip_disabled_background_models` globally are required at startup.
Thus authenticated `/health` skips these models rather than making an unclassified
provider call. Kubernetes uses provider-free, low-detail HTTPS liveliness/readiness
probes, not inference as a health check.

The launcher enables gateway request-class hints. The policy derives user/agent
classification from the last non-system conversational message and documented
hints; tool-only results, assistant continuations, and background/subagent work
are treated as automated. Trailing system context is preserved. Caller initiator
headers are not trusted. **Hints are not authorization, an adversarial-client
boundary, or proof of vendor billing treatment.** The only per-request audit line
contains bounded `class`/`initiator` vocabulary, never prompts, headers, or tokens.

## Network and TLS

The gateway is one non-root, read-only pod, with all capabilities dropped, no
service-account token, no persistent volume, and one worker. OAuth is loaded into
the process environment from its whole-directory read-only Secret mount; missing
or empty input fails before starting LiteLLM. Local Docker binds loopback only.

The ILB accepts Windows `10.77.1.4/32` on 443 and forwards to pod TLS port 4000.
NetworkPolicy permits that source, cluster DNS, and public TCP443 excluding the
private/link-local/IMDS/platform deny ranges. **This is not FQDN-only egress**.
The public AKS management API uses Entra RBAC and disables local accounts. Control
identity networking rights stay scoped to the VNet; user roles stay at the cluster.

The Windows foundation NSG is deny-only. An operator must review a manual access
path separately; do not open broad RDP, disable NLA/firewalls, or add services to
force a login. Developer Bastion deployment alone is not login/access proof.

A new CA is valid for 365 days; its critical name constraint permits the
`litellm.ccviaghcp.test` DNS subtree, with no subordinate CA. The server certificate is valid
for 90 days. Windows gets only the newly approved public CA through a trusted
handoff. Bootstrap/launcher use per-process trust, **not CurrentUser or LocalMachine
root-store imports**. No TLS/revocation bypass or root-import fallback is allowed.
Verify the handoff's newly computed hashes through an independent trusted channel.

The Windows launcher masks key entry, clears competing provider settings, enables
subprocess scrubbing, and restores the previous environment in `finally`. This is
defense in depth, not same-user process isolation or guaranteed zeroization of
managed strings. Keep the gateway key out of arguments, settings, scripts, Git
helpers, transcripts, and handoff files. Never put the server OAuth grant on Windows.

## Maintenance and costs

- No automated OAuth refresh, secret rotation, certificate renewal, or cleanup is
  implemented. Revocation/entitlement failures require legitimate authorization
  and review, not fabricated caches or bypasses. Existing private files are not
  silently overwritten; incomplete/invalid TLS material stops preparation.
- Renew the server certificate before 90 days and plan CA renewal before 365 days.
  Review trust distribution, replace the intended Kubernetes Secret, restart, and
  repeat live verification. Whole-Secret updates do not replace the process's
  environment; a reviewed restart is also required after credential replacement.
- One pod, Recreate rollout, Free control-plane tier, no autoscaling or durability
  guarantees: this is **not HA**. There are no budget alerts or central telemetry.
- Windows, nodes, disks, NAT/public IP, load balancer, DNS, and traffic incur costs.
  The control-plane tier does not make the deployment free. Vendor usage may also
  consume allowances or incur charges. Review costs and remove resources manually
  when finished; stopping a client or local container does not remove Azure resources.
- Regional/SKU/version availability, quota, licensing, real RDP, private TLS,
  native Windows tools, and real classification/reload behavior require validation
  in the **new** deployment. Never turn a synthetic pass into a live acceptance claim.
