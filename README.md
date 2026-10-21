<h1 align="center">ccviaghcp</h1>
<p align="center">Claude Code → a private LiteLLM gateway → GitHub Copilot</p>
<p align="center">A small, single-user AKS reference kit with a manually configured Windows client.</p>

Bring your own authorized account, Azure target, and newly generated private
artifacts. The gateway keeps native Messages, streaming, and tool calls; the
client receives a gateway key, never the server's Copilot OAuth credential.

**This public export has not been cloud-deployed or accepted on Windows.**
Private-lab results do not transfer to a new deployment. This is an independent
project, not endorsed by Microsoft, GitHub, Anthropic, or OpenAI. Use only with
genuine consent, allowed entitlements, and applicable vendor/organization policy.

## Quickstart

From the repository root on Linux, with Python 3.9+ and OpenSSL installed:

```bash
unset CCVIAGHCP_SUBSCRIPTION_ID CCVIAGHCP_TENANT_ID
python3 -m unittest discover -s tests -p test_kit.py -v
python3 -m compileall -q scripts tests
```

These checks need no Azure account or GitHub authorization. The ARM regression
also runs when a standalone `bicep` compiler is on `PATH`. With the pinned Docker
image already available and UID/GID 1000, run the full isolated proxy harness:

```bash
python3 tests/container_offline.py
```

It uses synthetic credentials, `--pull never`, and `--network none`. For a **new
deployment**, follow [setup](docs/setup.md), including explicit target binding,
fresh authorization, and the evidence gates **before paid provisioning**. There
is no package installer or one-command production deployment.

<details>
<summary>What is included?</summary>

- `scripts/`: protected local preparation, scoped deployment, explicit consent,
  native gateway policy, and live smoke checks; host-side Python is stdlib-only.
- `infra/` and `k8s/`: plain Bicep and Kubernetes JSON, with a private workload
  endpoint and an explicitly scoped public Entra management API.
- `windows/`: pinned native CLI bootstrap, masked-key launcher, optional TLS
  diagnostic, and manual acceptance instructions.
- `tests/`: synthetic unit, native proxy wire, and Linux PowerShell checks.

All active source code is included. Retired, unreviewed automation and private
history/artifacts are intentionally excluded with the owner's approval. No
credentials, certificates, deployment inputs, or historical evidence are shipped.

</details>

## Documentation

- [Setup and example topology](docs/setup.md)
- [Security boundaries and operating limits](docs/security.md)
- [Manual Windows setup and native acceptance](windows/README.md)

This is not a highly available service. Azure resources cost money; vendor
allowances and terms still apply. Rotation, renewal, access review, and cleanup
are manual.

---

[MIT licensed](LICENSE) · Copyright © 2026 ccviaghcp contributors.
Vendor binaries and services retain their own licenses and terms.
