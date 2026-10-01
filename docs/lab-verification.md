# Workspace implementation verification

Verified on 2026-09-24, native Linux x86-64. This record describes software checks, **not a DDoS experiment or proof of detection accuracy**.

- `make check`: 86 tests passed, 91.05% measured Python coverage; formatting, Ruff, strict mypy, shell syntax and topology JSON checks passed. Existing exclusions for the root-dependent Ryu app and legacy topology remain unchanged; new runtime boundaries are mocked, not excluded.
- Browser production build and four Playwright tests passed: graph visibility/dragging/editing, rejected imports, timestamp-ordered replay/packet expansion/export/draft preservation, and active-run restoration during a slow preset load. Screenshots were inspected locally; generated screenshots/traces are ignored.
- `npm audit --omit=dev`: no reported vulnerabilities at verification time. This does not cover legacy Python or OS dependencies.
- All three Dockerfiles built successfully. Nonprivileged containers with networking disabled verified Mininet/Ryu imports, Ryu's loopback-listener option, inference imports without a model, and availability of all selected TShark fields. Observed runner versions: Mininet 2.3.0, OVS 2.17.12, Ryu 4.34, runtime Python 3.10.12 and separate Ryu Python 3.9.23.
- Compose configuration validated with dummy credentials, without printing or changing the real `.env`.
- Five-axis review (correctness, readability, architecture, security, performance) completed, including an independent review. Findings fixed included Mininet subprocess detachment, independent traffic deadlines, cleanup after errors, loopback-only OpenFlow, MiniEdit numeric compatibility, replay ordering and editor-state preservation. Final review verdict: approve, with the live-test limitation below.

Not performed: database migration against the user's running PostgreSQL instance, loading a model, loading host kernel modules, starting a privileged Mininet network, or generating attack traffic. The existing database/container and the user's configurable PostgreSQL host-port change were preserved.

The [isolated-VM smoke-test checklist](lab-workspace.md#verification-and-release-gate) is still required before live container integration is considered verified. Legacy/EOL Ryu dependencies, best-effort telemetry, and the privileged shared-kernel runner remain documented risks. The frontend build also reports a non-blocking bundle-size warning; the generated main bundle is approximately 308 KiB gzipped.
