# Impact IQ — Teams surface (Custom Engine Agent)

This folder is the **thin Microsoft 365 Copilot Custom Engine Agent** that puts Impact IQ in Microsoft Teams. It is intentionally minimal: it owns the conversation, signs the user in (Microsoft Entra **On-Behalf-Of**), renders **Adaptive Cards**, and **forwards every turn to the Python FastAPI bridge** — which is where all analysis, the safety gates, and the audit chain live. There is no analysis logic here.

Built with the [Microsoft 365 Agents Toolkit](https://aka.ms/teams-toolkit) on the [Microsoft 365 Agents SDK](https://github.com/Microsoft/Agents).

## Layout

| Path | Contents |
|---|---|
| `src/` | the surface: `index.ts` (server) and `config.ts` (env). Turn handling, OBO sign-in, and card actions live alongside. |
| `appPackage/` | Teams app manifest + icons |
| `infra/` | Bicep for the Azure Bot + hosting |
| `env/` | per-environment Agents Toolkit config (secrets gitignored) |
| `m365agents*.yml` | Microsoft 365 Agents Toolkit project files |

## Configuration

`src/config.ts` reads:

- `IMPACTIQ_BRIDGE_URL` — the FastAPI bridge endpoint to forward turns to
- `IMPACTIQ_BRIDGE_KEY` — shared secret sent as the `X-ImpactIQ-Key` header
- `IMPACTIQ_OAUTH_CONNECTION_NAME` — the Azure Bot OAuth connection used for the On-Behalf-Of sign-in

## Run / deploy

Provision, deploy, and publish with the **Microsoft 365 Agents Toolkit** (VS Code extension or CLI). The surface needs the bridge running and reachable at `IMPACTIQ_BRIDGE_URL`.

For the full system design, see the repo root [`README.md`](../README.md) and [`ARCHITECTURE.md`](../ARCHITECTURE.md).
