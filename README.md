# Mini SOC

A hands-on Security Operations Center lab built on Wazuh, focused on detection
engineering, incident response, and end-to-end use case documentation.

## Architecture

- **Mac (192.168.1.7)** — Wazuh manager + indexer + dashboard (Docker Compose)
- **Ubuntu victim (192.168.1.14)** — Wazuh agent ID `001`, sshd exposed
- **Kali attacker (192.168.1.16)** — hydra, nmap, sshpass

All activity is confined to an isolated `192.168.1.0/24` lab network.

## Use cases

| ID | Title | Status | Report |
|---|---|---|---|
| UC-001 | SSH Brute Force → Confirmed Compromise | ✅ Validated | [docs/use-case-ssh-bruteforce-compromise.md](docs/use-case-ssh-bruteforce-compromise.md) |
| UC-002 | Custom detection engineering (Sigma → Wazuh) | 🚧 In progress | — |

## Detection rules

UC-001 relies entirely on Wazuh's built-in ruleset:

- `5710` — invalid-user enumeration
- `5760` — failed auth on valid user
- `2501`, `2502` — PAM session failure counters
- `40111` — sustained authentication failures
- `40112` — **multiple failures followed by a success** (compromise detection)

UC-002 will add custom Sigma-derived rules under `detections/` and `wazuh/`.

## Quick start

```bash
# 1. Deploy Wazuh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.8
cd wazuh-docker/single-node/
docker compose up -d
open https://localhost      # admin / SecretPassword

# 2. Enroll the Ubuntu agent — see docs/use-case-ssh-bruteforce-compromise.md §3.2

# 3. Reproduce the attack — see §5