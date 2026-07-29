# Kali Linux attacker

A Kali Linux VM provisioned with everything an Aurora attack chain needs on the attacker side: Sliver C2 server, Metasploit Framework, Python 3, and our [`attack-executor`](https://pypi.org/project/attack-executor/) PyPI package.

This is the shared attacker used across our shipped emulation environments. Any `envN` in [`../`](../) that lists a Kali attacker in its testbed will point here.

> **In a hurry?** A pre-built OVA is available in [`quick-start/`](quick-start/). Download, import, boot, done in ~10 minutes.

---

## What's inside

- **Sliver C2 server** — pinned binary version, downloaded during provisioning, launched under `tmux`
- **Metasploit Framework** — installed via apt, RPC service launched under `tmux`
- **Python 3** virtualenv with pinned versions of:
  - `attack-executor` — the pip package that drives the `attack_chain.py` wizards
  - `questionary` — interactive CLI prompts
- **`config.ini`** — pre-populated so the `attack_chain.py` wizards find Sliver / Metasploit out of the box

Exact version pins for a given dataset release live in [`COMPATIBILITY.md`](../../../COMPATIBILITY.md) at the repo root.

---

## Install

Boot a fresh Kali Linux VM (4 GB RAM, ~20 GB disk is enough), log in, then run [`attacker-setup.sh`](attacker-setup.sh):

```bash
bash attacker-setup.sh
```

Or, one-shot curl from GitHub (grabs the current version on `main`):

```bash
curl -fsSL https://raw.githubusercontent.com/LexusWang/Aurora-demos/main/environments/attackers/kali/attacker-setup.sh | bash
```

The script installs everything into `~/Aurora-executor/` by default. To use a different location:

```bash
AURORA_EXECUTOR_HOME=/opt/aurora bash attacker-setup.sh
```

After the script finishes, activate the venv:

```bash
source ~/Aurora-executor/env_aurora-executor/bin/activate
```

You're ready to run any chain from [`attacks/`](../../../attacks/) — copy that chain's `attack_chain.py` and `attack_chain.params.yml` over, adjust `LHOST` to this VM's IP, and go.

---

## Version note

The `attacker-setup.sh` in this directory is the current recommended version. If you're reproducing an older dataset release and want the exact setup script we tested against, see [`COMPATIBILITY.md`](../../../COMPATIBILITY.md) — older snapshots will be archived alongside this file as they get superseded.
