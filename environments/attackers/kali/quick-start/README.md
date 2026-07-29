# Kali attacker quick-start — pre-built OVA

Download the Kali attacker OVA, import, boot, and re-run `attacker-setup.sh` once to relaunch the C2 services. About 10 minutes total.

---

## Download

```bash
cd ~/Downloads
wget https://huggingface.co/datasets/LexusWang/aurora-demos-envs/resolve/main/kali-attacker.ova
wget https://huggingface.co/datasets/LexusWang/aurora-demos-envs/resolve/main/kali-attacker.ova.sha256

# Verify integrity
shasum -a 256 -c kali-attacker.ova.sha256    # macOS
# or on Linux:
sha256sum -c kali-attacker.ova.sha256
```

Expected output: `kali-attacker.ova: OK`

---

## Import (VirtualBox example)

```bash
VBoxManage import kali-attacker.ova
```

For other hypervisors, use their GUI's *File → Import* menu.

**Networking:** The network configuration depends on the requirements of specific attack emulation environments (See section in [`../../env0/quick-start/README.md`](../../env0/quick-start/README.md) as an example).

---

## First boot

Log in as `kali` / `kali` (default Kali credentials).

**One post-boot step: relaunch the Sliver + Metasploit services.** They live in tmux sessions that don't survive a VM shutdown, so re-run the setup script — it's idempotent, so with everything already installed it just re-launches the tmux sessions in ~30 seconds:

```bash
bash ~/Aurora-executor/attacker-setup.sh
```

You'll see the same output as a fresh install but the apt/pip steps skip (all "already installed"), and the tmux `msf` + `sliver` sessions come back up.

Then activate the venv:

```bash
source ~/Aurora-executor/env_aurora-executor/bin/activate
```

You're ready to run any chain from [`../../../attacks/`](../../../attacks/).

---

## What's in this OVA

See [`../README.md`](../README.md) for the full inventory:
- Kali Linux 2025.3
- Sliver C2 server (v1.7.2) + Metasploit Framework
- Python venv with `attack-executor==0.3.0` + `questionary==2.1.0`
- `config.ini` + `zer0cool.cfg` pre-populated for env0

For the exact `attacker-setup.sh` version bundled in this OVA, see [`COMPATIBILITY.md`](../../../../COMPATIBILITY.md) at the repo root.
