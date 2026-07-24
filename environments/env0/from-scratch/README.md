# env0 from-scratch build

Build both env0 VMs yourself, starting from official Microsoft and Kali installation media. Expected time: **60–90 minutes** for a first-time setup, mostly spent waiting for installers and package downloads.

Both VMs are built using scripts we maintain in **separate public repositories** — this keeps the tooling reusable across projects. This README is the road map for stitching them together into env0.

---

## Prerequisites

- A hypervisor that can create x86-64 VMs and expose a host-only network — VirtualBox, VMware Workstation / Fusion, Hyper-V, Parallels, or KVM/libvirt all work
- ~40 GB free disk for both VMs
- 8 GB RAM available to host both VMs concurrently (4 GB victim + 2 GB attacker recommended)
- Host with internet access (for downloading installation media and packages)

---

## Step 1 — Build the victim VM (Windows Server 2022)

We use the [`cyberrange-sphere`](https://github.com/LexusWang/cyberrange-sphere) project to build the base Windows Server 2022 VM. It handles unattended installation, initial account setup (`Administrator`, `useradmin`, `user`), OpenSSH, and VirtualBox Guest Additions.

**Follow the instructions in `cyberrange-sphere/scripts/windows-base/`** — clone the repo, run `build-base-vm.sh`, and after 30–60 minutes you'll have a running Windows Server 2022 VM with all base configuration in place.

### Step 1a — Apply the env0-specific Defender delta

Copy [`env0-defender-disable.ps1`](env0-defender-disable.ps1) to the victim VM (e.g., via the SSH server that `cyberrange-sphere` sets up) and run it once from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File env0-defender-disable.ps1
```

This is the **only env0-specific delta** on top of the `cyberrange-sphere` base image. The script is short (~15 lines) and idempotent — you can run it more than once safely.

---

## Step 2 — Build the attacker VM (Kali Linux)

The attacker VM is a stock Kali installation plus the [`Aurora-executor`](https://github.com/LexusWang/Aurora-executor) toolchain — Sliver, Metasploit, Python 3, and our [`attack-executor`](https://pypi.org/project/attack-executor/) package.

1. Install Kali Linux from an [official ISO](https://www.kali.org/get-kali/) into a new VM (4 GB RAM, ~20 GB disk)
2. Log in and run the one-shot deploy script:

    ```bash
    mkdir -p ~/Aurora-executor && cd ~/Aurora-executor
    curl -fsSL https://raw.githubusercontent.com/LexusWang/Aurora-executor/main/auto_deploy.sh | bash
    ```

The script provisions Sliver, Metasploit, Python dependencies, and `attack-executor`. See the [`Aurora-executor` README](https://github.com/LexusWang/Aurora-executor#readme) for full details, troubleshooting, and per-tool version pinning.

---

## Step 3 — Network the two VMs together

Configure a **host-only adapter** in your hypervisor and attach both VMs to it. In VirtualBox:

```bash
# On the host, create the adapter if you don't have one already
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1

# Then in each VM's settings, add a network adapter of type "Host-only" attached to vboxnet0
```

Once both VMs are on the host-only network, boot them, and verify from the attacker:

```bash
ping <victim-host-only-ip>          # should succeed
```

For hypervisors other than VirtualBox, consult their docs — the principle (an isolated network shared between the two VMs, unreachable from your host's LAN) is the same everywhere.

---

## Done

Head back to [`attacks/v2.0/README.md`](../../../attacks/v2.0/README.md) → *Getting started* → step 2 to pick a chain and run it.
