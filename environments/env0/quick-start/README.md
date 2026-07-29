# env0 quick-start — pre-built OVAs

Download two OVAs, import into your hypervisor, boot. About 15 minutes total.

env0 is a pair of VMs, a Windows victim (this directory) and a Kali attacker. Both are hosted on Hugging Face Datasets for fast download.

---

## Download

**Victim VM — Windows Server 2022 Evaluation (6.6 GB compressed):**

```bash
cd ~/Downloads   # or wherever you want to keep the OVA
wget https://huggingface.co/datasets/LexusWang/aurora-demos-envs/resolve/main/env0-victim-windows-server-2022.ova
wget https://huggingface.co/datasets/LexusWang/aurora-demos-envs/resolve/main/env0-victim-windows-server-2022.ova.sha256

# Verify integrity
shasum -a 256 -c env0-victim-windows-server-2022.ova.sha256    # macOS
# or on Linux:
sha256sum -c env0-victim-windows-server-2022.ova.sha256
```

Expected output: `env0-victim-windows-server-2022.ova: OK`

**Attacker VM — Kali Linux (7.4 GB compressed):**

Download instructions live in the attacker directory. See [`../../attackers/kali/quick-start/`](../../attackers/kali/quick-start/).

---

## Import (VirtualBox example)

```bash
VBoxManage import env0-victim-windows-server-2022.ova
```

For other hypervisors (VMware, Hyper-V, Parallels) the OVA import happens through their GUI's *File → Import* menu. The OVA declares its network as VirtualBox host-only; on non-VirtualBox platforms you may need to re-map to your hypervisor's equivalent isolated network.

**Networking:** attach the imported VM's adapter to a **host-only network** shared with the Kali attacker. On VirtualBox:

```bash
# Create a host-only adapter if you don't already have one
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Attach the imported VM
VBoxManage modifyvm env0-victim-windows-server-2022 --nic1 hostonly --hostonlyadapter1 vboxnet0

VBoxManage modifyvm kali-attacker --nic1 hostonly --hostonlyadapter1 vboxnet0
```

Both the victim and the Kali attacker must live on the **same** host-only network.

---

## First boot

Log in as `useradmin` (Administrator-group user). See [`../README.md`](../README.md) for the full account inventory and env0 configuration.

---

## Windows Server 2022 evaluation notes

The victim contains **Microsoft Windows Server 2022 Standard Evaluation**, distributed under Microsoft's evaluation EULA:

- **180-day trial** from first activation. Re-import the OVA to reset the trial, or convert to a licensed copy via `slmgr.vbs`.
- **Not for production use.**
- **We do not modify Windows binaries** — only account creation, service configuration, and Defender knobs, all documented in [`../from-scratch/`](../from-scratch/).

---

## Once both VMs are running

Head back to [`../../../attacks/v2.0/README.md`](../../../attacks/v2.0/README.md) → *Getting started* → step 2 to pick a chain and run it.
