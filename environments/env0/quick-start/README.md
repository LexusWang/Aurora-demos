# env0 quick-start — pre-built OVAs

Download two OVA files, import into your hypervisor, boot. Done in about 15 minutes (most of which is the download).

- **env0 victim OVA** — hosted here (see below)
- **Kali attacker OVA** — hosted alongside the shared Kali attacker, at [`../../attackers/kali/quick-start/`](../../attackers/kali/quick-start/)

> ⏳ **Coming in v2.0.1** — both OVAs are still being built and uploaded to Zenodo. For the v2.0 release, please use the [from-scratch path](../from-scratch/) instead. This page will be filled in with download links, SHA256 hashes, and import commands once the OVAs are published.

---

## What you'll get (once published)

Two OVA files, together ~25 GB compressed:

| File | Location | Size (approx.) | Contains |
|---|---|---|---|
| `env0-victim-windows-server-2022.ova` | this directory | ~15–20 GB | Windows Server 2022 Evaluation with env0-specific configuration applied |
| `kali-attacker.ova` | [`../../attackers/kali/quick-start/`](../../attackers/kali/quick-start/) | ~5–7 GB | Kali Linux with Sliver, Metasploit, and `attack-executor` pre-installed |

Both are exported from the exact machines we used for our pilot runs. If you import them and run `chain-005`'s `attack_chain.py`, you should see output very close to the `result.txt` shipped with that chain.

---

## Legal note

The Windows Server 2022 OVA contains **Microsoft Windows Server 2022 Standard Evaluation**, distributed under Microsoft's evaluation EULA. Key implications:

- **180-day trial**: The OS activates as an evaluation copy and stops booting after 180 days from first activation. Re-import the OVA to reset, or convert to a licensed copy via `slmgr.vbs`.
- **Not for production use**: Microsoft's EULA restricts evaluation SKUs to testing and evaluation purposes.
- **We do not modify Windows binaries** — only account creation, service configuration, and Defender knobs (all documented in [`../from-scratch/`](../from-scratch/) and applied via the provisioning scripts).

The Kali Linux OVA is distributed under the [Kali Linux license](https://www.kali.org/docs/policy/kali-linux-trademark-policy/) (GPL-derived, freely redistributable).

---

## Once you have them running

Head back to [`attacks/v2.0/README.md`](../../../attacks/v2.0/README.md) → *Getting started* → step 2 to pick a chain and run it.
