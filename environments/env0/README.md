# env0 — Windows Server 2022 attack testbed

**env0** is the emulation environment used to develop and validate the Aurora attack chains. It consists of two virtual machines connected by a host-only network:

| Machine | Role | OS |
|---|---|---|
| **victim** | The target the attack chains hit — receives payloads, hosts the Sliver / Meterpreter implants, runs the persistence and impact steps | Windows Server 2022 Standard Evaluation |
| **attacker** | The operator's workstation — runs the Sliver C2 server, Metasploit, and the `attack_chain.py` wizard | Kali Linux |

The two machines see each other over a VirtualBox host-only adapter (or your hypervisor's equivalent). No internet access is required for chain execution once both machines are provisioned.

---

## Two setup paths

Pick whichever fits your situation:

### 🚀 [Quick start](quick-start/) — download OVAs, import, boot (~15 minutes)

Two pre-built OVA files (attacker + victim), hosted on Zenodo with SHA256 verification. Import into VirtualBox / VMware / any hypervisor that reads OVA, boot both VMs, done. **This is the default recommendation** — self-contained, hypervisor-agnostic, matches our pilot state exactly.

### 🔧 [From scratch](from-scratch/) — build both VMs from official media (~60–90 minutes)

Provision each VM yourself, starting from official Windows Server 2022 Evaluation and Kali Linux ISOs. More work but fully transparent — you see exactly what's installed and configured, and you can modify anything. **Use this path if:**

- You want to audit what's in the environment before running attacks against it
- You're on hardware where OVA import doesn't work well (e.g., macOS on Apple Silicon)
- Your Windows Server 2022 Evaluation OVA has passed its 180-day trial and you want to re-provision fresh
- You want to fork env0 into a new environment (env1, env2, …)

Both paths result in **the same env0** — same accounts, same Defender configuration, same networking. The `from-scratch` scripts are also what we use internally to build the OVAs published in `quick-start/`, so there's no drift between the two.

---

## What's inside env0

**Victim (Windows Server 2022 Standard Evaluation):**
- Local accounts: `Administrator` (built-in), `useradmin` (member of Administrators), `user` (Users only, for privilege-escalation targets)
- OpenSSH server enabled on port 22 (for provisioning access)
- VirtualBox Guest Additions installed
- Windows Defender: real-time protection **disabled**, telemetry **disabled**; the Defender service itself remains running (matches realistic enterprise "reduced-monitoring" configurations, not a Defender-off honeypot)
- No RDP — pilots ran via the VirtualBox console / hypervisor GUI

**Attacker (Kali Linux):**
- Sliver C2 server
- Metasploit Framework
- Python 3 + our [`attack-executor`](https://pypi.org/project/attack-executor/) package (drives the `attack_chain.py` wizards)

**Network:**
- Host-only adapter shared by both VMs
- Attacker at a static or DHCP-assigned IP on the host-only subnet; victim reaches attacker at that IP for payload downloads and C2 callbacks
