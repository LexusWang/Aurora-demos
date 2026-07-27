# Aurora-demos v2.0

This is the **v2.0 release** of the Aurora attack-chain dataset. 101 chains, planned by Aurora and validated on the [env0 testbed](../../environments/env0/) (Windows Server 2022 + Kali Linux).

For the top-level project introduction, license, and citation info, see [the repository root](../../README.md).

---

## What's new in v2.0

- **101 attack chains** in a flat, uniformly-numbered layout (`chain-001` … `chain-101`)
- **10 chains verified end-to-end** on env0. Each ships with the pilot log (`result.txt`) so you can see exactly what a real run looks like — including chains that fail in realistic ways
- **91 additional chains** emitted by the diverse-planning pipeline (MMR-selected for breadth of TTPs)
- **Updated AALM predicate ontology** — cleaner naming (`os-windows` vs older `os_windows`), new gates like `callback-covered`, When-effects for elevation propagation
- **New action families**: msfvenom HTA / VBS payload generators, `.hta` / `.vbs` / `.lnk` execution simulators (root and non-root variants), fodhelper UAC bypass
- **Human-readable `readme.md` per chain** — MITRE ATT&CK coverage, step-by-step overview + full detail (preconditions, effects, commands, arguments)

---

## Layout

```
attacks/v2.0/
├── README.md                    ← you are here
│
├── chain-001/                   ← verified: pre-populated params + pilot log
│   ├── attack_chain.yml         ← the chain definition (AALM ground truth)
│   ├── attack_chain.py          ← executable wizard (Python)
│   ├── attack_chain.params.yml  ← runtime parameters (pre-filled)
│   ├── result.txt               ← end-to-end pilot log from our run
│   └── readme.md                ← human-readable chain description
│
├── chain-011/                   ← diverse-unverified: null params template
│   ├── attack_chain.yml
│   ├── attack_chain.py
│   ├── attack_chain.params.yml  ← template with inline docs
│   └── readme.md
│
├── ... (chain-002 through chain-101)
│
└── docs/
    ├── attack_chain_schema.md   ← the attack_chain.yml format
    └── verification_notes.md    ← how the 10 verified chains were piloted
```

> Verified chains live at positions `chain-001` … `chain-010`; the remaining `chain-011` … `chain-101` are diverse-planner output. Both share exactly the same file layout — the only difference is whether we've personally piloted the chain and whether `attack_chain.params.yml` is pre-filled with the values we used.

---

## Watch it run

Terminal captures of the five chains running end-to-end on env0. Or [watch all as a playlist](https://www.youtube.com/playlist?list=PLVLjOxpv8hL0).

| Chain | Description | Video |
|---|---|---|
| **chain-001** | sliver-EXE + BITS persistence + change-password impact (~3 min) | [![thumb](https://img.youtube.com/vi/uD20iQvjpa8/mqdefault.jpg)](https://youtu.be/uD20iQvjpa8) |
| **chain-002** | msf-EXE + schtasks persistence + net-stop-service impact (~10 min) | [![thumb](https://img.youtube.com/vi/eXzAfwUfIQM/mqdefault.jpg)](https://youtu.be/eXzAfwUfIQM) |
| **chain-003** | msf-HTA + SAM dump + BITS persistence + restart (~13 min) | [![thumb](https://img.youtube.com/vi/DpsdTeLKRhc/mqdefault.jpg)](https://youtu.be/DpsdTeLKRhc) |
| **chain-004** | msf-VBS + SAM dump + net-user-add persistence + reboot (~13 min) | [![thumb](https://img.youtube.com/vi/5HCD7QK-OSc/mqdefault.jpg)](https://youtu.be/5HCD7QK-OSc) |
| **chain-005** | sliver-EXE + SAM dump + persistence + Spooler stop (~3 min) | [![thumb](https://img.youtube.com/vi/J9txdLHPlNA/mqdefault.jpg)](https://youtu.be/J9txdLHPlNA) |

---

## Getting started

### 1. Set up the environment

The chains in this release are validated against **[env0](../../environments/env0/)** (Windows Server 2022 victim + Kali Linux attacker on a host-only network). Two setup paths are available:

- **Quick start** — download a pre-built OVA pair and import into your hypervisor (~15 minutes)
- **From scratch** — provision both machines using our scripts (~60–90 minutes, but transparent and hypervisor-agnostic)

See [`environments/env0/README.md`](../../environments/env0/README.md) for both paths.

You can also run the chains against other Windows environments — most chains target Windows in general and don't hard-depend on Server-tier surface — but be aware that a handful of actions (`sc.exe stop`, `reg save HKLM\sam`, `Register-ScheduledTask` with SYSTEM privileges, etc.) may behave differently on client SKUs. Check each chain's `readme.md` for specific requirements.

### 2. Pick a chain

**Start with a verified chain.** Any of `chain-001` through `chain-010` will do — they're pre-populated with the exact `params.yml` values we used during pilot on env0, so you can see a full worked example.

Open the chain's `readme.md` first to understand what it does. `chain-005` is a good introductory example: 11 steps, dual-payload Sliver, credential dump, persistence, and impact — all in about 3 minutes of runtime.

### 3. Substitute your own values

At minimum you'll need to change:

- `LHOST` → your attacker machine's routable IP
- Attacker-side paths (`/home/kali/...`) → paths on your own attacker box
- Victim-side paths (`C:\Users\Public\...`) usually work as-is on default Windows

Everything else can typically stay. Each chain's `params.yml` has inline comments identifying what each PDDL binding feeds into (`# used by: 3_sliver-payload-windows-exe.SAVE_PATH`), so you can trace values to their steps.

### 4. Run it

Copy `attack_chain.py` and `attack_chain.params.yml` to your attacker machine, then:

```bash
python attack_chain.py --params attack_chain.params.yml
```

The script is a semi-automatic wizard: it will prompt for confirmation between steps, show human-execute instructions when a step requires manual interaction (e.g., double-clicking a `.lnk` on the victim), and print a final summary of which steps succeeded.

### 5. Running unverified chains

Chains `chain-011` … `chain-101` use the same layout, but `attack_chain.params.yml` is a null template. Copy the value patterns from a verified chain (same shape of param → same shape of value) and fill in. If a chain uses an action you haven't seen in the verified chains, its `readme.md` includes a full argument table with descriptions and expected types.

---

## Understanding a chain

Each chain's `readme.md` has three sections:

1. **Header** — testbed, step count, and the MITRE ATT&CK tactics touched
2. **MITRE ATT&CK Coverage** — tactic → unique technique IDs the chain covers (useful for detection-engineering audience matching)
3. **Attack Steps** — a short overview table (# / tactic / technique / action / executor) followed by a detailed section per step: description, executor + command, arguments, preconditions, and effects

**Preconditions and effects** are expressed as AALM predicates like `(sliver-session ?s - executor ?target - host)`. They describe what state the chain assumes going into each step and what state the step establishes coming out. If you want to understand *why* the planner chose a particular action at a particular position, these predicates are the answer — the planner selects each next action so that all of its preconditions are satisfied by the accumulated effects of prior actions.
