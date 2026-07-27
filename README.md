![License](https://img.shields.io/github/license/LexusWang/Aurora-demos)

# Aurora-demos

**A dataset of emulated APT-style cyberattack chains: end-to-end runnable, symbolic-planned, and openly modeled.**

Aurora is a system for automatically constructing high-fidelity, end-to-end, APT-style attack chains for emulation. It combines classical (PDDL-based) planning with LLM-assisted knowledge extraction to compose real attack tools (Sliver, Meterpreter, Atomic Red Team, native Windows utilities) into causally coherent multi-step chains — the kind of chains you'd otherwise write by hand for a red-team exercise.

This repository is the **output dataset** of Aurora. Every chain here is represented in a shared symbolic model (AALM — Aurora Action Language Model), comes with an executable Python wizard, and is meant to be run against real emulation environments to produce authentic telemetry.

📄 **Paper**: *From Sands to Mansions: Towards Automated Cyberattack Emulation with Classical Planning and Large Language Models* (ACNS 2026) — [arXiv preprint](https://arxiv.org/abs/2407.16928)

🌐 **Homepage**: [auroraattack.github.io](https://auroraattack.github.io/)

---

## Watch a chain in action

[![Aurora chain-005 — sliver-EXE + SAM dump + persistence + Spooler stop, 3 min end-to-end](https://img.youtube.com/vi/J9txdLHPlNA/maxresdefault.jpg)](https://youtu.be/J9txdLHPlNA)

*Aurora `chain-005` running end-to-end on env0 (3 minutes). See [Watch it run](attacks/v2.0/README.md#watch-it-run) for more chain videos, or jump straight to the [YouTube playlist](https://www.youtube.com/playlist?list=PLVLjOxpv8hL0).*

---

## Repository layout

The repo is organized into two independent axes: **releases of the dataset** and **the environments those releases were built against**.

```
Aurora-demos/
├── README.md                   ← you are here
├── LICENSE                     ← Apache 2.0
├── CITATION.cff
│
├── attacks/                    ← chain dataset, versioned
│   └── v2.0/                   ← the current release
│       ├── README.md           ← what's in this release, how to run it
│       ├── chain-001/          ← one directory per attack chain
│       ├── ...
│       └── docs/
│
└── environments/               ← emulation testbeds, shared across releases
    └── env0/                   ← the Windows-Server-2022 testbed used for v2.0
        ├── README.md
        ├── quick-start/        ← one-click OVA path
        └── from-scratch/       ← manual build path (transparent, hypervisor-agnostic)
```

New releases are added under `attacks/vX.Y/` without touching prior releases (git tags freeze historical states). New testbeds are added under `environments/envN/`. Releases declare which environment(s) they were validated against in their own README.

---

## Available releases

| Release | Chains | Testbed | Highlights |
|---|---|---|---|
| [**v2.0**](attacks/v2.0/) | 101 | [env0](environments/env0/) | Updated AALM ontology, msf-HTA / VBS / fodhelper action families, per-chain readmes with MITRE ATT&CK coverage |

Legacy 1.0 chains(250 CTI-derived chains from the original release)are preserved on the [`v1.0` git tag](https://github.com/LexusWang/Aurora-demos/releases/tag/v1.0) — they use an older AALM predicate scheme and are not maintained forward.

---

## Available emulation environments

| Name | Description |
|---|---|
| [**env0**](environments/env0/) | Windows Server 2022 (Victim) + Kali Linux (Attacker)|

---

## Known failure modes

Chains are not guaranteed to run to completion, some steps fail at execution time even when the plan is well-formed. We've catalogued the recurring causes in [`FAILURE_MODES.md`](FAILURE_MODES.md). We recommend users read it to better understand Aurora.

---

## Feedback & Contributions

We welcome community review of the attack chains and the underlying AALM predicates (`preconditions` / `effects` in each `attack_chain.yml`). If you spot inaccuracies, edge cases, or think a chain could be modeled better, please open a GitHub issue or PR. Discussion is what will make this dataset useful over time.

---

## Citation

If you use Aurora or the chains in this repo, please cite:

```bibtex
@article{wang2024sands,
  title={{From Sands to Mansions: Towards Automated Cyberattack Emulation with Classical Planning and Large Language Models}},
  author={Wang, Lingzhi and Li, Zhenyuan and Jiang, Yi and Wang, Zhengkai and Guo, Zonghan and Wang, Jiahui and Wei, Yangyang and Shen, Xiangmin and Ruan, Wei and Chen, Yan},
  journal={arXiv preprint arXiv:2407.16928},
  year={2024},
  note={Accepted to ACNS 2026}
}
```

(The ACNS 2026 proceedings citation will be added once the conference publishes.)

---

## License

Distributed under the Apache License 2.0. See `LICENSE` for details.

The attack chains in this repository are for **education, research, and defensive testing purposes only**. The authors do not condone unauthorized use. Use at your own risk.

---

## Contributors

- Lingzhi Wang — [lingzhiwang2025@u.northwestern.edu](mailto:lingzhiwang2025@u.northwestern.edu)
- Yi Jiang — [jiangyi99@zju.edu.cn](mailto:jiangyi99@zju.edu.cn)
- Zhengkai Wang — [wangzhengkai@zju.edu.cn](mailto:wangzhengkai@zju.edu.cn)
