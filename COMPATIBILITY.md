# Attacker's Machine Compatibility

To reproduce our emulated attacks, we recommend running them against the **exact environments we provide**. The easiest way is to import the OVA files we ship. If you'd rather build from scratch, we also provide provisioning scripts.

Victim environments are naturally version-distinguished — each one gets its own name (`env0`, `env1`, ...). Attacker environments are largely shared across emulations and only differ in small ways over time: different tool versions, or a different version of `attack-executor` (our own PyPI package that provides Python bindings for the tools Aurora uses). For example, an attacker machine built for env0 at v2.0 may not work cleanly against env0 at v2.8, even though the victim side is identical.

This page records which attacker-setup script goes with which dataset release.

---

## Matrix

| Aurora-demos | Attacker's Machine | attacker-setup.sh | attack-executor | Notes |
|---|---|---|---|---|
| **v2.0** | Kali 2025.1 | [`environments/attackers/kali/attacker-setup.sh`](environments/attackers/kali/attacker-setup.sh) | 0.3.0 | Initial 2.x release. The bundled `attacker-setup.sh` was added on `main` after the v2.0 tag; if you have v2.0 checked out, either fetch the script from `main` (URL in the setup docs) or move to a later commit on `main`. |

> [1] Kali is rolling-release: the version above is the snapshot we tested against, not a hard pin. Installing a more recent Kali snapshot should work equally well.

---

## How to use this table

**"I'm running dataset release vX.Y — which attacker machine do I need?"**
Find your row. The `attacker-setup.sh` column tells you which script to run; the `attack-executor` column tells you the pinned pip version (the script installs it for you).

**"I want the latest tooling regardless of dataset release."**
Use the `attacker-setup.sh` from the most recent row — it reflects the current tested state. Older dataset chains generally still work against newer `attack-executor` versions (we keep the executor backward-compatible), but this is the "tracking main" path and some drift is possible over time.
