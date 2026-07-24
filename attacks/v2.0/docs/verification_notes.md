# Verification notes

Ten of the 101 chains in v2.0 (`chain-001` … `chain-010`) were run end-to-end on [env0](../../../environments/env0/) before this release was cut. Each of those chains ships with its full pilot log (`result.txt`) — you can see exactly which steps ran, what the wizard prompted, what output came back, and how long each step took.

This document explains what "verified" does and doesn't mean here, and how to read the pilot logs.

---

## What "verified" means

For a chain to be marked verified, we require:

1. It ran to completion on env0 — every step in `attack_action_sequence` was reached (either succeeded or failed for a documented reason)
2. `result.txt` was captured live during the run (we didn't reconstruct it after the fact)
3. The `attack_chain.params.yml` shipped with the chain contains the exact values we used

For chains where every step succeeded, we call the outcome **clean**. For chains where one or more steps failed *for a reason we understand and consider authentic* (see below), we call the outcome **partial**. Both are considered verified.

| Class | Chains in v2.0 |
|---|---|
| clean | `chain-001` … `chain-005` (5 chains) |
| partial | `chain-006` … `chain-010` (5 chains) |

We do not label chains as verified *outside* this set — the other 91 chains (`chain-011` … `chain-101`) have not been piloted by us and their `attack_chain.params.yml` files are null templates rather than filled-in values.

---

## What "verified" does not mean

- **Not "guaranteed to work on your setup."** Verified means it worked on env0, in the specific state env0 was in on the day of the pilot. Different hypervisors, different Windows patch levels, different network configurations, different Defender rules — any of these can change the outcome. If a chain fails for you where our log shows success, treat that as interesting data (either your environment differs meaningfully, or the chain has an environmental dependency we didn't detect) rather than as a bug in the chain.
- **Not a claim of TTP coverage completeness.** Verified means the chain runs; it does not mean the chain covers every plausible variation of the TTPs it demonstrates.
- **Not a security or safety review of the actions themselves.** These are real attack techniques being run against a real Windows machine. The env0 recipe puts them in a sealed testbed for that reason. Don't run these chains against systems you don't own or are not authorized to test.

---

## Reading a `result.txt`

Each `result.txt` is the direct stdout capture of `python attack_chain.py --params attack_chain.params.yml`. What you'll see, from top to bottom:

1. **Welcome banner and step 1** — the wizard prompts for each argument (with the value from `params.yml` pre-filled as the current answer), prints the command it will run, and asks for confirmation
2. **One block per step** — same shape as step 1: parameter prompts, command display, confirmation, then the tool's stdout / stderr
3. **Between-step confirmations** — where the wizard asks *"Keep going with the next attack step?"* — these are always answered `y` in our pilots
4. **Final summary table** — one row per step, with start time, end time, duration, and `✓` / `✗` status
5. **Failed-steps list** (if any) — for each failed step, the error message that caused the ✗

If you're trying to compare your run against ours to debug a divergence, the final summary is the fastest thing to eyeball.

---

## Documented failures in the partial chains

The five `partial` chains each fail for a specific, understood reason. Two motivations for keeping them in the release instead of quietly dropping or "fixing" them:

- **Some failures are the honest attacker experience.** A real operator dropping `pypykatz` on a cold Server 2022 target hits the same Sliver-implant task-timeout wall we hit; a real operator trying `wbadmin.exe` on Windows Server 2022 discovers wbadmin was removed from the SKU. Papering over these failures would make the dataset less true to the underlying threat surface, not more.
- **Some failures are genuinely useful for detection engineering.** A chain that *tries* to dump LSASS with `pypykatz` and hits LSA Protection (`RunAsPPL=1`) still produces telemetry — the attempt itself is visible. That telemetry is what a Blue-team consumer of this dataset cares about.

Every failed step in a partial chain has an entry in an `ISSUES.txt` next to `result.txt` in the chain's directory, spelling out exactly what failed and why we did not attempt to work around it. Read those before flagging a partial chain as broken.

For a broader taxonomy of failure *categories* — the recurring shapes we've seen across releases, not just this one — see [`FAILURE_MODES.md`](../../../FAILURE_MODES.md) at the repository root.

---

## Reproducibility gap and expected variance

Even on a freshly-built env0 image, expect small variance between your `result.txt` and ours:

- **Sliver session UUIDs** — regenerated per implant callback, will not match ours
- **Timestamps and durations** — network round-trip time and disk I/O vary
- **Windows process PIDs** — differ every boot; `sliver-ps` output will list roughly the same set of processes but with different PIDs
- **Some LSASS content / secret material** — pypykatz output depends on which credentials have been used since last reboot

What should **not** vary meaningfully: the `✓ / ✗` pattern in the final summary table, the sequence of executor prompts, the shape of the tool output for each step. If any of those diverge from our log, that's the signal worth investigating.
