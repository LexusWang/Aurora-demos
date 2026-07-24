# Known Failure Modes in Aurora-Generated Attack Chains

The attack chains in this dataset are not guaranteed to run to completion. Even after a chain is emitted by Aurora's planner and passes syntactic checks, individual steps can, and do, fail at execution time. This document catalogs the recurring causes so operators can distinguish "this chain is broken" from "this chain hit a known limitation."

Three modes cover major failures we have observed to date.
---

## Mode 1 — The underlying source command is broken

Aurora's action library is populated by transcribing tests and command patterns from public sources (Atomic Red Team, MITRE ATT&CK procedure examples, Metasploit modules, Sliver documentation, etc.). Sometimes the source itself carries a latent bug: it worked in the environment where its author wrote it but fails elsewhere. Aurora transcribes the source faithfully, so the bug propagates into every chain that uses the action.

Two sub-cases show up often enough to name separately.

### 1a — Missing environment setup line

The script assumes an environment property that the author's box provided by default, but a fresh victim does not. The script itself is otherwise correct.

**Example.** An Atomic Red Team test for T1555.003 (Credentials from Web Browsers) fetches a PowerShell utility from GitHub via `System.Net.WebClient.DownloadString(...)`. On Windows Server 2016 and Windows 10 builds prior to 1809, `WebClient` defaults its SecurityProtocol to SSL 3.0 / TLS 1.0. Since 2018, GitHub, most CDNs, and `download.sysinternals.com` refuse those protocols. The step fails with:

```
The request was aborted: Could not create SSL/TLS secure channel.
```

The remedy is a one-line prepend forcing TLS 1.2 before the download call. Local to the action definition, no ontology change.

### 1b — Non-atomic invocation into a stateful third-party framework

The script calls one function of a larger third-party framework, but the framework has hidden initialization state (config variables, module registrations, base-URL prefixes) that a different framework entrypoint is supposed to set up first. The source test violates its own "atomic" contract by depending on state it doesn't establish. Because the missing init is silent (no fail-fast in the framework), the script exits with `Status=0` while producing nothing useful — the failure only shows up in stderr as a wall of non-terminating errors.

**Example.** Continuing the T1555.003 case: after the TLS 1.2 fix, the same script invokes a sub-function of the WinPwn toolkit directly. That sub-function relies on config variables (URL prefixes and download-path bases) that WinPwn's main orchestrator sets during interactive startup. Called directly, those variables are empty, so every attempted download of a helper script resolves to a bare relative path that Windows treats as a nonexistent local file. Dozens of non-terminating `WebException` records accumulate; the script then calls a helper that was supposed to be defined by one of the failed downloads and gets `CommandNotFoundException`. **No browser credentials are actually extracted, but the step returns Status=0.**

Sub-case 1b is fundamentally harder to fix than 1a because the problem is structural — a script written against a framework used incorrectly. Repair options in decreasing preference:

- Replace the action with a framework-free implementation of the same MITRE technique (e.g. direct SharpChrome or DPAPI decryption of Chrome's `Login Data` SQLite for T1555.003). Same technique, no framework dependency.
- Swap the sub-function for the parent orchestrator. Works, but the AALM effect of the action then diverges from what the script actually does (the orchestrator runs many unrelated modules).
- Inline the missing framework init before the sub-call. Fragile — the internal variable names change across framework revisions.

When you encounter a 1b-shaped failure, patching is a trap. Prefer replacement.

---

## Mode 2 — The source's declared metadata is inaccurate

Aurora infers each action's AALM preconditions partly from the metadata the source declares — for Atomic Red Team, fields like `elevation_required`, `supported_platforms`, `prereqs`. When that metadata contradicts what the source script actually does, the derived preconditions are wrong, and the planner may schedule the action into a chain where it cannot succeed.

**Example.** An ART test for T1053.005 (Scheduled Task) declares `elevation_required: false`, but the underlying script calls `Register-ScheduledTask` with `-Principal BUILTIN\Administrators -RunLevel Highest`, which requires an elevated invoking session. In a chain where the current session is at medium integrity (e.g., a payload executed by a non-elevated user), the persistence step fails with:

```
Register-ScheduledTask : Access is denied.
HRESULT 0x80070005
```

The fix is to correct the derived preconditions on our side — mark the action as requiring `(elevated-executor ?executorID)`. On the next domain rebuild the planner is then forced to insert an elevation step (e.g. a UAC-bypass) before this one, or pick a different persistence method that doesn't need elevation. We apply these Mode 2 corrections in each release; the corresponding upstream metadata bug can be reported to the source project separately.

---

## Mode 3 — AALM does not (yet) express a real-world precondition

AALM enumerates the state predicates currently used to distinguish planning-relevant situations. When a real execution prerequisite has no corresponding AALM predicate, the planner cannot condition sequencing on it, and any chain that lands the dependent action into an environment where the prerequisite is unmet will fail at runtime.

**Example.** Several credential-access actions dump the Windows SAM / SYSTEM registry hives via Volume Shadow Copy Service (VSS). These commands require the Windows `VSS` service to be running, and (for some) the target file to be present in a snapshot. AALM currently has no `(vss-running ?target - host)` predicate, so the planner cannot condition a VSS-dependent step on the service being up. A chain containing one of these steps can be produced against a victim where VSS is stopped, and the step will fail at execution time with a service-unavailable or copy-source-missing error.

The remedy is to extend AALM: add the predicate, add a producer action that establishes it (e.g. `start-vss-service`) if operators should be able to enable the state mid-chain, or list it as part of the environment's initial state if it's an environment-builder assumption. Add the predicate to the affected actions' preconditions, rebuild the domain.

This is the same growth pattern that produced `(callback-covered ?file)` earlier in Aurora's evolution — a real ordering constraint had no expression in the ontology, and we added one. AALM is designed to grow with the action library; Mode 3 fixes are additive and don't disturb prior chains.

---

## Not a failure, but easy to misread

PowerShell run over `powershell.exe -EncodedCommand` serializes its **Progress stream** into stderr — the byte-progress bars emitted by `Invoke-WebRequest`, the tick records from `Expand-Archive`, and so on. A step that succeeds cleanly can still produce thousands of CLIXML `<Obj S="progress">` entries in stderr, which look like warnings under any naive "stderr non-empty ⇒ suspect" heuristic.

Aurora's PowerShell executor prepends `$ProgressPreference = 'SilentlyContinue'` to every script it runs, so in current pilot logs a non-empty stderr under `Status=0` reflects only real Warning / Error stream content. If you're inspecting an older log or running one of our chains through a different executor, mentally discount progress-only stderr as noise.

---

## What to do when you hit a failure

- **Recognize the mode.** Does the error look like one of the three above? If so, note it and continue. The chain probably still teaches its full attack graph up to and after the failed step — Aurora's wizard runs subsequent steps even after a failure, so the tail of the run may still produce useful telemetry.
- **Check the chain's own notes first.** Partial-verified chains (`chain-006` … `chain-010` in the current release) ship with an `ISSUES.txt` next to `result.txt` explaining every failed step we observed during pilot and why we did not attempt to work around it. If your failure matches one of those, it's already documented.
- **If it's new to us, tell us.** Open a GitHub issue with the failing chain number, the failed step, and (ideally) an attached `result.txt`. If you already know the fix and want to propose it directly — an action-YAML correction for Mode 1, a precondition tweak for Mode 2, an AALM extension for Mode 3 — a PR is even more welcome.

## Not fundamental, not unfixable

| Mode | What is wrong | What changes |
|---|---|---|
| 1 | The action's script itself is buggy or invoked incorrectly | The action's command template |
| 2 | The action's declared preconditions do not match what the script actually needs | The action's AALM preconditions |
| 3 | AALM has no predicate for a real prerequisite | The AALM ontology + affected actions' preconditions |

Each mode has a bounded fix that touches definitions, not planning. We apply the fixes we know about in each release cycle. If you find one we haven't, the fastest way for it to reach the next release is to open an issue or PR.

---

## Related reading

For **how to run and interpret** the specific pilot logs shipped with the verified chains in a given release, see that release's own `docs/verification_notes.md` (e.g. [`attacks/v2.0/docs/verification_notes.md`](attacks/v2.0/docs/verification_notes.md)). This document catalogs failure *categories*; `verification_notes.md` walks through the *pilot receipts* for one release.
