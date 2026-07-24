# attack_chain.yml schema reference

This document describes the format of `attack_chain.yml`, the canonical representation of an Aurora attack chain. Every chain in v2.0 (all 101 of them) conforms to this schema; reading it is the fastest way to understand *what* a chain is, independent of how it's rendered in `readme.md` or executed by `attack_chain.py`.

If you want to author your own chain, or programmatically process the dataset, this is the reference to work from.

---

## Top-level structure

```yaml
emulation_plan_details:      # metadata about the plan itself
  ...

attack_action_sequence:      # ordered list of steps that make up the chain
  - ...
  - ...
```

Two top-level keys, always in this order. The chain is fully specified by the second — the first is purely descriptive metadata.

---

## `emulation_plan_details`

Provenance metadata. Not consumed at execution time; useful for lineage and reproducibility.

| Field | Type | Meaning |
|---|---|---|
| `adversary_name` | string | Name of the testbed this chain targets (e.g. `env0`). Historical field name — Aurora treats this as the **testbed / victim environment**, not the attacker. See [`environments/env0/`](../../../environments/env0/) for what `env0` refers to. |
| `creation_time` | ISO-8601 timestamp string | When the planner emitted this chain. |
| `parent_chain_idx` | integer | Index of the chain within the planner's raw output before deduplication / MMR-selection. Purely diagnostic. |
| `internal_chain_idx` | integer | Index in the planner's diverse-selection output. Purely diagnostic. |
| `stage_outcomes` | list of objects | One entry per attack lifecycle stage the planner attempted (initial-executor, discovery, credential-access, persistence, privilege-escalation, collection, exfiltration, impact, lateral-movement). Each records whether the stage was `succeeded` (the planner found actions that closed the stage's goal) or `failed`, and which sub-plan source it came from. |

Example:

```yaml
emulation_plan_details:
  adversary_name: env0
  creation_time: 2026-07-15 05:36:23 UTC+0000
  parent_chain_idx: 142
  internal_chain_idx: 169
  stage_outcomes:
    - stage: initial-executor
      status: succeeded
      plan_source: attack_plan-1.yml
    - stage: credential-access-obtained
      status: succeeded
      plan_source: attack_plan-3.yml
    # ... one entry per stage
```

---

## `attack_action_sequence`

The ordered list of steps. Each entry is one action (one atomic building block). The list order **is** the execution order — step *n* depends on state established by steps *0..n-1*.

Each entry has these fields:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `uuid` | string | ✅ | Stable identifier of the action. If two chains reference the same `uuid`, they mean the same underlying action (same command template, same preconditions/effects). |
| `name` | string | ✅ | Human-readable action name. |
| `id` | list of strings | ✅ | MITRE ATT&CK technique / sub-technique IDs this action realizes. E.g. `["T1003.002"]`. |
| `source` | string | ✅ | Origin of the action definition — `Atomic Red Team`, `Sliver`, `Metasploit`, `Manual`, etc. |
| `supported_platforms` | list of strings | ✅ | OSes this action can run on: `windows`, `linux`, `macos`. |
| `tactics` | list of strings | ✅ | MITRE ATT&CK tactic name(s) this action serves. |
| `technique` | list of strings | ✅ | MITRE technique name(s) (paired with `id` above). |
| `description` | string \| null | ✅ | Free-form prose about what the action does. Can be `null`. |
| `execution` | object | ✅ | How the action runs — executor + command template. See below. |
| `arguments` | object \| null | ✅ | Argument spec — one entry per placeholder in the command template. See below. |
| `preconditions` | list | ✅ | AALM predicates that must hold before this step can run. See [Predicates](#predicates). |
| `effects` | list | ✅ | AALM predicates that hold after this step succeeds. See [Predicates](#predicates). |

### `execution`

```yaml
execution:
  executor: Sliver Session Derive     # which executor family drives this step
  command: |                          # command template with #{VARIABLE} placeholders
    powershell(#{SessionID},#{Commands})
```

The `executor` value drives how `attack_chain.py` invokes the step (Sliver session, Meterpreter session, human-in-the-loop, direct PowerShell, direct cmd.exe, etc.). Placeholders in `command` are of the form `#{NAME}` and are resolved from the corresponding entry in `arguments`.

### `arguments`

One entry per placeholder in the command template.

```yaml
arguments:
  save_dir:
    description: Directory on the target where the SAM / SYSTEM / SECURITY hives are written.
    default: '%TEMP%'
    required: true
    pddl_index: string2_var_in_plan
```

| Field | Type | Meaning |
|---|---|---|
| `description` | string | Human-readable explanation shown by the wizard. |
| `default` | any \| null | Fallback value if the operator provides none. `null` (or omitted) means no default. |
| `required` | bool | If `true`, the wizard blocks progress until the operator provides a value. |
| `pddl_index` | string | (Optional) The PDDL variable name this argument binds to. When multiple actions in a chain share the same `pddl_index`, they must use the same value — the planner unifies them. This is how `attack_chain.params.yml`'s `pddl_bindings` section wires up: `pddl_bindings.<pddl_index>` → the value used everywhere the index appears. |

---

## Predicates

AALM (Aurora Action Language Model) predicates express **what state exists** at a point in a chain. They're plain PDDL-style expressions.

### Plain predicates

Most preconditions and effects are plain strings:

```yaml
preconditions:
  - (os-windows ?target - host)
  - (sliver-session ?executorID - executor ?target - host)
```

Each is a predicate name followed by typed variables. The variable names (`?target`, `?executorID`) matter only in scope of the one action — they're placeholders bound to concrete objects at planning time.

### `or` / `and` operators

For preconditions that need multiple options or a conjunction:

```yaml
preconditions:
  - operator: or
    operands:
      - (os-windows ?target - host)
      - (os-linux ?target - host)
      - (os-macos ?target - host)
```

The action's precondition is satisfied if **any** of the operands hold (`or`) or if **all** do (`and`). Nested operators are allowed.

### `When` operator (conditional effects)

Effects can be conditional — "if X held before this step, then Y holds after":

```yaml
effects:
  - (sliver-session ?s - executor ?target - host)
  - operator: When
    params:
      condition: (file-executed-elevated ?f - file ?target - host)
      effect: (elevated-executor ?s - executor)
```

Here the action always establishes a Sliver session; **additionally**, if the file that was executed to establish the session was executed with elevated privileges, the resulting session is marked as elevated.

`When` gives Aurora the ability to model actions whose outcome depends on the state going in — without splitting them into multiple separate actions.

---

## Cross-reference to `attack_chain.params.yml`

The `attack_chain.yml` defines the **chain structure**; `attack_chain.params.yml` defines the **runtime parameter values** the operator wants to plug in. The link is `pddl_index`:

```yaml
# attack_chain.yml
- uuid: sliver-payload-windows-exe
  arguments:
    SAVE_PATH:
      pddl_index: string0_var_in_plan     # ← binds this argument to string0
```

```yaml
# attack_chain.params.yml
pddl_bindings:
  string0_var_in_plan: /home/kali/Desktop/chain5.exe   # ← the value string0 gets
```

Multiple arguments across different steps can share the same `pddl_index` — they all resolve to the same value, guaranteeing the planner's unification stays consistent at runtime (e.g., the attacker-side path the payload is *written to* and the attacker-side path the HTTP server serves *from* both bind to `string0_var_in_plan`).

Arguments **without** `pddl_index` are per-step free params: they're set in `params.yml`'s `steps` section, keyed by step position + name.

---

## Full example — one action

```yaml
- uuid: art-t1003_002-reg-save-sam
  name: Registry dump of SAM, creds, and secrets
  id:
    - T1003.002
  source: Atomic Red Team
  supported_platforms:
    - windows
  tactics:
    - Credential Access
  technique:
    - 'OS Credential Dumping: Security Account Manager'
  description: |
    `reg save` writes the SAM, SYSTEM and SECURITY registry hives to a
    target-side directory (default `%TEMP%`).
  execution:
    executor: Command Prompt Executor
    command: |
      if not exist "#{save_dir}" mkdir "#{save_dir}"
      reg save HKLM\sam #{save_dir}\sam
      reg save HKLM\system #{save_dir}\system
      reg save HKLM\security #{save_dir}\security
  arguments:
    executor:
      description: The Command Prompt session ID used to invoke reg save.
      required: true
      pddl_index: executor1_var_in_plan
    save_dir:
      default: '%TEMP%'
      description: Directory on the target where the SAM / SYSTEM / SECURITY hives are written.
      required: true
      pddl_index: string2_var_in_plan
  preconditions:
    - (os-windows ?target - host)
    - (command-prompt ?executorID - executor ?target - host)
    - (elevated-executor ?executorID - executor)
  effects:
    - (credential-data ?d - data ?target - host)
    - (data-stored-in-file ?d - data ?f - file)
    - (file-exists ?path - string ?f - file ?target - host)
    - (callback-covered ?f - file)
```

This one action:
- Requires a Windows target with an **elevated** command-prompt executor available (`preconditions`)
- Writes the SAM / SYSTEM / SECURITY hives to `save_dir` on the target (`execution`)
- Establishes that credential data now exists on the target, stored in a file, at the given path (`effects`)

A downstream action that has `(credential-data ?d - data ?target - host)` in its own preconditions (e.g., an exfiltration action) can now be scheduled after this one.
