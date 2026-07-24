<#
.SYNOPSIS
    Applies env0's Defender configuration to a base Windows Server 2022 VM.

.DESCRIPTION
    env0's victim is piloted with a minimal set of Defender knobs disabled to
    reduce interference with the attack chains without fully removing Defender.
    The WinDefend service continues to run — this reflects realistic
    enterprise "reduced-monitoring" configurations rather than a fully
    Defender-off honeypot.

    Run once from an elevated PowerShell prompt AFTER the base VM
    (from cyberrange-sphere/scripts/windows-base/) is up. Idempotent — safe
    to re-run.

.NOTES
    Matches the observed Defender state on env0 as of the v2.0 pilot runs:
      DisableRealtimeMonitoring : True
      MAPSReporting             : Disabled (0)
      SubmitSamplesConsent      : AlwaysPrompt (0, OS default)
      WinDefend service         : Running (default)
      No exclusion paths or extensions
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

Write-Host "Applying env0 Defender configuration..." -ForegroundColor Cyan

# Turn off real-time scanning — allows staged payloads to persist on disk.
Set-MpPreference -DisableRealtimeMonitoring $true

# Turn off cloud-delivered protection reporting — no telemetry to MAPS.
Set-MpPreference -MAPSReporting Disabled

# SubmitSamplesConsent is left at OS default (AlwaysPrompt / 0). On a
# headless server with MAPSReporting off, no submission occurs anyway.

Write-Host "`n=== Verify current Defender state ===" -ForegroundColor Cyan
Get-MpPreference | Select-Object `
    DisableRealtimeMonitoring, `
    DisableBehaviorMonitoring, `
    DisableScriptScanning, `
    DisableIOAVProtection, `
    MAPSReporting, `
    SubmitSamplesConsent | Format-List

Write-Host "=== Defender service state ===" -ForegroundColor Cyan
Get-Service -Name WinDefend, WdNisSvc, Sense -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType

Write-Host "`nenv0 Defender configuration applied." -ForegroundColor Green
