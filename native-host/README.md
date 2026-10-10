# PeripheralShield Native Messaging Companion Host

This directory contains the OS-level native messaging companion host for PeripheralShield.

## Overview
When the browser extension detects and blocks a rogue peripheral command or unauthorized firmware reprogramming attempt, it dispatches structured telemetry to this host via Chromium's Native Messaging API (`com.defensive.extension.host`).

The host records security events in standardized SIEM JSONL format:
- **Location:** `~/.peripheralshield/security_alerts.jsonl`

## Available Implementations
1. **Python Host:** `host.py` (Default; portable, zero external dependencies)
2. **Node.js Host:** `host.js` (Alternative runtime for enterprise environments)

## Installation

### Windows
1. Double-click or run `install.bat` as the current user.
2. The script registers the native host manifest in:
   - `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.defensive.extension.host`
   - `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.defensive.extension.host`
   - `HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.defensive.extension.host`

To uninstall, run `uninstall.bat`.

### Linux & macOS
1. Open terminal in this directory.
2. Run:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

## Verifying Ingestion
You can monitor the live alert stream in PowerShell:
```powershell
Get-Content -Wait ~\.peripheralshield\security_alerts.jsonl
```
Or on Linux/macOS:
```bash
tail -f ~/.peripheralshield/security_alerts.jsonl
```
