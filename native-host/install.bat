@echo off
setlocal
echo Installing PeripheralShield Native Messaging Host for Windows...

set MANIFEST_PATH=%~dp0com.defensive.extension.host.json

REG ADD "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.defensive.extension.host" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f
REG ADD "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.defensive.extension.host" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f
REG ADD "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.defensive.extension.host" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f

echo.
echo Native Host Registered Successfully!
echo Manifest: %MANIFEST_PATH%
echo Logs will be written to: %USERPROFILE%\.peripheralshield\security_alerts.jsonl
pause
