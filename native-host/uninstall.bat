@echo off
setlocal
echo Uninstalling PeripheralShield Native Messaging Host...

REG DELETE "HKCU\Software\Google\Chrome\NativeMessagingHosts\com.defensive.extension.host" /f
REG DELETE "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.defensive.extension.host" /f
REG DELETE "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.defensive.extension.host" /f

echo Native Host Unregistered.
pause
