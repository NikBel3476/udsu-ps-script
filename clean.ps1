# Unregister task after complete
Unregister-ScheduledTask -TaskName "SetUserSettingsOnLogon" -Confirm:$false

Remove-Item -LiteralPath "C:\Scripts" -Force -Recurse