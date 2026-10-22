@echo off
:: Windows Advanced Audit Policy & Command-Line Ingestion Setup
:: Author: Mahi Al Jaber (github.com/mahialjaber)
:: Target: Windows 11 Enterprise (windows-vm-01)

echo [*] Enabling Advanced Audit Policies...
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

echo [*] Enabling Process Creation Command-Line Inclusion in Event ID 4688...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f

echo [*] Configuring Account Lockout Threshold...
net accounts /lockoutthreshold:15 /lockoutduration:30 /lockoutwindow:30

echo [*] Enabling Windows Defender Firewall across all profiles...
powershell -Command "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"

echo [*] Adding Management Subnet Firewall Exceptions...
powershell -Command "Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'"
powershell -Command "Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)'"
powershell -Command "Enable-NetFirewallRule -DisplayGroup 'Remote Service Management'"
powershell -Command "New-NetFirewallRule -DisplayName 'Lab SMB Inbound' -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow -RemoteAddress 192.168.198.0/24 -ErrorAction SilentlyContinue"

echo [✓] Windows Enterprise Telemetry Stack Hardened Successfully!
pause
