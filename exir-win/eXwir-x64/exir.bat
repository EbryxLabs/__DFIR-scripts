@ECHO ON

set host=%COMPUTERNAME%
mkdir C:\artifacts
mkdir C:\artifacts\%host%_evtx
.\logonsessions64.exe -accepteula -c > C:\artifacts\%host%_logonssns-c.txt
.\logonsessions64.exe -accepteula -p > C:\artifacts\%host%_logonssns-p.txt
REM logonssessions command executed successfully!
.\PsLoggedon64.exe -accepteula > C:\artifacts\%host%_psloggedon.txt
REM psloggedon command executed successfully!
netstat -anb > C:\artifacts\%host%_ntst-anb.txt
REM netstat command executed successfully!
ipconfig /displaydns > C:\artifacts\%host%_dspdns.txt
REM ipconfig command executed successfully!
schtasks > C:\artifacts\%host%_schtsk.txt
schtasks /query > C:\artifacts\%host%_schtsk-qry.txt
REM schtasks command executed successfully!
sc query > C:\artifacts\%host%_sq.txt
sc query eventlog > C:\artifacts\%host%_sqet.txt
sc queryex eventlog > C:\artifacts\%host%_sqel.txt
sc query type= driver > C:\artifacts\%host%_sqtd.txt
sc query type= service > C:\artifacts\%host%_sqts.txt
sc query state= all > C:\artifacts\%host%_sqsa.txt
sc query bufsize= 50 > C:\artifacts\%host%_sqb50.txt
sc query ri= 14 > C:\artifacts\%host%_sqr14.txt
sc query type= interact > C:\artifacts\%host%_scqti.txt
sc query type= driver group= NDIS > C:\artifacts\%host%_qtdg.txt
REM sc commands executed successfully!
copy c:\windows\system32\winevt\logs\* c:\artifacts\%host%_evtx\
REM event logs copied successfully!
netsh advfirewall firewall show rule name=all > c:\artifacts\%host%_firewall_rules.txt
REM firewall rules copied successfully!
powershell -command "[System.IO.Directory]::GetFiles(\"\\.\\pipe\\\")" >> c:\artifacts\%host%_pipes.txt
REM All pipe names copied successfully
powershell -command "get-childitem \\.\pipe\\" >> c:\artifacts\%host%_pipes_details.txt
REM All pipe nameds copied with more information successfully
mkdir C:\artifacts\Powershell\PowerShell_history\
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts\Powershell\PowerShell_history\%%a
			copy %%A\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history* C:\artifacts\Powershell\PowerShell_history\%%a\
		)
	)
)
REM Powershell command history fetched successfully!
mkdir C:\artifacts\Powershell\PowerShell_transcripts\
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\Documents\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts\Powershell\PowerShell_transcripts\%%a
			copy %%A\Documents\PowerShell_transcript* C:\artifacts\Powershell\PowerShell_transcripts\%%a\
		)
	)
)
REM Powershell transcript logs fetched successfully!
systeminfo >> C:\artifacts\%host%_systeminfo.txt
REM collected system information successfully
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\AppData\Local\Microsoft\AzureAD\Powershell\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts\Powershell\PowerShell_log_AD\%%a
			copy %%A\AppData\Local\Microsoft\AzureAD\Powershell\AzureADPowershell* C:\artifacts\Powershell\PowerShell_log_AD\%%a\
		)
	)
)
REM collected Powershell log file for AD as well!