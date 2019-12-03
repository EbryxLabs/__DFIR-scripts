@ECHO ON

set host=%COMPUTERNAME%
mkdir C:\artifacts-%host%
mkdir C:\artifacts-%host%\%host%_evtx
mkdir C:\artifacts-%host%\info
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && set OS=32BIT || set OS=64BIT
wmic useraccount get disabled,domain,name,sid > C:\artifacts-%host%\info\%host%_user_accounts_and_sids.txt
REM listed all user accounts and their SIDs respectively
wmic sysaccount get domain,name,sid > C:\artifacts-%host%\info\%host%_system_accounts_and_sids.txt
REM listed all system accounts and their SIDs respectively
wmic group get domain,name,sid > C:\artifacts-%host%\info\%host%_domain_groups_and_sids.txt
REM listed all groups domain memberships and their SIDs respectively
wmic net localgroup Administrators > C:\artifacts-%host%\info\%host%_localadmins_and_sids.txt
REM listed all localadministrator group members
mkdir C:\artifacts-%host%\registry
for /f %%A in ('wmic useraccount get sid') DO (
	reg query HKEY_USERS\%%A\SOFTWARE\Sysinternals\ /s > C:\artifacts-%host%\registry\%%A_si_entries.txt
)
REM listed all sysinternals utilities entries
if %OS%==32BIT (
	echo "OS is 32 bit"
	.\logonsessions.exe -accepteula -c > C:\artifacts-%host%\%host%_32bit_logonssns-c.txt
	.\logonsessions.exe -accepteula -p > C:\artifacts-%host%\%host%_32bit_logonssns-p.txt
)
if %OS%==64BIT (
	echo "OS is 64 bit"
	.\logonsessions64.exe -accepteula -c > C:\artifacts-%host%\%host%_64bit_logonssns-c.txt
	.\logonsessions64.exe -accepteula -p > C:\artifacts-%host%\%host%_64bit_logonssns-p.txt
)
REM logonssessions command executed successfully!
if %OS%==32BIT (
	echo "OS is 32 bit"
	.\PsLoggedon.exe -accepteula > C:\artifacts-%host%\%host%_32bit_psloggedon.txt
)
if %OS%==64BIT (
	echo "OS is 64 bit"
	.\PsLoggedon64.exe -accepteula > C:\artifacts-%host%\%host%_64bit_psloggedon.txt
)
REM psloggedon command executed successfully!
netstat -anb > C:\artifacts-%host%\%host%_ntst-anb.txt
REM netstat command executed successfully!
ipconfig /displaydns > C:\artifacts-%host%\%host%_dspdns.txt
REM ipconfig command executed successfully!
schtasks > C:\artifacts-%host%\%host%_schtsk.txt
schtasks /query > C:\artifacts-%host%\%host%_schtsk-qry.txt
REM schtasks command executed successfully!
sc query > C:\artifacts-%host%\%host%_sq.txt
sc query eventlog > C:\artifacts-%host%\%host%_sqet.txt
sc queryex eventlog > C:\artifacts-%host%\%host%_sqel.txt
sc query type= driver > C:\artifacts-%host%\%host%_sqtd.txt
sc query type= service > C:\artifacts-%host%\%host%_sqts.txt
sc query state= all > C:\artifacts-%host%\%host%_sqsa.txt
sc query bufsize= 50 > C:\artifacts-%host%\%host%_sqb50.txt
sc query ri= 14 > C:\artifacts-%host%\%host%_sqr14.txt
sc query type= interact > C:\artifacts-%host%\%host%_scqti.txt
sc query type= driver group= NDIS > C:\artifacts-%host%\%host%_qtdg.txt
REM sc commands executed successfully!
copy c:\windows\system32\winevt\logs\* c:\artifacts-%host%\%host%_evtx\
REM event logs copied successfully!
netsh advfirewall firewall show rule name=all > c:\artifacts-%host%\%host%_firewall_rules.txt
REM firewall rules copied successfully!
powershell -command "[System.IO.Directory]::GetFiles(\"\\.\\pipe\\\")" >> c:\artifacts-%host%\%host%_pipes.txt
REM All pipe names copied successfully
powershell -command "get-childitem \\.\pipe\\" >> c:\artifacts-%host%\%host%_pipes_details.txt
REM All pipe nameds copied with more information successfully
mkdir C:\artifacts-%host%\Powershell\PowerShell_history\
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts-%host%\Powershell\PowerShell_history\%%a
			copy %%A\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history* C:\artifacts-%host%\Powershell\PowerShell_history\%%a\
		)
	)
)
REM Powershell command history fetched successfully!
mkdir C:\artifacts-%host%\Powershell\PowerShell_transcripts\
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\Documents\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts-%host%\Powershell\PowerShell_transcripts\%%a
			copy %%A\Documents\PowerShell_transcript* C:\artifacts-%host%\Powershell\PowerShell_transcripts\%%a\
		)
	)
)
REM Powershell transcript logs fetched successfully!
systeminfo >> C:\artifacts-%host%\%host%_systeminfo.txt
REM collected system information successfully
for /f "tokens=3" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath ^| find "REG_EXPAND_SZ"') do (
	if exist %%A\AppData\Local\Microsoft\AzureAD\Powershell\ (
		for /f "tokens=3 delims=\" %%a in ('echo %%A') do (
			mkdir C:\artifacts-%host%\Powershell\PowerShell_log_AD\%%a
			copy %%A\AppData\Local\Microsoft\AzureAD\Powershell\AzureADPowershell* C:\artifacts-%host%\Powershell\PowerShell_log_AD\%%a\
		)
	)
)
REM collected Powershell log file for AD as well!
dir /r /s C:\ | findstr /r "$DATA Directory" >> C:\artifacts-%host%\%host%_ads.txt
REM successfully collected names of all ADS!
if %OS%==32BIT (
	echo "OS is 32 bit"
	.\autorunsc.exe -accepteula -nobanner * -a * -h -s -c -o C:\artifacts-%host%\%host%_32bit_autoruns.csv
)
if %OS%==64BIT (
	echo "OS is 64 bit"
	autorunsc64.exe -accepteula -nobanner * -a * -h -s -c -o C:\artifacts-%host%\%host%_64bit_autoruns.csv
)
REM Autoruns executed successfully!
.\WinAudit.exe /r=gsoPxuTUeERNtzDaIbMpmidcSArCOHG /f=C:\artifacts-%host%\%host%_winaudit-report.html
REM WinAudit.exe executed successfully