@REM
@REM Ausys - An Advanced Audit Policy Configuration Checker by Ebryx (Pvt. Ltd)
@REM Date: 20-10-2020
@REM Version: 0.3
@REM Description: Check the current status of advanced audit policy configurations in the system
@REM Pre-requisites: Requires admin privileges to execute
@REM 

cls
@echo off

:::
:::   ___                  
:::  / _ |__ _____ __ _____
::: / __ / // (_-</ // (_-<
:::/_/ |_\_,_/___/\_, /___/
:::              /___/     
:::

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

echo An Audit Configuration Checker by Ebryx (Pvt.) Ltd.
echo Version: 0.3
echo.

@REM 
@REM Admin Privilege Check
@REM 
goto adminCheck
:adminCheck
    echo Administrator Privilege Check
    echo [+] Administrative permissions required to execute the script. Checking for required privileges now...
    
    @REM Since the command requires administrator privileges, the execution's 'errorlevel' will decide the operation
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [+] SUCCESS: Administrative privileges are available.
        echo [+] Continuing the script's execution
        echo.
    ) else (
        echo [-] Failure: Current permissions are inadequate to execute the script. Please re-run the console window as an administrator or execute the script as such...
        echo [-] Halting the script's execution... 
        timeout 5
        Exit /B 1
    )

set host=%COMPUTERNAME%
set currPath=%~dp0
cd %currPath%

@REM 
@REM Return audit policy configurations 
@REM 
echo Advanced Audit Policy Configurations
echo [+] Acquiring the system's audit policy configurations using 'auditpol.exe'
auditpol.exe /get /Category:* > %host%_sys_auditpol.txt
echo [+] Acquired audit policy configurations and saved to disk. Continuing... 
echo.

@REM 
@REM Return PowerShell based logging
@REM 
echo PowerShell Logging Status
echo [+] Retrieving PowerShell logging status from the system's Registry hives
echo Module Logging Status: > %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" >> %host%_powershell_logging.txt
IF errorlevel 1 (
    echo Disabled >> %host%_powershell_logging.txt
)
echo. >> %host%_powershell_logging.txt
echo Script-block Logging Status: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" >> %host%_powershell_logging.txt
IF errorlevel 1 (
    echo Disabled >> %host%_powershell_logging.txt
)
echo. >> %host%_powershell_logging.txt
echo Transcription Status for PowerShell: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" >> %host%_powershell_logging.txt
IF errorlevel 1 (
    echo Disabled >> %host%_powershell_logging.txt
)
echo [+] Acquired PowerShell logging status from the system's Registry hives
echo. 

@REM 
@REM Return audit settings 
@REM 
echo Audit Trail
echo [+] Retrieving audit trail of the system from the Registry hives
echo Audit Settings on the System: > %host%_auditsettings.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" >> %host%_auditsettings.txt
IF errorlevel 1 (
    echo Disabled >> %host%_auditsettings.txt
)
echo [+] Acquired audit trail of the sytem and stored to disk 
echo. 

@REM 
@REM Checking log sources
@REM 
echo Log Channels [Size, Retention Policies, Access Times]
echo [+] Retrieving key information about log sources using wevtutil
echo Channel: Application > %host%_logsources.txt
wevtutil gli Application >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo Channel: Security >> %host%_logsources.txt
wevtutil gli Security >> %host%_logsources.txt 
echo. >> %host%_logsources.txt
echo Channel: System >> %host%_logsources.txt
wevtutil gli System >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo Channel: Powershell-Admin >> %host%_logsources.txt
wevtutil gli Microsoft-Windows-PowerShell/Admin >> %host%_logsources.txt
IF errorlevel 1 (
    echo Disabled >> %host%_logsources.txt
)
echo. >> %host%_logsources.txt
echo Channel: Powershell-Operational >> %host%_logsources.txt
wevtutil gli Microsoft-Windows-PowerShell/Operational >> %host%_logsources.txt
IF errorlevel 1 (
    echo Disabled >> %host%_logsources.txt
)
echo. >> %host%_logsources.txt
echo [+] Acuiqred key information about log sources and stored to disk

@REM 
@REM Execution Completed
@REM 
echo.
echo [+] EXECUTION STATUS: Complete
echo [+] Analyze results from auditsettings.txt, logsources.txt, powershell_logging.txt, and sys_auditpol.txt for a review of the logging configurations...
timeout 10