<#
.SYNOPSIS
A PowerShell module for executing DeepBlueCli for hunting on Windows event logs

.DESCRIPTION
Just pass the folder path to event logs and script with automatically execute on System.evtx, Security.evtx, Application.evtx, *powershell*.evtx and store findings in relevant files

.Example
execute-custom-deepbluecli.ps1 -folder \path\to\folder -output_folder_prefix mycustomlogoutput
#>

param ([string]$evtx_folder=".", [string]$deepbluecli_folder=".", [string]$output_folder_prefix=(Get-Date -UFormat "%Y%m%d%H%M%S"))

function Main {
    if ($evtx_folder -eq ""){
        Write-Host("Please provide a folder name ...")
        Write-Host("Exiting script ...")
        exit
    }
    else {
        Write-Host("Executing on folder $evtx_folder ...")
    }
    if ($output_folder_prefix -eq ""){
        Write-Host("Log File prefix can't be empty ...")
        Write-Host("Exiting script...")
        exit
    }
    else {
        Write-Host("Output folder prefix would be $output_folder_prefix ...")
    }

    $output_folder_name="out-deepbluecli-$output_folder_prefix"
    mkdir -p $output_folder_name

#    ForEach($filename in ls $evtx_folder\*.evtx | Get-ChildItem -Name){
#        if (($filename -eq "Security.evtx") -or ($filename -like "*powershell*") -or ($filename -like "*winrm*") -or ($filename -like "*wmi*") -or  ($filename -eq "System.evtx") -or ($filename -like "Application.evtx")){
#            Write-Host("Executing Deepbluecli on $filename ...")
#            Invoke-Expression "$deepbluecli_folder\DeepBlue.ps1 $evtx_folder\$filename | tee -a $output_folder_name\$filename.log"
#        }
#    }

    ForEach($filename in ls $evtx_folder\*.evtx | Get-ChildItem -Name){
        Write-Host("Executing Deepbluecli on $filename ...")
        Invoke-Expression "$deepbluecli_folder\DeepBlue.ps1 $evtx_folder\$filename | tee -a $output_folder_name\$filename.log"
    }

}

Main