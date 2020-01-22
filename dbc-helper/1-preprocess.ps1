param([string]$path=".")

$pwd=(Invoke-Expression "pwd")

cd $path

Get-ChildItem -File | Rename-Item -NewName { $_.Name -replace '%4','' }
Get-ChildItem -File | Rename-Item -NewName { $_.Name -replace ' ','' }

cd $pwd