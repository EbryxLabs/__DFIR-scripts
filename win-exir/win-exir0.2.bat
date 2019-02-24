@ECHO ON

set host=%COMPUTERNAME%
mkdir C:\artifacts
mkdir C:\artifacts\%host%_evtx
logonsessions64.exe -c > C:\artifacts\%host%_logonssns-c.txt
logonsessions64.exe -p > C:\artifacts\%host%_logonssns-p.txt
REM logonssessions command executed successfully!
PsLoggedon64.exe > C:\artifacts\%host%_psloggedon.txt
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
REM sc command executed successfully!
copy c:\windows\system32\winevt\logs\* c:\artifacts\%host%_evtx\
