# Quick & Dirty DFIR Scripts

## Excavator.py

- Original Author: DFIR Team @ Ebryx LLC\
- Description: A light-weight tool to parse Windows event-logs to XML and send them to ELK\
- Usage: python Excavator.py -m send -p `<Path_to_folder_conatining_evtx_files>` -ip `<ELK_IP>` -port `<Port_Number>` -user `<Username>` -pwd `<Password>` -i `<Index_name_for_ELK>` -scheme http -s `<Size_of_logs_to_send_in_one_go_default_is_100>`\
- Note: First use parameter `-m xml` to change all files in the folder to xml format

## exvt.py

- Original Author: Makman @ Ebryx LLC\
- Description: It first checks the hash .. If exists, it'll grab those results .. otherwise upload and push it to a queue to be checked again for the results\
- Usage: python vt.py `/path/of/samples`\
  - If we comment line 110 .. It'll just check for the hash without uploading\
  - If we comment, 106 to 109 .. it'll upload everything .. and check for the results

## eXir-win.bat

- Original Author: Ahmad @ Ebryx LLC\
- Contributor: heyibrahimkhan @ Ebryx LLC\
- Description: Let's just say its FASTIRfor Windows OS\
- Usage: run with admin exir<version>.bat

## eXir.py

- Original Author: Ishaq & Dan @ Ebryx LLC\
- Description: Inspired by FASTIR but better\
- Usage: run with sudo exir.py

## lies.py

- Original Author: UK @ Ebryx LLC\
- Description: A script to ingest IOC scanner result files to ES in bulk\
- Usage: lies.py\
- Change variable parameters in the script enclosed in <>

## eXir-lin-helper

- Original Author: heyibrahimkhan @ Ebryx LLC\
- Description: A script to help with output of eXir by neatly highlighting the results
- Usage: /bin/bash find_interesting.sh
- Read the script to see the params details

## eXir-win-helper

- Original Author: heyibrahimkhan @ Ebryx LLC\
- Description: A script to help with output of eXir-win by converting it to CSV
- Usage: script.py
- Change variable parameters in the script enclosed in <>

## dbc-helper

- Original Author: heyibrahimkhan @ Ebryx LLC\
- Description: Scripts to help with DeepBlueCLI bulk execution
- Usage: - preprocess.ps1 - execute-custom.ps1
- Change variable parameters in the script enclosed in <>

## vetter-py

- Original Author: SyeedHasan @ Ebryx LLC\
- Description: Calculated hashes for files and run a scan against VT
- Usage: python vetter.py -h

## ausys.bat

- Original Author: SyeedHasan @ Ebryx LLC\
- Description: Export system audit configurations and policies for a review
- Usage: ausys.bat
- Pre-requisites: Administrator privileges
