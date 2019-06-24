# Quick & Dirty DFIR Scripts

# 1. Excavator.py
#Original Author: DFIR Team @ Ebryx LLC\
#Description: A light-weight tool to parse Windows event-logs to XML and send them to ELK\
#Usage: python Excavator.py -m send -p `<Path_to_folder_conatining_evtx_files>` -ip `<ELK_IP>` -port `<Port_Number>` -user `<Username>` -pwd `<Password>` -i `<Index_name_for_ELK>` -scheme http -s `<Size_of_logs_to_send_in_one_go_default_is_100>`\
#NOTE: First use parameter `-m xml` to change all files in the folder to xml format\

# 2. exvt.py
#Original Author: Makman @ Ebryx LLC\
#Description: It first checks the hash .. If exists, it'll grab those results .. otherwise upload and push it to a queue to be checked again for the results\
#Usage: python vt.py /path/of/samples\
#If we comment line 110 .. It'll just check for the hash without uploading\
#If we comment, 106 to 109 .. it'll upload everything .. and check for the results

# 3. win-exir.bat
#Original Author: Ahmad @ Ebryx LLC\
#Description: FASTIR for Windows OS\
#Usage: run with admin winexir.py

# 4. lies.py
#Original Author: UK @ Ebryx LLC\
#Description: A script to ingest IOC scanner result files to ES in bulk\
#Usage: lies.py\
#Change variable parameters in the script enclosed in <>
