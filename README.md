# Quick & Dirty DFIR Scripts

# 1. exvt.py
#Original Author: Makman @ Ebryx LLC\
#Description: It first checks the hash .. If exists, it'll grab those results .. otherwise upload and push it to a queue to be checked again for the results\
#Usage: python vt.py /path/of/samples\
#If we comment line 110 .. It'll just check for the hash without uploading\
#If we comment, 106 to 109 .. it'll upload everything .. and check for the results

# 2. win-exir.bat
#Original Author: Ahmad @ Ebryx LLC\
#Description: FASTIR for Windows OS\
#Usage: run with admin winexir.py

# 3. lies.py
#Original Author: UK @ Ebryx LLC\
#Description: A script to ingest IOC scanner result files to ES in bulk\
#Usage: lies.py\
#Change variable parameters in the script enclosed in <>
