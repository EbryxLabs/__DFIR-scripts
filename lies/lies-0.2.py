
import re
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import glob, os

es = Elasticsearch(host="<ES-IP-HERE>", port=9200)
from dateutil import parser
import pprint

reg = "([a-z,A-Z].*:\d\d) ([a-z,A-Z].*) (sshd.*\:) ([A-Z,a-z].*.from)(.\d*.\d*.\d*.\d*)"
reg_keys = ["@timestamp","system","service","message","IP"]

keys_process = ["MODULE:","MESSAGE:","PID:","NAME:","OWNER:","CMD:","PATH:"]
keys_filescan = ["MODULE:","MESSAGE:","FILE:","TYPE:","SIZE:","FIRST_BYTES:","MD5:","SHA1:","SHA256:","CREATED:",
                 "MODIFIED:","ACCESSED:","REASON_1:","REASON_2","REASON_3","SCORE:"]
os.chdir("/media/<USER-NAME>/li-results/")
for file in glob.glob("*"):
    print "Bulking:",file,"to ES"
    f=open(file)
    bundle = []
    for line in f.readlines():
        try:
            if 'FileScan' == re.search('MODULE:(.*)MESSAGE',line).groups()[0].strip(' '):
                log = {}
                log['@timestamp']= parser.parse(line.split(' ')[0])
                for count,key in enumerate(keys_filescan):
                    try:
                        found = re.search(key+'(.*)'+keys_filescan[count+1],line).groups()[0]
                        log[key]=found
                    except:
                        log['SCORE']=line.split(':')[-1].strip()
                        pass

            else:
                log = {}
                log['@timestamp']=parser.parse(line.split(' ')[0])
                for count,key in enumerate(keys_process):
                    try:
                        found = re.search(key+'(.*)'+keys_process[count+1],line).groups()[0]
                        log[key]=found
                    except:
                        pass
        except:
            pass
        bundle.append({"_index": "<INDEX-NAME-HERE>", "_type": "loki", "Workstation": file, "body": log})
        if len(bundle) > 1000:
            print "INFO: Ingesting logs to Elasticsearch"
            helpers.bulk(es, bundle)
            bundle = []

    helpers.bulk(es, bundle)
