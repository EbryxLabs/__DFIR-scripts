#!/usr/bin/python3
# Original Author: Mukarram Khalid, Ebryx LLC
# Description: It first checks the hash .. If exists, it'll grab those results .. otherwise upload and push it to a queue to be checked again for the results.
# Usage: python vt.py /path/of/samples
# If we comment line 110 .. It'll just check for the hash without uploading
# If we comment, 106 to 109 .. it'll upload everything .. and check for the results ..

import requests
import os, json, sys, secrets, time, hashlib

keys = ['ac3c52036bc0de77187e2dd55e26ecc4f10a4e9a07cdaf5ffd3567c9721e1272', '405a1bdf56ce5fc78fe98fda1a43806abbbf0107141033da9883cbd7b8f7fb9f', 'd7dbb7b00c76d77ffc1a03573312e82966b7f5de6dcf61204f8ca94d74930daa']

class VirusTotal:
    ''' VirusTotal file scanner '''
    #seconds
    timeout = 10
    samplesPath = None
    headers = {}

    def __init__(self, samplesPath):
        self.samplesPath = samplesPath.rstrip('/') + '/'
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent' : 'Mozilla 5.0'
        }

    def queryHash(self, sampleHash):
        params = {'apikey': secrets.choice(keys), 'resource': sampleHash}
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params = params, headers = self.headers)
        except:
            time.sleep(self.timeout * 2)
            return self.queryHash(sampleHash)
        time.sleep(self.timeout)
        return response

    def checkHash(self, sample, queuedHash = False):
        if queuedHash:
            sampleHash = queuedHash
        else:
            sampleHash = hashlib.md5(open(self.samplesPath + sample, 'rb').read()).hexdigest()
        sampleHashresult = None
        while sampleHashresult == None:
            sampleHashresult = self.queryHash(sampleHash)
            try:
                sampleHashresult = sampleHashresult.json()
            except:
                sampleHashresult = None
                time.sleep(self.timeout * 2)
        if 'response_code' in sampleHashresult and sampleHashresult['response_code'] == 0:
            return False
        if 'total' in sampleHashresult and 'positives' in sampleHashresult:
            return {'hash' : sampleHash, 'total' : sampleHashresult['total'], 'positives' : sampleHashresult['positives']}
        return False

    def hashFound(self, sample, details):
        print('[+] ' + self.samplesPath + sample + ' - hash : ' + details['hash'] + ' - Detections : ' + str(details['positives']) + '/' + str(details['total']))
        with open(self.samplesPath.replace('/', '_') + '_results.txt', 'a+') as results:
            results.write('[+] ' + self.samplesPath + sample + ' - hash : ' + details['hash'] + ' - Detections : ' + str(details['positives']) + '/' + str(details['total']) + "\n")

    def upload(self, sample):
        params = {'apikey': secrets.choice(keys)}
        files = {'file': (sample, open(self.samplesPath + sample, 'rb'))}
        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files = files, params = params, headers = self.headers)
        except:
            time.sleep(self.timeout * 2)
            return self.upload(sample)
        time.sleep(self.timeout)
        return response

    def queueToUpload(self, sample):
        results = None
        while results == None:
            results = self.upload(sample)
            try:
                results = results.json()
            except:
                results = None
                time.sleep(self.timeout * 2)
        if 'scan_id' in results:
            print('[+] ' + self.samplesPath + sample + ' - scan_id : ' + results['scan_id'] + ' - Queued')
            with open(self.samplesPath.replace('/', '_') + '_queued.txt', 'a+') as queued:
                queued.write(json.dumps({'path' : self.samplesPath, 'sample' : sample, 'scan_id' : results['scan_id']}) + "\n")

    def checkQueued(self):
        print('[+] Checking queued scans')
        if not os.path.isfile(self.samplesPath.replace('/', '_') + '_queued.txt'):
            return
        queuedItems = []
        with open(self.samplesPath.replace('/', '_') + '_queued.txt') as queued:
            queuedItems = queued.read().splitlines()
        open(self.samplesPath.replace('/', '_') + '_queued.txt', 'w').close()
        if len(queuedItems) < 1:
            return
        for item in queuedItems:
            item = json.loads(item)
            hashFound = self.checkHash(None, item['scan_id'])
            if hashFound:
                self.hashFound(item['sample'], hashFound)
                continue
            with open(self.samplesPath.replace('/', '_') + '_queued.txt', 'a+') as queued:
                queued.write(json.dumps({'path' : self.samplesPath, 'sample' : item['sample'], 'scan_id' : item['scan_id']}) + "\n")
        time.sleep(self.timeout * 2)
        return self.checkQueued()

    def scan(self):
        samples = next(os.walk(self.samplesPath))[2]
        for sample in samples:
            hashFound = self.checkHash(sample)
            if hashFound:
                self.hashFound(sample, hashFound)
                continue
            self.queueToUpload(sample)
        time.sleep(self.timeout * 2)
        self.checkQueued()
        print('[+] Done')

def main():
    if len(sys.argv) < 2 or not os.path.isdir(sys.argv[1]):
        print('[-] Usage : %s /path/of/samples/here' % sys.argv[0])
        print('[-] Example: %s /home/makman/Desktop' % sys.argv[0])
        exit()
    virustotal = VirusTotal(sys.argv[1])
    virustotal.scan()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit("\n[-] CTRL-C detected.\n")
# End
