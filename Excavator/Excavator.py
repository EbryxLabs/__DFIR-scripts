#Excavator

import os
import sys
from subprocess import check_output
import argparse
import re
import json
import xmltodict
from elasticsearch import Elasticsearch, helpers

#perform a sanity check on OS
def check_os():
	if os.name != 'nt':
		print('[~] OS: Not Windows\n[-] Quitting!\n')
		exit()
	else:
		print('[~] OS: Windows\n[+] All OK!\n')

#convert evtx files to xml
def evt_to_xml(path,file):
	#check if running on windows
	check_os()
	#define scope of filess
	if file == '*':
		for file in os.listdir(path):
			if file.endswith('.evtx'):
				print('[+] ' + file)
				try:
					check_output('wevtutil qe ' + path + '\\' + file + ' /lf:true /f:XML >> ' + path + '\\' + file + '.xml', shell=True)
				except Exception as exception:
					print('[~] ',exception)
					print('[-] Unable to execute command!')
	else:
		print('[+] ' + file)
		try:
			check_output('wevtutil qe ' + path + '\\' + file + ' /lf:true /f:XML >> ' + path + '\\' + file + '.xml', shell=True)
		except Exception as exception:
			print('[~] ',exception)
			print('[-] Unable to execute command!')
			exit()

def validate_event(event):
	#print the log that is parsed form XML before editing anything
	#print(event)
	if ('EventData' in event['Event']) and not (event['Event']['EventData'] == None):
		if ('Data' in event['Event']['EventData']) and not (event['Event']['EventData']['Data'] == None):
			if not ('@Name' in event['Event']['EventData']['Data']):
				try:
					event['Event']['EventData']['Data'][0]['@Name']
				except:
					group_data = [{'@Name': 'param1', '#text': str(event['Event']['EventData']['Data'])}]
					event['Event']['EventData']['Data'] = group_data
	if ('System' in event['Event']) and not (event['Event']['System'] == None):
		if ('EventID' in event['Event']['System']) and not (event['Event']['System'] == None):
			try:
				event['Event']['System']['EventID']['@Qualifiers']
			except:
				group_data = {'@Qualifiers': 'Unknown', '#text': event['Event']['System']['EventID']}
				event['Event']['System']['EventID'] = group_data
	#print the event log that is not being sent to ELK
	#print(event)
	return event

def push_to_elk(ip,port,index,user,pwd,bulk,scheme):
	elk = None
	if(user == None) and (pwd == None):
		elk = Elasticsearch(ip,scheme=scheme,port=port,)
	else:
		elk = Elasticsearch(ip,http_auth=(user,pwd),scheme=scheme,port=port,)
	try:
		helpers.bulk(elk, bulk)
		return True
	except Exception as exception:
		print('[~] ELK ingestion error')
		print(exception)
		return False

def xml_to_json_to_es(action,path,ip,port,file,index,user,pwd,size,scheme):
	bulk = []
	successful_events = 0
	#define scope of files for converting xml to json
	if file == '*':
		for file in os.listdir(path):
			if file.endswith('.xml'):
				with open(path+'\\'+file) as opened_file:
					events = opened_file.readlines()
					jump=0 
					for line_num in range(0,len(events)):
						if(jump>0):
							jump=jump-1
							continue
						event = events[line_num]
						while not ('<Event' in event and '</Event>' in event):
							line_num = line_num+1
							jump=jump+1
							event = event + '' + events[line_num]
						event = event.replace('\n','')
						event = json.loads(json.dumps(xmltodict.parse(event)))
						event = validate_event(event)
						successful_events=successful_events+1
						if action == 'send':
							bulk.append({
								"_index": index,
								"_type": index,
								"@timestamp": event['Event']['System']['TimeCreated']['@SystemTime'],
								"body": event
								})
							if (len(bulk) == size):
								print('[~] Sending Logs to ELK: ' + str(successful_events))
								logs_sent = False
								#keep looping until the bulked logs have not been sent successfully
								while not logs_sent:
									logs_sent = push_to_elk(ip,port,index,user,pwd,bulk,scheme)
									if logs_sent:
										bulk = []
									else:
										continue
						elif action == 'json':
							print(json.dumps(event, indent=4))
	else:
		bulk = []
		if file.endswith('.xml'):
			with open(path+'\\'+file) as opened_file:
				events = opened_file.readlines()
				jump=0 
				for line_num in range(0,len(events)):
					if(jump>0):
						jump=jump-1
						continue
					event = events[line_num]
					while not ('<Event' in event and '</Event>' in event):
						line_num = line_num+1
						jump=jump+1
						event = event + '' + events[line_num]
					event = event.replace('\n','')
					event = json.loads(json.dumps(xmltodict.parse(event)))
					event = validate_event(event)
					successful_events=successful_events+1
					if action == 'send' or action == 'auto':
						bulk.append({
							"_index": index,
							"_type": index,
							"@timestamp": event['Event']['System']['TimeCreated']['@SystemTime'],
							"body": event
							})
						if (len(bulk) == size):
							print('[~] Sending Logs to ELK: ' + str(successful_events))
							logs_sent = False
							#keep looping until the bulked logs have not been sent successfully
							while not logs_sent:
								logs_sent = push_to_elk(ip,port,index,user,pwd,bulk,scheme)
								if logs_sent:
									bulk = []
								else:
									continue
					elif action == 'json':
						print(json.dumps(event, indent=4))
	print('[~] Sending Logs to ELK: ' + str(successful_events))
	logs_sent = False
	logs_sent = push_to_elk(ip,port,index,user,pwd,bulk,scheme)
	#keep looping until the bulked logs have not been sent successfully
	while not logs_sent:
		logs_sent = push_to_elk(ip,port,index,user,pwd,bulk,scheme)
		if logs_sent:
			bulk = []
		else:
			continue
	print('[+] Successfully processed the logs of file')

def process(action,path,ip,port,file,index,user,pwd,size,scheme):
	if action == 'xml':
		evt_to_xml(path,file)
	if (action == 'send') or (action == 'json'):
		xml_to_json_to_es(action,path,ip,port,file,index,user,pwd,size,scheme)
	if (action == 'auto'):
		evt_to_xml(path,file)
		if not file == '*':
			file = file + '.xml'
		xml_to_json_to_es(action,path,ip,port,file,index,user,pwd,size,scheme)

#Perform a sanity check on log path and IP address provided by user
def sanity_check(action,path,ip,file,scheme):
	if not action or (action != 'xml' and action != 'send' and action != 'json' and action != 'auto'):
		print('[-] Please specify a valid action i.e. xml, send, json, auto')
		exit()
	if not path:
		print('[-] Excavator needs to know the path to logs')
		exit()
	elif not os.path.isdir(''+path):
		print('[-] Specified path does not exist')
		exit()
	if file != '*':
		if not os.path.isfile(path + '\\' + file):
			print('[-] Specified file does not exist')
			exit()
	if not ip and (action=='auto' or action=='send'):
		print('[-] IP not specified')
		exit()
	elif ip:
		sanity = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip)
		if not (bool(sanity) and all(map(lambda n: 0 <= int(n) <= 255, sanity.groups()))):
			print('[-] Invalid IP address!')
			exit()
	if scheme and not (scheme == 'http' or scheme == 'https'):
		print('[-] Proper scheme not defined.')
		exit()

#main
if __name__ == '__main__':
	parser = argparse.ArgumentParser('Excavator.py')
	parser.add_argument('-m', metavar='<action>', type=str, help='auto, json, send, xml')
	parser.add_argument('-p', metavar='<path>', type=str, help='path to Evtx files')
	parser.add_argument('-ip', metavar='<ip>', help='elasticsearch IP')
	parser.add_argument('-port', metavar='<port>', type=int, default=9200, help='elasticsearch port')
	parser.add_argument('-f', metavar='<file>', type=str, default='*', help='evtx file to process. Only use for single file')
	parser.add_argument('-i', metavar='<index>', type=str, default='excavator', help='name of ELK index')
	parser.add_argument('-user', metavar='<user>', type=str, help='username of ELK for authorization')
	parser.add_argument('-pwd', metavar='<pass>', type=str, help='password of ELK for authorization')
	parser.add_argument('-s', metavar='<size>', type=int, default=100, help='size of queue, default=100')
	parser.add_argument('-scheme', metavar='<size>', type=str, default='http', help='http or https')
	if len(sys.argv) <= 1:
		parser.print_help()
		exit()
	args = parser.parse_args()
	sanity_check(args.m,args.p,args.ip,args.f,args.scheme)
	process(args.m,args.p,args.ip,args.port,args.f,args.i,args.user,args.pwd,args.s,args.scheme)