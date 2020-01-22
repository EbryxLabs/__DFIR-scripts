import argparse
from datetime import datetime
from utils import setup_logger
from spellchecker import SpellChecker
# from argparse import RawTextHelpFormatter


# global vars
g_vars = {
	"time": {
		"start": datetime.utcnow(),
		"end": ""
	},
	"output_file": "",
	"valid_operations": {
		"display_dns": "Converts display DNS file into a CSV for easier analysis",
		"firewall_rules": "Parses the output of firewall rule dumps",
		"ntst_anb": "Parses the output from ntsts_anb file of exir-win",
		"sc_query": "Parses sc query files. Module isn't complete yet"
	},
	'verbosity': 'INFO',
	'logger': setup_logger(),
	'replacement_keywords': {
		# string1: replace_with_string2
		',': '|=|',
		"\n": "",
		"\t": ""
	},
	"whitelists": {
		"firewall_rules": [
			"BranchCache",
			""
		]
	}
}


def replace_keywords(mstr):
	try:
		for k, v in g_vars.get('replacement_keywords').items():
			if k in mstr: mstr = mstr.replace(str(k), str(v))
	except Exception as e:
		g_vars.get('logger').error('Exception {} occurred in replace_keywords for {}'.format(e, mstr))
	return mstr


def is_spelling_correct(word_list):
	ret = True
	if len(SpellChecker().unknown(word_list)) > 0: ret = False
	if not ret: g_vars.get('logger').warning('Spell Check failed for {}'.format(word_list))
	return ret


def parser_sc_query(input_file, output_file):
	log_msg("#,ServiceName,DisplayName,Type,State,StateDetails,Win32ExitCode,ServiceExitCode,CheckPoint,WaitHint,Interesting", output_file)
	try:
		len_records = 0
		with open(input_file) as in_file:
			in_file = in_file.readlines()
			len_in_file = len(in_file)
			g_vars.get('logger').info('Num lines: {}'.format(len_in_file))
			idx = 1 # Since this is the first readable line in file
			while True:
				mstr = []
				interesting = ''
				idx2 = 0
				for idx2 in range(0, 9):
					g_vars.get('logger').debug('file line num: {}'.format(idx + idx2))
					if idx + idx2 >= len_in_file: break
					line = replace_keywords(in_file[idx + idx2].rstrip('\n').lstrip(' '))
					if idx2 == 8 and line == '': idx2 -= 1
					g_vars.get('logger').info('line: {}'.format(line))
					if 'STOPPED' in in_file[idx + idx2 - 1] and idx2 == 4: mstr.append('')
					elif ':' in line: mstr.append(line.split(':')[1].lstrip(' '))
					else: mstr.append(line.lstrip(' '))
					# if idx2 in [1] and not is_spelling_correct(line.split(':')[1].lstrip(' ').split(' ')):
					# 	interesting += 'DisplayName spellings not correct --- '
				mstr.append(interesting.rstrip(' --- '))
				len_records += 1
				log_msg("{},{}".format(len_records, ','.join(mstr)), output_file)
				# input('Press to continue...')
				idx += idx2 + 2
				if idx > len_in_file: 
					print("No more records to look for...")
					break
	except Exception as e:
		g_vars.get('logger').error("Exception {} occurred in parser_sc_query...".format(e))


def parser_ntst_anb(input_file, output_file):
	log_msg("#,Executable,Executable2,Protocol,LocalAddress,LocalPort,ForeignAddress,ForeignPort,State", output_file)
	try:
		records = []
		with open(input_file) as in_file:
			in_file = in_file.readlines()
			idx = 4 # Since this is the first readable line in display_dns output file
			while True:
				next_idx = 2
				mstr = []
				jump = False
				# executable info
				executable_info = in_file[idx+1].rstrip('\n')
				if 'Can not obtain ownership information' in executable_info:
					mstr.append('')
					mstr.append('Can not obtain ownership information')
				elif '[' in executable_info:
					mstr.append('')
					mstr.append(replace_keywords(in_file[idx+1].rstrip('\n').replace('[', '').replace(']', '').lstrip(' ').rstrip(' ')))
				elif len(executable_info) > 56: 
					mstr.append('')
					mstr.append('')
					next_idx = 1
				else: 
					jump = True
					mstr.append(replace_keywords(in_file[idx+1].rstrip('\n').replace('[', '').replace(']', '').lstrip(' ').rstrip(' ')))
					mstr.append(replace_keywords(in_file[idx+2].rstrip('\n').replace('[', '').replace(']', '').lstrip(' ').rstrip(' ')))
				g_vars.get('logger').debug('Executable info extracted -- {}...'.format(mstr))
				# network info
				g_vars.get('logger').debug(in_file[idx])
				network_info = [i for i in in_file[idx].rstrip('\n').split(" ") if i != '']
				g_vars.get('logger').debug('Starting extraction of network info...')
				g_vars.get('logger').debug(network_info)
				for idx2, item in enumerate(network_info):
					g_vars.get('logger').debug('Currently processing idx - {} and item - {}'.format(idx2, item))
					if idx2 == 1 or idx2 == 2:
						if ']' in item:
							addr_port = item.split(']:')
							addr_port[0] += ']'
						else: addr_port = item.split(':')
						g_vars.get('logger').debug(addr_port)
						for item2 in addr_port: mstr.append(item2)
					else: mstr.append(item)
				###
				idx += next_idx + (1 if jump else 0)
				records.append(','.join(mstr))
				records[-1] = "{},{}".format(len(records), records[-1])
				log_msg(records[-1], output_file)
				# input('Press any key to continue...')
				if idx >= len(in_file) - 1: 
					g_vars.get('logger').info("No more records to look for...")
					break
	except Exception as e:
		g_vars.get('logger').error("Exception {} occurred in parser_ntst_anb...".format(e))


def highlight_interesting_logs(m_list, mstr, list_type='whitelist'):
	ret = 'Intersting'
	if list_type == 'whitelist':
		for item in m_list:
			if item in mstr:
				ret = ''
				break
	return ret


def parser_firewall_rules(input_file, output_file):
	log_msg("#,RuleName,Enabled,Direction,Profiles,Grouping,LocalIP,RemoteIP,Protocol,LocalPort,RemotePort,EdgeTraversal,Action,Interesting", output_file)
	try:
		records = []
		with open(input_file) as in_file:
			in_file = in_file.readlines()
			g_vars.get('logger').debug('File to lines...')
			idx = 1 # Since this is the first readable line in display_dns output file
			while True: # each firewall rule
				mstr = ''
				idx2 = 0
				while True: # each item inside firewall rule
					if idx + 1 > len(in_file): 
						idx += 1
						g_vars.get('logger').info("No more records to look for inner loop...")
						break
					if "----------------------------------------------------------------------" in in_file[idx+idx2]:
						idx2 += 1
						g_vars.get('logger').debug('First if cleared...')
						continue
					elif in_file[idx+idx2] == "\n":
						idx += idx2 + 1
						g_vars.get('logger').debug('First elif cleared...')
						break
					splitted = in_file[idx+idx2].split(":")
					g_vars.get('logger').debug('Split complete...')
					if len(splitted) < 2: 
						splitted = replace_keywords(splitted[0].lstrip(" ").rstrip("\n"))
						g_vars.get('logger').debug('Replacement complete...')
						mstr = mstr[:-1]
					else: 
						splitted = replace_keywords(splitted[1].lstrip(" ").rstrip("\n"))
					mstr += "{},".format(splitted)
					idx += 1
				if mstr != '':
					# highlight inetersting logs
					mstr += highlight_interesting_logs(g_vars.get('whitelists').get('firewall_rules'), mstr.split(',')[0], list_type='whitelist')
					records.append(mstr)
					records[-1] = "{},{}{}".format(len(records), records[-1], ','*(9 - mstr.count(',')))
					log_msg(records[-1], output_file)
				if idx > len(in_file): 
					g_vars.get('logger').info("No more records to look for outer loop...")
					break
	except Exception as e:
		g_vars.get('logger').error("Exception {} occurred in parser_firewall_rules...".format(e))


def find_next_dspdns_index(in_file, idx):
	try:
		len_in_file = len(in_file)
		while True:
			idx += 1
			if idx < len_in_file:
				g_vars.get('logger').debug('finding next idx - line: {}'.format(in_file[idx].replace('\n', '')))
				if "Record Name" in in_file[idx]: 
					g_vars.get('logger').debug('finding next idx in Record Name - idx: {}'.format(idx))
					break
				elif "----------------------------------------" in in_file[idx]: 
					g_vars.get('logger').debug('finding next idx in ----------- - idx: {}'.format(idx))
					idx -= 1
					break
				else: pass
			else: 
				g_vars.get('logger').debug('finding next idx in len_file - idx: {}'.format(idx))
				break
		return idx
	except Exception as e:
		g_vars.get('logger').error("Exception {} occurred in find_next_dspdns_index...".format(e))
	return idx


def parser_display_dns(input_file, output_file):
	log_msg("#,Record,RecordName,RecordType,TTL,DataLength,Section", output_file)
	try:
		records = []
		with open(input_file) as in_file:
			in_file = in_file.readlines()
			len_in_file = len(in_file)
			idx = 3 # Since this is the first readable line in display_dns output file
			record = ''
			while True:
				idx2 = 0
				g_vars.get('logger').debug('=============Started iteration for idx: {} - line: {}'.format(idx, in_file[idx].replace('\n', '')))
				g_vars.get('logger').debug('File idx: {}'.format(idx))
				mstr = ''
				if '----------------------------------------' in in_file[idx+1]:
					if 'No records' in in_file[idx+2] or 'Name does not exist.' in in_file[idx+2]:
						mstr += in_file[idx].rstrip('\n').lstrip('    ') + ',' + in_file[idx+2].rstrip('\n').lstrip('    ')
				if 'Record Name' in in_file[idx+2]:
					for i in range(2, 8):
						mstr += replace_keywords(in_file[idx-idx2+i].split(" : ")[1]) + ","
					idx += 7
				
				if idx < len_in_file:
					if idx + 4 < len_in_file and '----------------------------------------' in in_file[idx+4]:
						idx += 3
					else: idx += 1
				g_vars.get('logger').debug('Get all values - new idx: {}'.format(idx))
				if mstr != '':
					records.append(mstr)
					records[-1] = "{},{}".format(len(records), records[-1])
					log_msg(records[-1], output_file)
				if idx >= len_in_file - 2:
					g_vars.get('logger').info("No more records to look for...")
					break
	except Exception as e:
		g_vars.get('logger').error("Exception {} occurred in parser_display_dns...".format(e))



def log_msg(mstr, output_file):
	with open(output_file, 'a') as o:
		s_mstr = str(mstr)
		g_vars.get('logger').info("{} --- {}".format(datetime.utcnow(), s_mstr))
		o.write('{}\n'.format(s_mstr))


def arg_parser():
	parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-i", "--input_file", help="/path/to/input/file. Default is {}".format(None), default=None, type=str)
	parser.add_argument("-v", "--verbosity", help="Verbosity level of the script. Default is {}".format(g_vars.get('verbosity')), default=g_vars.get('verbosity'), type=str)
	parser.add_argument("-p", "--operation", help="Type of operation to be performed on the input_file.\n1. display_dns --- {}\n2. firewall_rules --- {}\n3. ntst_anb --- {}\n4. sc_query --- {}\n".format(
			g_vars.get('valid_operations').get('display_dns'),
			g_vars.get('valid_operations').get('firewall_rules'),
			g_vars.get('valid_operations').get('ntst_anb'), 
			g_vars.get('valid_operations').get('sc_query')
		), 
		default=None, type=str
	)
	args = parser.parse_args()
	g_vars["output_file"] = "report-{}-{}.csv".format(str(args.operation).replace(" ", ""), g_vars["time"]["start"].timestamp())
	g_vars.get('logger').info("Output file name {}...".format(g_vars['output_file']))
	return args


def main():
	args = arg_parser()
	g_vars.get('logger').setLevel(args.verbosity)

	print("Checking if {} is a valid operation...".format(args.operation))
	if args.operation in g_vars["valid_operations"]:
		print("Valid operation {} detected...".format(args.operation))
		if args.operation == "display_dns":
			parser_display_dns(args.input_file, g_vars["output_file"])
		elif args.operation == "firewall_rules":
			parser_firewall_rules(args.input_file, g_vars["output_file"])
		elif args.operation == "ntst_anb":
			parser_ntst_anb(args.input_file, g_vars["output_file"])
		elif args.operation == "sc_query":
			parser_sc_query(args.input_file, g_vars["output_file"])
		else:
			g_vars.get('logger').warning("Operation {} is unknown...".format(args.operation))
	else:
		g_vars.get('logger').warning("Operation {} is unknown...".format(args.operation))


if __name__ == "__main__":
	log_msg("Start Time: {}".format(g_vars["time"]["start"]), "output.log")
	main()
	# print(g_vars.get('valid_operations').get('sc_qtdg'))
	g_vars["time"]["end"] = datetime.utcnow()
	log_msg("End Time: {}".format(g_vars["time"]["end"]), "output.log")
	log_msg("Time Difference: {}".format(g_vars["time"]["end"] - g_vars["time"]["start"]), "output.log")
	log_msg("Output file: {}".format(g_vars.get('output_file')), "output.log")