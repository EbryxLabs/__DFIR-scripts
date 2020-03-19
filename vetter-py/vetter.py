'''
Name: Vetter
Description: Calculate hashes from a given directory and check against VT's databases
Or, you can scan a file on VT and check it's output

Author: Ebryx
Version: 0.2
Date: 18-02-2020

'''

# Library imports
import os
import requests
import time
import json
import hashlib
import platform
import configparser
import argparse

from datetime import datetime
from virus_total_apis import PublicApi

currTime = datetime.now()
currTime = currTime.strftime("%d-%m-%Y_%H%M%S")

# Helper Functions

def saveVtResults(vtResults, mode):
	''' Stores VT's results in a file in the same directory '''

	for result in vtResults:
		jsonResult = json.dumps(result, indent=4)
		fileObj = open(f'vetter-{mode}-{currTime}.json', 'a+')
		print(jsonResult, file=fileObj)

def getFiles(directory):
	'''Return the files in the current directory and all its child directories'''

	targetFiles = []
	fileCount = 0

	for root, dirs, files in os.walk(directory):
		
		for file in files:
			fileName = os.path.abspath(os.path.join(root, file))
			#print("[+] Successfully found file at: " + str(fileName))	
			fileCount += 1
			try:
				targetFiles.append(fileName)
			except:
				print(f"[-] An error occured while processing file: {fileName}")

	print(f"[+] Located all files. Final Count: {fileCount}")
	return targetFiles

def saveHashes(hashes, mode):
	''' Save all hashes in files '''

	with open(f"vetter-{platform.node()}-{mode}.txt", "a") as fileObj:
		for aHash in hashes:
			record = str(aHash[1]) + " ; " + str(aHash[0]) + " \n"
			fileObj.write(record)

# VirusTotal Search

def processVtMode(directory, config):
	'''Starts up VT mode for searching hashes'''

	vt = setupVt(config)
	getSearchReports(vt, directory)

def setupVt(config):
	'''Initialize the VirusTotal Public API Object'''
	
	API_KEY = returnApiKey(config)
	vt = PublicApi(API_KEY)
	return vt

def returnApiKey(configFile):
	'''Returns the VT API Key from the configuration file '''

	config = configparser.ConfigParser()

	try:
		config.read(configFile)
	except: 
		print("[-] Error in reading config.ini. Setup the configuration properly and execute Vetter.")
	vtApiKey = config['VirusTotal']['apiKey']
	
	if vtApiKey:
		print("[+] Loaded VT API Key")

	return vtApiKey

def getSearchReports(vtObj, directory):

	extensions = ['txt']
	hashFiles = getHashFiles(directory, extensions)
	if not hashFiles:
		# TODO Add this argument support
		print("[-] No files found to match hashes from. Please use the '--files' argument to specify your files or rename them with 'vetter'")
		exit()

	searchCount = 1
	vtOutputs = []
	hashLength = (32, 40, 64)

	for file in hashFiles:
		with open(file, 'r') as fileObj:
			for line in fileObj:
				if not ";" in line:
					continue

				hash = line.split(";")[0].rstrip(" ")
				fileName = line.split(";")[1].lstrip(" ").rstrip(" \n")
				if len(hash) not in hashLength:
					print(f"[-] Unable to process hash: {hash}")
					continue

				# TODO: Add generator support! (or async calls for faster execution)
				# TODO: Add support for batch reporting
				response = vtObj.get_file_report(hash)
				compResponse = {
					'response': response,
					'file_name': fileName
				}	
				vtOutputs.append(compResponse)
				if searchCount%4 == 0:
					analyzeVtOutput(vtOutputs)
					vtOutputs = []
					print("[+] Cool down time to stay within assigned quota!")
					time.sleep(60)

				searchCount += 1	

def getHashFiles(directory, extensions):

	hashFiles = []
	fileMatchKeywords = ['vetter', 'md5', 'sha1', 'sha-1', 'sha-256', 'sha256']

	for root, dirs, files in os.walk(directory):
		for file in files:
			try:
				fileName, fileExt = file.split(".")
				matches = [option for option in fileMatchKeywords if option in fileName]

				if len(matches) >= 1 and fileExt in extensions:
					hashFiles.append(file)

			except:
				pass

	return hashFiles

def analyzeVtOutput(outputs):

	vtResults = []
	noVtResultsAvailable = []
	vtLink = "https://https://www.virustotal.com/gui/file/"

	for output in outputs:

		singleResult = output['response']

		try:
			respCode = singleResult['response_code']

			# There's an error due to the limit being crossed or some other issue
			if respCode == 204 or ("error" in singleResult.keys()):
				print(f"[-] ERROR: {singleResult['error']}")
				return

			# The hash isn't available on VT and needs manual scanning
			elif respCode == 200 and (singleResult['results']['response_code'] == 0):
				print(f"[-] The hash isn't available for searching on VT. Check the 'manual-scan' file for more information.")
				noVtResultsAvailable.append(output['file_name'])
		
			# The hash is available on VT and might be a positive
			elif respCode == 200 and ("scans" in singleResult['results'].keys()):
				results = singleResult['results']
				sha1Hash = results['sha1']
				message = f'https://www.virustotal.com/gui/file/{sha1Hash}/detection'
				result = {
					'File': output['file_name'],
					'SHA-256 Hash': results['sha256'],
					'SHA1 Hash': sha1Hash,
					'MD5 Hash': results['md5'],
					'Positives': results['positives'],
					'Total': results['total'],
					'Message': message
				}
				print(f"[+] Found a match. Positives: {result['Positives']} out of {result['Total']}")

				vtResults.append(result)

			else:
				print("[-] Illegal output received by VT.")
		
		except Exception as e:

			if hasattr(e, 'message'):
				print(e.message)
			else:
				print(e)

	if vtResults is not []:
		saveVtResults(vtResults, mode='results')
	
	if noVtResultsAvailable is not []:
		saveVtResults(noVtResultsAvailable, mode='manual-search')
		

# Hashing

def processHashMode(args):

	currDir = args['dir']
	# Parse the algorithm choice
	hashingAlgos = args['algo'].split(',')

	# Get all files in the given directory
	targetFiles = getFiles(currDir)

	# Calculate hashes and save them 
	calculateHashes(hashingAlgos, targetFiles)

def calculateBlockHash(bytesiter, hasher):
	''' Processes each block in bytes and updates the hash '''

	for block in bytesiter:
		hasher.update(block)
	return hasher.hexdigest()

def processFile(fileName, blockSize=65536):
	'''Returns data in chunks for processing by the hashing algorithm'''

	try:
		with open(fileName, 'rb') as fileObj:
			block = fileObj.read(blockSize)
			while len(block) > 0:
				yield block
				block = fileObj.read(blockSize)
	except:
		print(f"[-] Failure in processing file: {fileName}")

def calculateHashes(hashingAlgos, files):
	'''Calculate file hashes against each found file '''

	md5hash = []
	sha1hash = []
	sha256hash = []

	for algo in hashingAlgos:
		algoName = algo.lower()
		if algoName == "md5":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.md5())
				# Format: File Name, Hash
				md5hash.append((aFile, calcHash))
			print("[+] MD5 hashes calculated.")
			saveHashes(md5hash, "md5")
	
		elif algoName == "sha1" or algoName == "sha-1":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha1())
				sha1hash.append((aFile, calcHash))
			print("[+] SHA-1 hashes calculated.")
			saveHashes(sha1hash, "sha1")

		elif algoName == "sha256" or algoName == "sha-256":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha256())
				# Just need the file name? Use this: .split('\\')[-1] with aFile and voila!
				sha256hash.append((aFile, calcHash))
			print("[+] SHA-256 hashes calculated.")		
			sha256 = 1
			saveHashes(sha256hash, "sha256")

# Scanner

def processScanMode(config, filePath):
	'''Setup scan mode by configuring API and then present report'''

	vt = setupVt(config)
	getScanReport(vt, filePath)

def getScanReport(vtObj, filePath):
	'''Scans the given file on VT'''

	# TODO: Find existing reports on VT to save bandwidth
	
	results = vtObj.scan_file(filePath)
	if results['response_code'] == 200:
		scanReport = {
			'File Path': filePath,
			'scan_ID': results['results']['scan_id'],
			'SHA1': results['results']['sha1'],
			'SHA256': results['results']['sha256'],
			'MD5': results['results']['md5'],
			'Permalink': results['results']['permalink'],
			'Message': results['results']['verbose_msg'],
		}

		# TODO: Write a mode to get the scanned report only (since new scans are queued only)
		fileReport = vtObj.get_file_report(scanReport['scan_ID'])

		fileOutput = json.dumps(fileReport, indent=4)
		jsonOutput = json.dumps(scanReport, indent=4)
		fileObj = open(f'vetter-scan-{currTime}.json', 'a+')
		print(jsonOutput, file=fileObj)
		print(fileOutput, file=fileObj)

		print("[+] Successfully scanned the file and saved output in the current directory.")

	elif results['response_code'] == 204:
		print("[-] You've crossed your quota limits. Please wait for a minute to continue scanning")
		exit()

	else:
		print("[-] Either the file is already scanned on VT or there's a different issue. Crash output: ")
		print(results)
	
# General Calls

def processModes(args):
	''' Determine the appropriate execution flow based on selected mode '''

	mode = args['mode']

	if mode == "hash":
		processHashMode(args)
	
	elif mode == "search":	
		processVtMode(args['dir'], args['config'])
	
	elif mode == "scan":
		processScanMode(args['config'], args['filepath'])
	
	elif mode == "auto":
		processHashMode(args)
		processVtMode(args['dir'], args['config'])

def sanityCheck(args):
	''' Check for the sanity of all arguments passed '''
	possibleModes = ('hash', 'search', 'scan', 'auto')

	# Check if configuration file exists
	if not (os.path.exists(args['config'])):
		print(f"[-] Error reading the configuration file: {args['config']}")
		exit()

	# Configure the right directory
	elif not os.path.isdir(''+args['dir']):
		print("[ERROR] Specified path does not exist. Issue: --dir ")
		exit()

	elif args['mode']=="scan":
		if not os.path.isfile(args['filepath']):
			print("[ERROR] Use the correct file path to scan. Issue: --filepath")
			exit()

	elif args['mode'] not in possibleModes:
		print('[ERROR] Wrong mode selected!')
		exit()

def parseArgs():
	''' Parse arguments from command line '''

	ap = argparse.ArgumentParser()
	ap.add_argument("--dir", metavar="Directory to scan", required=True, help="Starting point of files to hash or hashes to search on VT (./)")
	ap.add_argument("--config", metavar="Configuration file", default="config.ini", help="Configuration file for VT (config.ini)")
	ap.add_argument("--algo", metavar="Algorithms to use", default="SHA256", help="Hashing algorithms [MD5, SHA1, SHA256*]")
	ap.add_argument("--filepath", metavar="File to scan on VT", help="Scan the file on VT by using it's complete path {MAX SIZE: 32MB}")
	ap.add_argument("--mode", metavar="Mode of operations [hash/search/scan/auto]", required=True, help="Calculate hashes, search hashes, or scan a file on VT. 'auto' calculates hashes and searches them on VT")
	args = vars(ap.parse_args())
	return args

def main():
	''' Starting point of our program '''
	
	args = parseArgs()
	sanityCheck(args)

	processModes(args)

if __name__ == '__main__':
	main()
