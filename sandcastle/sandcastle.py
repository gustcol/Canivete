#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, commands, requests, random, string
from threading import BoundedSemaphore, Thread
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from argparse import ArgumentParser

print """
   ____             __             __  __   
  / __/__ ____  ___/ /______ ____ / /_/ /__ 
 _\ \/ _ `/ _ \/ _  / __/ _ `(_-</ __/ / -_)
/___/\_,_/_//_/\_,_/\__/\_,_/___/\__/_/\__/ 
                                            
S3 bucket enumeration // release v1.3 // ysx & Parasimpaticki

"""
#Create file for write check
filename = 'sndt_' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(15)) + '.txt'
threadCount = 20 #Default

targetStem = ""
inputFile = ""
bucketFile = ""

parser = ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", dest="targetStem",
                    help="Select a target stem name (e.g. 'shopify')", metavar="shopify")
group.add_argument("-f", "--file", dest="inputFile",
                    help="Select a target list file", metavar="targets.txt")
parser.add_argument("-b", "--bucket-list", dest="bucketFile",
                    help="Select a bucket permutation file (default: bucket-names.txt)", default="bucket-names.txt", metavar="bucket-names.txt")
parser.add_argument("-o", "--output", dest="outputFile",
                    help="Select a output file", default="", metavar="output.txt")
parser.add_argument("--threads", dest="threadCount",
                    help="Choose number of threads (default=50)", default=50, metavar="50")
args = parser.parse_args()

semaphore = BoundedSemaphore(threadCount)

def checkBuckets(target,name):
	for c in {"-",".","_",""}:
		for l in (True,False):
			if(l):
				bucketName = target + c + name
			else:
				bucketName = name + c + target
			try:
				r = requests_retry_session().head("http://%s.s3.amazonaws.com" % bucketName)
			except:
				continue
			if r.status_code != 404:
				readCheck = commands.getoutput("aws s3 ls s3://%s" % bucketName)
				if "The specified bucket does not exist" not in readCheck:
					writeCheck = commands.getoutput("aws s3 cp %s s3://%s" % (filename, bucketName))
					formatOutput(sys.stdout,bucketName, readCheck, writeCheck)
					if args.outputFile:
						formatOutput(outFile,bucketName, readCheck, writeCheck)
	semaphore.release()

def formatOutput(outFile,bucketName, readCheck, writeCheck):
	if ("An error occurred" not in readCheck) or ("An error occurred" not in writeCheck):
		outFile.write("[!] Found a match: %s\n" % bucketName)
	if "An error occurred" not in readCheck:
		outFile.write("[+] Read access test (%s):%s\n" % (bucketName,readCheck))
	if "An error occurred" not in writeCheck:
		outFile.write("[+] Write access test (%s):%s\n" % (bucketName,writeCheck))

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def loadBuckets(target):
	threads = []
	for name in bucketNames:
		threads.append(Thread(target=checkBuckets, args=(name,target)))
	for thread in threads:  # Starts all the threads.
		semaphore.acquire()
		thread.start()
	for thread in threads:  # Waits for threads to complete before moving on with the main script.
		thread.join()

if __name__ == "__main__":	
	open(filename,'a').close() #Create random file for write test
	with open(args.bucketFile, 'r') as b: 
		bucketNames = [line.strip() for line in b] 
		lineCount = len(bucketNames)
		b.close()
	if args.outputFile:
		outFile = open(args.outputFile,"w")

	if(args.inputFile):
		with open(args.inputFile, 'r') as f: 
			targetNames = [line.strip() for line in f]
			f.close()
		for target in targetNames:
			print "[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (target, lineCount, b.name)
			loadBuckets(target)
			print "[*] Enumeration of '%s' buckets complete." % (target)
	else:
		print "[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (args.targetStem, lineCount, b.name)
		loadBuckets(args.targetStem)
		print "[*] Enumeration of '%s' buckets complete." % (args.targetStem)

	print "[*] Cleaning up..."
	try:
		os.remove(filename)
	except:
		pass
	try:
		outFile.close()
	except:
		pass
