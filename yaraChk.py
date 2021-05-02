# This is a short python script meant for testing YARA rules against a specified directory.
# You can get a dataset of malware to test YARA rules with from a website such as virusshare.com.

import subprocess
import os
import stat
import errno
import sys
from io import StringIO
import yara

def Yara_check(directory):
	matchCnt = 0
	totalCnt = 0
	print("Scanning files in directory:", directory)
	rules = yara.compile(filepath='Hajime.yara')
	
	# Iterate through data/downloads directory
	for file in os.listdir(directory):

		filename = os.fsdecode(file)
		# print("Value of file:", file)
		realLocation = directory + filename
		out = subprocess.Popen(['file', realLocation],
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT)

		stdout,stderr = out.communicate()


		if b'executable' in stdout: # if file is executable
			totalCnt += 1
			# Check file/match with YARA
			matches = rules.match(realLocation, timeout=60)
			# print("Value of matches:", matches)
			if not matches:
				print("Undetected sample found:", filename)
			else:
				matchCnt += 1
				print("File matches YARA rule:", filename)
		else:
			print("Not a executable file:", filename)
	print("Matches found:", matchCnt)
	print("Total files checked:", totalCnt)
	
def main():
	# Set target directory for testing the yara rule
	directory = "/malwareSamples/"
	Yara_check(directory) # check malware files with Yara

if __name__ == "__main__":
	main()
