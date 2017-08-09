import os
import sys
from pprint import pprint
import re
import json
from bs4 import BeautifulSoup
import requests
import string
import csv
from collections import Counter


dictionary = {
				'malware' : ['malware', 'ransomware', 'worms', 'worm', 'trojan', 'trojan.', 'virus', 'viruses', 'malicious code', 'spyware', 'adware', 'bot', 'bots', 'bugs', 'bug', 'rootkit', 'trojan horse', 'trojanhorse', 'logic bomb', 'crimeware', 'bloatware', 'vaperware', 'ware', 'scareware'], 
				'phishing spoofing' : ['spear', 'whaling', 'clone phishing', 'link spoofing', 'website spoofing', 'pharming', 'pharm', 'google docs phishing', 'dropbox phishing', 'dns cache', 'poisoning', 'in-session', 'social engineering', 'social', 'arp', 'irs'], 
				'sql injection attack' : ['sql', 'injection', 'unsanitized input', 'blind', 'out-of-band', 'xml injection', 'sqlia', 'union sqlia', 'dbms'], 
				'cross-site scripting (XSS)' : ['xss', 'cross-site', 'beef hooking' 'beef'], 
				'denial of service (DoS)' : ['dos', 'ddos', 'pdos', 'ackscan', 'ack scan', 'denial of service', 'denial-of-service'], 
				'session hijacking and man-in-the-middle attacks' : ['Session Hijacking', 'man-in-the-middle', 'cookies', 'passive hijacking', 'active hijacking'], 
				'botnet' : ['botnet', 'zombie', 'robot'], 
				'keylogger' : ['keylogger', 'keystroke', 'logging', 'keyboard capturing', 'spambot'],
				'eavesdropping' : ['eavesdropping', 'fiber tapping'], 
				'ip spoofing' : ['ip spoofing', 'ip faking', 'packets', 'proxy', 'proxy server'], 
				'crediental harvesting' : ['crediental', 'bruteforcing', 'brute', 'bruteforce', 'cookies', 'wordlist', 'social-engineer toolkit', 'social-engineer', 'toolkit', 'site cloner', 'harvest', 'harvesting', 'rainbow table']
			} 

results = dict()

x=0

def loadfile(): 
    with open('data.txt', 'r') as f:
	    reader = csv.reader(f, dialect='excel', delimiter='|')
	    for row in reader:
	    	global x
	    	x=x+1
	       	data = Counter(row[2].split())
	    	for key, value in data.iteritems():
				for k,v in dictionary.iteritems():
					for i in v:
						if key.lower() == i:
							if not k in results:
								results[k] = [(row[0], row[1], row[7])]
							else:
								# cvs = int(results.get(k)[0][2].split('.')[0]) + int(row[7].split('.')[0])
			 					results[k].append((row[0], row[1], row[7])) 
		try: 
			more_data = Counter(row[12].split())
			for key, value in more_data.iteritems():
				for k,v in dictionary.iteritems():
					for i in v:
						if key.lower() == i:
							if not k in results:
								results[k] = [(row[0], row[1], row[7])]
							else:
								# cvs = int(results.get(k)[0][2].split('.')[0]) + int(row[7].split('.')[0])
			 					results[k].append((row[0], row[1], row[7])) 
		except: 
			continue	
	# analyze()	   

# def analyze():
# 	print x 
# 	for key, value in results.items():
		# list(set(t))
    		# print key, len([item for item in value if item]), float(len([item for item in value if item]))/float(x) * 100

def writefile():

	print x
	for key, value in results.iteritems():
		try: 
			length = len([item for item in value if item])
			percent = float(len([item for item in value if item]))/float(x) * 100
			average = float([int(item.split('.')[0]) + int(item.split('.')[0]) for item in value[0][2] if item])/float(length)
		except ValueError:
			pass
		row = [key, length, percent, average]
		with open('anaylsis.txt', "wb") as csv_file:
			print row
			writer = csv.writer(csv_file, delimiter='|')
			writer.writerow(row)

def main():
    loadfile()
    writefile()

if __name__ == "__main__":
    main()
