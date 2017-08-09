import os
import sys
from pprint import pprint
import re
import json
# import simplejson as json
from bs4 import BeautifulSoup
import requests
import string
import csv


regex = re.compile(r'[\n\r\t]')

def readfile(data):

    for i in range(0, len(data['CVE_Items']), 1): 
        try:
            CVE_data_meta = data['CVE_Items'][i]['CVE_data_meta']['CVE_ID']
            product_name = data['CVE_Items'][i]['CVE_affects']['CVE_vendor']['CVE_vendor_data'][0]['CVE_product']['CVE_product_data'][0]['CVE_product_name']
            description = str(data['CVE_Items'][i]['CVE_description']['CVE_description_data'][0]['value'])
            scores = data['CVE_Items'][i]['CVE_impact']['CVE_impact_cvssv2']['bm']
            availability_score = str(scores['a'])
            attack_complexity_score = str(scores['ac'])
            integrity_score = str(scores['i'])
            confidentiality_score = str(scores['c'])
            scope_score = str(scores['score'])
            authentication_score = str(scores['au']) 
            attack_vector_score = str(scores['av'])
            CWE = str(data['CVE_Items'][i]['CVE_problemtype']['CVE_problemtype_data'][0]['description'][0]['value'])
            CWE_num  = CWE.split('-')[1]
            if CWE_num.isdigit():
                cwe_title, cwe_description, cwe_languages, cwe_consequences, cwe_likihood, cwe_mitigrations = CWE_description(CWE_num)
                csvRow = [CVE_data_meta, product_name, description, availability_score, attack_vector_score, integrity_score, confidentiality_score, scope_score, authentication_score, attack_vector_score, CWE, cwe_title, cwe_description, cwe_languages, cwe_consequences, cwe_likihood, cwe_mitigrations]
                with open('data.csv', "a") as csv_file:
                    writer = csv.writer(csv_file, delimiter='|')
                    writer.writerow(csvRow)
            else: 
                csvRow = [CVE_data_meta, product_name, description, availability_score, attack_vector_score, integrity_score, confidentiality_score, scope_score, authentication_score, attack_vector_score]
                with open('data.csv', "a") as csv_file:
                    writer = csv.writer(csv_file, delimiter='|')
                    writer.writerow(csvRow)
        except:
            continue 

        print '\t' + str(i) + " of " + str(len(data['CVE_Items']))
        

def CWE_description(cwe):
    cwe_reference = 'http://cwe.mitre.org/data/definitions/'
    html = requests.get(cwe_reference + cwe)
    soup = BeautifulSoup(html.content, "html.parser")
    title = str(soup.find("h2").text.split(':')[1].strip())
    description = str(soup.findAll("div", { "id" : "Description" })[0].text.strip()[11:])
    description = regex.sub(' ', description)
    languages = str(soup.findAll("div", { "id" : "Applicable_Platforms" })[0].text.strip()[40:])
    languages = regex.sub(' ', languages)
    consequences = str(soup.findAll("div", { "id" : "Common_Consequences" })[0].text[31:].strip())
    consequences = regex.sub(' ', consequences)
    likihood = str(soup.findAll("div", { "id" : "Likelihood_of_Exploit" })[0].text[22:].strip())
    mitigations = str(soup.findAll("div", { "id" : "Potential_Mitigations" })[0].text[22:].strip())
    mitigations = regex.sub(' ', mitigations)
    return title, description, languages, consequences, likihood, mitigations
 

def loadfile():
    with open('data.csv', "wb") as csv_file:
            writer = csv.writer(csv_file, delimiter='|')
            csvRow = ["CVE_code", "product_name", "description", "availability_score", "attack_vector_score", "integrity_score", "confidentiality_score", "scope_score", "authentication_score", "attack_vector_score", "cwe_code", "cwe_title", "cwe_description", "cwe_languages", "cwe_consequences", "cwe_likelihood", "cwe_mitigrations"]
            writer.writerow(csvRow)

    for files in os.listdir('json'): 
        if files.endswith('.json'):
            with open('json/' + files) as f:
                print files 
                data = json.load(f)
                readfile(data)
        else:
            continue    

    csv_file.close()

def main():
    loadfile()

if __name__ == "__main__":
    main()
