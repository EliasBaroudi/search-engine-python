# Correction de G. Poux-Médard, 2021-2022

# =============== PARTIE 1 =============


# =============== 1 : CVE ===================

collection = []

import requests
import datetime
from Classes import *

page_number = 2
items_per_page = 50
response = requests.get(f'https://kevin.gtfkd.com/kev?page={page_number}&per_page={items_per_page}')
data_vuln = response.json()

cves = []
data_vuln = data_vuln['vulnerabilities']
for vuln in data_vuln:
    cves.append(vuln)

print(cves[0]['notes'])
for cve in cves:
    
    cveID = cve['cveID']
    dateAdded = cve['dateAdded']
    notes = cve['notes']
    nvdData = cve['nvdData']
    product = cve['product']
    shortDescription = cve['shortDescription']
    vulnerabilityName = cve['vulnerabilityName']

    dateAdded = datetime.datetime.strptime(dateAdded, "%Y-%m-%d")    
    
    cve_classe = CVE(cveID, dateAdded, notes, nvdData, product, shortDescription, vulnerabilityName)
    collection.append(cve_classe)

# =============== 2 : CORPUS ===============

from Corpus import *
corpus = Corpus("Corpus")

# Construction du corpus à partir des documents
for cve in collection:
    corpus.add(cve)
#corpus.show(tri="abc")
print(repr(corpus))


# # =============== 2.9 : SAUVEGARDE ===============
# import pickle

# # Ouverture d'un fichier, puis écriture avec pickle
# with open("corpus.pkl", "wb") as f:
#     pickle.dump(corpus, f)

# # Supression de la variable "corpus"
# del corpus

# # Ouverture du fichier, puis lecture avec pickle
# with open("corpus.pkl", "rb") as f:
#     corpus = pickle.load(f)

# # La variable est réapparue
# print(corpus)








