"""
@file main.py
@brief Script principal de l'application.

Ce fichier permet la création de nos objets CVE ainsi que de notre corpus.
Dans un premier temps, nous recherchons les CVE les plus connues à l'aide de l'API Kevin.
Ensuite, nous créons le corpus à partir de ces CVE.
Enfin, nous sollicitons le moteur de recherche avec une requête contenant des mots clés.

@author BAROUDI Elias & GHALMI Nassim
@date 28/12/2024
@version v2

"""

# Inspiré des corrections fournies sur les 3 premiers TDs


# =============== 1 : CVE ===================


import requests
import datetime
from Classes import *

import os 
import pickle

def init(): 

    print('Chargement des CVE')
    
    # Initialisation
    path = 'data.pkl'
    cves = []
    collection = []
    page_number = 2
    items_per_page = 50

    # Verification de la présence des données sinon telechargement via l'API puis sauvegarde
    if os.path.exists(path):

        print('CVE trouvées')
        
        with open("data.pkl", "rb") as f:
            data_vuln = pickle.load(f)
    
    else:
        
        print('Aucun fichier de CVE trouvé')
        # Recupération des données avec l'API
        response = requests.get(f'https://kevin.gtfkd.com/kev?page={page_number}&per_page={items_per_page}')
        data_vuln = response.json()

        with open("data.pkl", "wb") as f:
            pickle.dump(data_vuln, f)

    data_vuln = data_vuln['vulnerabilities']
    for vuln in data_vuln:
        cves.append(vuln)

    # print(cves[0]['notes'])

    print("Recerche d'articles correspondant...")
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

    return collection

# =============== 2 : CORPUS ===============

from Corpus import *

# Construction du corpus à partir des documents
# Implementer une sauvegarde
def get_corpus(collection):

    path = 'corpus.pkl'

    if os.path.exists(path):
        
        print('Fichier de sauvegarde trouvé')

        # Ouverture du fichier, puis lecture avec pickle
        with open("corpus.pkl", "rb") as f:
            corpus = pickle.load(f)

    else:

        print('Aucun fichier de sauvegarde trouvé ')

        # Creation du corpus
        n = 0
        corpus = Corpus("Corpus")
        for cve in collection:
            corpus.add(cve)

            # Indication de l'avencement du chargement
            if n%10 == 0:
                print(f"{n}/{len(collection)}")
            n += 1

        # Ouverture d'un fichier, puis écriture avec pickle
        with open("corpus.pkl", "wb") as f:
            pickle.dump(corpus, f)
            
        #corpus.show(tri="abc")
        # print(repr(corpus))

    return corpus

# ============== 3 : Moteur de recherche ==============

from Classes import SearchingEngine

def get_engine(corpus): 
    search = SearchingEngine(corpus)
    return search
    # print(search.search('privileges escalation',5))

# # =============== 2.9 : SAUVEGARDE ===============









