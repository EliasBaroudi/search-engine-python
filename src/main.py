"""
@file main.py
@brief Script principal de l'application.

Ce fichier permet la création de nos objets CVE ainsi que de notre corpus.
Dans un premier temps, nous recherchons les CVE les plus connues à l'aide de l'API Kevin et NST.
Ensuite, nous créons le corpus à partir de ces CVE.
Enfin, nous sollicitons le moteur de recherche avec une requête contenant des mots clés.

@author BAROUDI Elias & GHLAMI Nassim
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
import zipfile
import io
import json

def init(nb): 
    
    # Initialisations
    path = 'data.pkl'
    collection = []
    page_number = 2
    items_per_page = nb

    # Verification de la présence des données sinon telechargement via l'API puis sauvegarde
    if os.path.exists(path):

        print('CVE trouvées')
        
        with open("data.pkl", "rb") as f:
            collection = pickle.load(f)
    
    else:
        
        print('Aucun fichier de CVE trouvé')

        # Recupération des données avec l'API
        print('Chargement des CVE Kevin')
        response = requests.get(f'https://kevin.gtfkd.com/kev?page={page_number}&per_page={items_per_page}')
        data_vuln = response.json()

        # Parcourir la liste des vulnérabilités 
        data_vuln = data_vuln['vulnerabilities']
        for cve in data_vuln:
            
            # On récupère les informations nécessaires
            cveID = cve['cveID']
            dateAdded = cve['dateAdded']
            notes = cve['notes']
            nvdData = cve['nvdData']
            product = cve['product']
            shortDescription = cve['shortDescription']
            vulnerabilityName = cve['vulnerabilityName']
            dateAdded = datetime.datetime.strptime(dateAdded, "%Y-%m-%d")   # Formatage de la date
            
            # Creation de l'objet CVE de l'api Kevin
            cve_kevin = KevinCVE(cveID, dateAdded, notes, nvdData, product, shortDescription, vulnerabilityName)
            collection.append(cve_kevin) # Ajout de l'objet à la collection


        print('Chargement des CVE NST')
        response = requests.get('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip')
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            # Obtention du Json dans le ZIP
            file_names = zip_file.namelist()
            
            # Lire le fichier Json à partir du ZIP
            with zip_file.open(file_names[0]) as json_file:
                data = json.load(json_file)  # Charger le fichier JSON
                
        for cve_item in data['CVE_Items'][:nb]:  # Affiche les nb premieres CVE
            
            # Recupération des informations
            cve_id = cve_item['cve']['CVE_data_meta']['ID']
            date = cve_item['publishedDate']
            
            try:
                notes = cve_item['cve']['references']['reference_data'][0]['url']
            except:
                notes = 'Aucune note'

            description = cve_item['cve']['description']['description_data'][0]['value']

            # Creation de l'objet CVE de l'api NST
            cve_nst = NSTCVE(cve_id,date,notes,description)
            collection.append(cve_nst) # Ajout de l'objet à la collection

        # Sauvegarde du fichier collection
        with open("data.pkl", "wb") as f:
            pickle.dump(collection, f)
            
    return collection

# =============== 2 : CORPUS ===============

from Corpus import *

# Construction du corpus à partir des CVE
def get_corpus(collection):

    path = 'corpus.pkl'

    # Verification de la présence du corpus dans les fichiers
    if os.path.exists(path):
        
        print('Fichier de sauvegarde trouvé')

        # Ouverture du fichier, puis lecture avec pickle
        with open("corpus.pkl", "rb") as f:
            corpus = pickle.load(f)

    # Sinon création via la classe Corpus
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

        # Sauvegarde de la variable corpus
        with open("corpus.pkl", "wb") as f:
            pickle.dump(corpus, f)
            
    return corpus

# ============== 3 : Moteur de recherche ==============

from Classes import SearchingEngine

# Creation du moteur de recherche à partir du corpus
def get_engine(corpus): 
    search = SearchingEngine(corpus)
    return search









