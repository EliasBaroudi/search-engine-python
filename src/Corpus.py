# Correction de G. Poux-Médard, 2021-2022

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

# =============== CLASSE CORPUS ===============

import urllib, urllib.request
import xmltodict

class Corpus:

    """!
    @class Corpus
    @brief Cette classe régie le fonctionnement du corpus
    
    Cette classe permet de créer un corpus à partir des CVE fournies dans le script principal.
    Dans la création du corpus, une étape importante consiste à rechercher des documents sur arXiv.
    Elle utilise les trois derniers mots présents dans le titre de la CVE pour effectuer une recherche sur arXiv, dans la section Computer Science - Cryptography and Security.
    Les articles liés aux CVE sont ensuite enregistrés dans un dictionnaire appelé link.
    """

    def __init__(self, nom):
        """!
        @brief Initialise le corpus.
        
        @param nom : Nom du corpus à definir.
        """
         
        self.nom = nom
        self.cve = {}
        self.link = {}
        self.date = ''
        self.name = ''
        self.desc = ''
        self.ndoc = 0

    def add(self, doc):

        """!
        @brief Ajoute les CVE au corpus.
        
        @param doc : Represente la réference à l'objet CVE.

        Ajout des CVE au corpus.
        Recherche des articles correspondant à la vulnérabilité sur arXiv en utilisant les trois derniers mots du nom de la vulnérabilité.
        """

        self.date = doc.dateAdded
        self.desc = doc.shortDescription
        self.name = doc.vulnerabilityName 
        self.ndoc += 1 #Nombre de cve

        self.cve[self.ndoc] = doc # Ajout des cve
        
        # Ajout des articles correspondant aux cve
        query = self.name.split(' ')
        query = query[-3:]
        query = '+'.join(query).lower()

        print(query)
        data = urllib.request.urlopen(f'http://export.arxiv.org/api/query?search_query=all:{query}+AND+cat:cs.CR&max_results=3')
        data = xmltodict.parse(data.read().decode('utf-8'))

        try:
            pdf = []
            for i, entry in enumerate(data["feed"]["entry"]):
                for link in entry.get("link", []):
                    if link["@type"] == "application/pdf":
                       pdf.append( link["@href"] )  # Ajout du lien de l'article
            self.link[doc.cveID] = pdf
        except:
            print('Aucun document trouvé')
            self.link[doc.cveID] = 'Aucun article'

# =============== REPRESENTATION ===============

    def show(self, n_docs=-1, tri="abc"):

        """!
        @brief Permet d'afficher le corpus.
        
        @param n_docs (-1 par défaut) : Nombre de documents à afficher.
        @param tri ("abc" par défaut) : Type de tri à faire (alphabétique ("abc") ou numérique ("123")).

        Utilisation de la fonction repr
        """

        docs = list(self.cve.values())
        if tri == "abc":  # Tri alphabétique
            docs = list(sorted(docs, key=lambda x: x.vulnerabilityName.lower()))[:n_docs]
        elif tri == "123":  # Tri temporel
            docs = list(sorted(docs, key=lambda x: x.dateAdded))[:n_docs]

        print("\n".join(list(map(repr, docs))))

    def __repr__(self):

        """!
        @brief Representation du corpus
        
        Affiche l'id de la CVE ainsi que les liens trouvés sur Arxiv
        """

        docs = list(self.cve.values())
        docs = list(sorted(docs, key=lambda x: x.vulnerabilityName.lower()))
        
        result = []
        for doc in docs:
            cveID = doc.cveID 
            link = self.link.get(cveID, "Lien non disponible")
            
            result.append(f"{str(doc)}\nArticles : {link}")
                    
        return "\n".join(result)

# ============== GETTERS =======================

    def getNdoc(self):
        """!
        @brief Getter du nombre de CVE
    
        """
        return self.ndoc
    
    def getCve(self):
        """!
        @brief Getter de la liste des CVE
    
        """
        return self.cve

