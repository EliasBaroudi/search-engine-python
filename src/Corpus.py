# Correction de G. Poux-Médard, 2021-2022

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

# =============== CLASSE CORPUS ===============
# Inspiré de la correction fournie lors des TDs

import urllib, urllib.request
import xmltodict

class Corpus:

    """
    @class Corpus
    @brief Cette classe régie le fonctionnement du corpus
    
    Cette classe permet de créer un corpus à partir des CVE fournies dans le script principal.
    Dans la création du corpus, une étape importante consiste à rechercher des documents sur arXiv.
    Elle utilise un dictionnaire de vulnérabilités pour effectuer une recherche sur arXiv, dans la section Computer Science - Cryptography and Security.
    Si un mot de la description de la CVE est présent dans le dictionnaire de vulnérabilités, on l'ajoute à la requête arXiv.
    Les articles liés aux CVE sont ensuite enregistrés dans un dictionnaire appelé link.
    """

    def __init__(self, nom):
        """
        @brief Initialise le corpus.
        
        @param nom : Nom du corpus à definir.
        """

        # Liste de mots clés pour detecter les mots perinents dans la description des CVE
        self.vulnerabilities = [
            "buffer",
            "overflow"
            "cross-site",
            "scripting",
            "xss",
            "sql",
            "injection",
            "request",
            "forgery",
            "csrf",
            "buffer",
            "overflow",
            "command",
            "directory",
            "traversal",
            "broken",
            "authentication",
            "sensitive",
            "data",
            "exposure",
            "security",
            "misconfiguration",
            "insecure",
            "deserialization",
            "xml",
            "external",
            "entities",
            "xxe",
            "server",
            "side",
            "ssrf",
            "privileged",
            "privilege",
            "privileges",
            "elevated",
            "escalation",
            "remote",
            "code",
            "commands",
            "execute",
            "execution",
            "rce",
            "path",
            "denial",
            "service",
            "dos",
            "mitm",
            "weak",
            "password",
            "policies",
            "clickjacking",
            "session",
            "fixation",
            "insufficient",
            "logging",
            "monitoring"
        ]

        self.nom = nom
        self.cve = {}
        self.link = {}
        self.date = ''
        self.desc = ''
        self.ndoc = 0

    def add(self, doc):

        """
        @brief Ajoute les CVE au corpus.
        
        @param doc : Represente la réference à l'objet CVE.

        Ajout des CVE au corpus.
        Recherche des articles correspondant à la vulnérabilité sur arXiv en utilisant les mots-clés de la description.
        La classe dispose d'une liste de mots-clés (vulnérabilités). En parcourant la description des CVE, si un mot est présent dans la liste de mots-clés, on l'ajoute à la requête envoyée sur arXiv.
        """
        
        self.date = doc.dateAdded
        self.desc = doc.shortDescription
        
        self.cve[self.ndoc] = doc # Ajout des cve
        self.ndoc += 1 # Nombre de cve incrémenté
        
        # Ajout des articles correspondant aux cve
        query = []
        for char in [',','.']:
            self.desc = self.desc.replace(char, "")

        self.desc = self.desc.split(' ')

        for word in self.desc:
            if word.lower() in self.vulnerabilities:
                query.append(word.lower())

        query = '+'.join(query)
        # On s'assure que la requete contient des mots
        if len(query) != 0:
            query += '+vulnerability'
        else:
            # Si jamais aucun mot n'a été jugé pertinent on prend les 3 derniers mots du nom de la vulnérabilité
            if doc.getType() == 'KevinCVE': # Cela ne fonctionne uniquement si la CVE provient de l'api de Kevin
                query = doc.vulnerabilityName.split(' ')
                query = query[-3:]
                query = '+'.join(query).lower()
            else:
                # On rend volontairement la requete obselète : puisque l'alogrtihme de récupération des mots perinents n'a pas fonctionné
                query = '!?!?!?'

        data = urllib.request.urlopen(f'http://export.arxiv.org/api/query?search_query=all:{query}+AND+cat:cs.CR&max_results=3')
        data = xmltodict.parse(data.read().decode('utf-8'))

        try:
            pdf = []
            for i, entry in enumerate(data["feed"]["entry"]):
                for link in entry.get("link", []):
                    if link["@type"] == "application/pdf":
                       pdf.append( link["@href"] )  # Ajout du lien de l'article

            # On s'assure que la CVE n'est pas déjà présente dans le dictionnaire
            if doc.cveID not in self.link:
                self.link[doc.cveID] = pdf
        except:
            # On s'assure que la CVE n'est pas déjà présente dans le dictionnaire
            if doc.cveID not in self.link:
                self.link[doc.cveID] = 'Aucun article'

# =============== REPRESENTATION ===============

    def __repr__(self):

        """
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
        """
        @brief Getter du nombre de CVE
    
        """
        return self.ndoc
    
    def getCve(self):
        """
        @brief Getter de la liste des CVE
    
        """
        return self.cve

