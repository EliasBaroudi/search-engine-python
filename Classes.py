# Correction de G. Poux-Médard, 2021-2022

# =============== CLASSE CVE ===============

class CVE:
    def __init__(self, cveID="", dateAdded="", notes="", nvdData=None, product="", shortDescription="", vulnerabilityName=""):
        self.cveID = cveID
        self.dateAdded = dateAdded
        self.notes = notes
        self.nvdData = nvdData if nvdData is not None else []
        self.product = product
        self.shortDescription = shortDescription
        self.vulnerabilityName = vulnerabilityName
            
    def __str__(self):
        return f"CVE ID: {self.cveID}\nVulnerability Name: {self.vulnerabilityName}"
    
    def getType():
        return 'CVE'
    
# =============== CLASSE ARXIV ===============

class ArxivDocument:
    def __init__(self, titre="", auteur="", date="", url="", texte="",co_auteurs=""):
        self.titre = titre  
        self.auteur = auteur  
        self.date = date  
        self.url = url  
        self.texte = texte  
        self.co_auteurs = co_auteurs  

    def getCoAuteurs(self):
        return self.co_auteurs
    
    def setCoAuteurs(self,co_auteurs=0):
        self.nbcom = co_auteurs

    def __str__(self):
        return f"{self.titre}, par {self.auteur}, co-Auteurs : {self.co_auteurs}, source : {self.getType()}"

    def getType(self):
        return 'Arxiv'


