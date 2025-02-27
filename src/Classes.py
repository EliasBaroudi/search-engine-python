# =============== CLASSE CVE ===============

class NSTCVE:
    """
    @class CVE
    @brief Cette classe régie le fonctionnement d'une CVE de l'api NST
    
    """

    def __init__(self, cveID="", dateAdded="", notes="", shortDescription=""):
        """
        @brief Initialise l'objet CVE.

        @param nom : Nom du corpus à définir.
        @param cveID ("" par défaut) : Identifiant de la CVE.
        @param dateAdded ("" par défaut) : Date d'ajout de la CVE.
        @param notes ("" par défaut) : Notes concernant la CVE.
        @param shortDescription ("" par défaut) : Description courte de la CVE.

        Initialise l'objet NSTCVE.
        """

        # Initialisation des attributs
        self.cveID = cveID
        self.dateAdded = dateAdded
        self.notes = notes
        self.shortDescription = shortDescription
            
    def __str__(self):
        """
        @brief Donne une representation de l'objet CVE (son ID ainis que son nom de vulnérabilité)     
        """
        return f"CVE ID: {self.cveID}\nVulnerability Name: {self.shortDescription}"
    
    def getType(self):
        """
        @brief Donne le type de l'objet
        """
        return 'NSTCVE'

class KevinCVE:
    """
    @class CVE
    @brief Cette classe régie le fonctionnement d'une CVE de l'api Kevin
    
    """

    def __init__(self, cveID="", dateAdded="", notes="", nvdData=None, product="", shortDescription="", vulnerabilityName=""):
        """
        @brief Initialise l'objet CVE.

        @param nom : Nom du corpus à définir.
        @param cveID ("" par défaut) : Identifiant de la CVE.
        @param dateAdded ("" par défaut) : Date d'ajout de la CVE.
        @param notes ("" par défaut) : Notes concernant la CVE.
        @param nvdData (None par défaut) : Données supplémentaires concernant la CVE (liste).
        @param product ("" par défaut) : Produit concerné par la CVE.
        @param shortDescription ("" par défaut) : Description courte de la CVE.
        @param vulnerabilityName ("" par défaut) : Nom de la vulnérabilité.

        Initialise l'objet KevinCVE.
        """

        # Initialisation des attributs
        self.cveID = cveID
        self.dateAdded = dateAdded
        self.notes = '\n'.join(notes.split(';'))
        self.nvdData = nvdData if nvdData is not None else []
        self.product = product
        self.shortDescription = shortDescription
        self.vulnerabilityName = vulnerabilityName
            
    def __str__(self):
        """
        @brief Donne une representation de l'objet CVE (son ID ainis que son nom de vulnérabilité)     
        """
        return f"CVE ID: {self.cveID}\nVulnerability Name: {self.vulnerabilityName}"
    
    def getType(self):
        """
        @brief Donne le type de l'objet
        """
        return 'KevinCVE'
    
# =============== CLASSE SEARCH ENGINE ===============
# Classe Search Engine inspirée du modèle développé lors des derniers TDs

from scipy.sparse import csr_matrix
import math
import numpy as np
from numpy.linalg import norm
import pandas as pd

class SearchingEngine:
    """
    @class SearchingEngine

    @brief Classe moteur de l'application, permet de faire des opérations sur le corpus

    Calcul du vocabulaire du corpus, des valeurs TF et des valeurs IDF.
    Construction d'une matrice pour chaque valeur (TF et IDF).
    Permet à l'utilisateur d'effectuer une recherche pour obtenir les documents les plus pertinents en fonction de sa requête, à l'aide de la similarité cosinus.
    """

    def __init__(self, corpus):
        """
        @brief Initialise le moteur de recherche.
        
        @param corpus : Nom du corpus à utiliser.

        Durant l'initialisation, le moteur de recherche calcule immédiatement les matrices TFxIDF.
        Tout d'abord, nous parcourons une première fois les CVE du corpus afin de définir un dictionnaire de vocabulaire, contenant uniquement les mots.
        Ensuite, nous parcourons une deuxième fois les CVE pour calculer la fréquence d'apparition de chaque mot dans chaque document.
        Nous construisons ensuite la matrice TF (Term Frequency).
        Enfin, nous parcourons une dernière fois le corpus pour calculer les valeurs IDF (Inverse Document Frequency) et construire la matrice TFxIDF.

        """

        self.corpus = corpus
        self.list_doc = []
        ens = set()

        self.ndoc = self.corpus.getNdoc() # Nombre de documents
        self.list_doc = self.corpus.getCve() # Liste des CVE

        # Recuperation des descriptions
        for i in range (1,self.ndoc):
            __chaine = self.list_doc[i].shortDescription.split(' ')
            for word in __chaine:
                ens.add(word) # On renseigne les mots dans un ensemble afin de limiter les doublons

        # Creation du vocabulaire
        self.vocabulaire = dict.fromkeys(ens, 0)

        # Préparation pour TF
        num_doc = len(self.list_doc) 
        num_mot = len(self.vocabulaire)  
        self.word_to_idx = {word: idx for idx, word in enumerate(self.vocabulaire.keys())}

        __data = []  
        __rows = [] 
        __cols = []  

        # Calcul des fréquences
        for i in range (1,self.ndoc):
            words = self.list_doc[i].shortDescription.split(' ')
            word_count = dict.fromkeys(self.vocabulaire.keys(), 0)  # On récupère le mot
            for word in words:  # Pour chaque mot dans la description
                if word in word_count:  # Si il est présent dans le vocabulaire 
                    word_count[word] += 1  # Incrémentation dans wordcount
            
            # Remplissage de la matrice 
            for word, count in word_count.items():
                if count > 0:  
                    __rows.append(i)  
                    __cols.append(self.word_to_idx[word])  
                    __data.append(count/len(words))  # Calcul de TF (fréq. d'apparation du mot / le nb de mots dans le doc)

        # Mise a jour de la matrice
        self.mat_TF = csr_matrix((__data, (__rows, __cols)), shape=(num_doc, num_mot))

        # Reinisialisation des var temporaires
        __data = []  
        __rows = [] 
        __cols = []  
        

        # Parcours de tous les documents
        for i in range (1,self.ndoc):
            for word in self.vocabulaire:
                tf = self.mat_TF[i, self.word_to_idx[word]]
                
                n=0
                for j in range (1,self.ndoc): # Calcul du nombre d'apparition dans un doc
                    if word in self.list_doc[j].shortDescription.split(' '):
                        n+=1

                # Calcul du produit tfidf
                tfidf = tf * math.log(self.ndoc/n)
                
                # Stockage dans les variables temporaires
                if tfidf > 0:
                    __rows.append(i)  
                    __cols.append(self.word_to_idx[word])  
                    __data.append(tfidf)

        # Construction de la matrice
        self.mat_TFIDF = csr_matrix((__data, (__rows, __cols)), shape=(num_doc, num_mot))

    def getTF(self):
        """
        @brief Retourne la matrice TF
        """
        return self.mat_TF
    
    def getTFIDF(self):
        """
        @brief Retourne la matrice TFxIDF
        """
        return self.mat_TFIDF

    def search(self, mots, nb, source, only_link):
        """
        @brief Fonction de recherche 

        @brief Fonction de recherche

        @param mots : chaîne de caractères contenant les mots saisis par l'utilisateur pour la recherche
        @param nb : nombre de documents à retourner
        @param source : contient la liste des sources choisies par l'utilisateur
        @only_link : booléen representant le choix de l'utilisateur concenrant les articles scientifiques

        @return pd.DataFrame(res) : DataFrame des CVE les plus pertinents

        Cette fonction permet de trouver les documents les plus pertinents en fonction de la recherche de l'utilisateur.  
        Elle crée un vecteur à partir des mots clés saisis en utilisant un vocabulaire déjà établi.  
        Ensuite, elle calcule le TF (Term Frequency) et l'IDF (Inverse Document Frequency) sur ce vecteur, puis normalise ce dernier.  
        La similarité cosinus est calculée entre le vecteur représentant les mots clés saisis par l'utilisateur et les vecteurs TFxIDF de chaque document.  
        Les similarités sont ensuite triées selon le score.  
        Ensuite, les documents les plus pertinents sont retournés en fonction des identifiants présents dans le vecteur de similarité calculée.
        Enfin, on renvoie les cve seulement si elles correspondent aux filtres.
        """
        

        print(source)

        mot_cles = mots.split(' ')

        vect = np.zeros(len(self.vocabulaire))

        for mot in mot_cles:
            if mot in self.vocabulaire:
                vect[self.word_to_idx[mot]] += 1 / len(mot_cles) # Calcul de TF sur la requette
        
        for word in self.vocabulaire:
            if self.vocabulaire[word] > 0:
                idf = math.log( self.ndoc / self.vocabulaire[word] ) # Calcul de IDF
                vect[self.word_to_idx[mot]] *= idf

        # Simplification de la mat TFIDF
        idf_vect = self.mat_TFIDF.toarray()

        # Normalisation du vecteur requette
        vect_norm = norm(vect)
        if norm(vect) != 0:
            vect = vect / vect_norm

        similarites = []

        # On parcour tous les documents à partir de la matrice tfidf applatie
        for i in range (1,self.ndoc):
            if norm(idf_vect[i]) > 0:
                sim = np.dot(vect, idf_vect[i]) / norm(idf_vect[i]) # Calcul de la similarité cosinus
                similarites.append((i, sim))

        
        similarites.sort(key=lambda x: x[1], reverse=True) # Tri des resultats

        res = []
       

        # On parcours la liste des documents avec leurs similarités
        for id, score in similarites[:nb]:
            
            # Necessaire au bon fonctionnement quand le filtre n'est pas coché
            valide = True
            
            # Si l'utilisateur à coché le filtre 'Liens trouvés uniquement'
            if only_link:
                # Si la liste la valeur des liens d'articles scientifiques est différente de 'Aucun article trouvé'
                if self.corpus.link[self.list_doc[id].cveID] == 'Aucun article':
                    valide = False # Le document est alors valide
                

            #Si la CVE provient de Kevin
            if self.list_doc[id].getType() == 'KevinCVE' and 'Kevin' in source and valide:
                res.append({
                        'Source': 'Kevin API',
                        'CVE ID': self.list_doc[id].cveID, 
                        'Name': self.list_doc[id].vulnerabilityName,
                        'Description': self.list_doc[id].shortDescription,
                        'CVE Link': self.list_doc[id].notes,
                        'Arxiv related': self.corpus.link[self.list_doc[id].cveID], # Recupération des liens aux articles arxiv correspondants
                        'Score': score
                })

            #Si la CVE provient de NST
            elif self.list_doc[id].getType() == 'NSTCVE' and 'NST' in source and valide: 
                
                res.append({
                        'Source': 'NST API',
                        'CVE ID': self.list_doc[id].cveID, 
                        'Name': '',
                        'Description': self.list_doc[id].shortDescription,
                        'CVE Link': self.list_doc[id].notes,
                        'Arxiv related': self.corpus.link[self.list_doc[id].cveID], # Recupération des liens aux articles arxiv correspondants
                        'Score': score
                })
    
        return pd.DataFrame(res)