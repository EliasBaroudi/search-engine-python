import pytest
from Classes import CVE, ArxivDocument, SearchingEngine
from Corpus import Corpus
import pandas as pd
import numpy as np

# Tests pour la classe CVE
def test_cve_init(): # Création d'une CVE type
    cve = CVE( 
        cveID="CVE-2023-1234",
        dateAdded="2023-01-01",
        notes="Test notes",
        nvdData=["data1", "data2"],
        product="Test Product",
        shortDescription="Test description",
        vulnerabilityName="Test Vulnerability"
    )
    
    # On verifie que chaque champ correspond à nos valeurs
    assert cve.cveID == "CVE-2023-1234"
    assert cve.dateAdded == "2023-01-01"
    assert cve.notes == "Test notes"
    assert cve.nvdData == ["data1", "data2"]
    assert cve.product == "Test Product"
    assert cve.shortDescription == "Test description"
    assert cve.vulnerabilityName == "Test Vulnerability"

def test_cve_str(): # Test de l'affichage
    cve = CVE(cveID="CVE-2023-1234", vulnerabilityName="Test Vulnerability")
    expected_str = "CVE ID: CVE-2023-1234\nVulnerability Name: Test Vulnerability" # Valeur attendue
    assert str(cve) == expected_str


# Tests pour la classe Corpus
@pytest.fixture
def sample_corpus(): # Création d'un corpus fictif
    return Corpus("Test Corpus")

def test_corpus_init(sample_corpus): # Test de l'initialisation d'un corpus fictif

    # Verification des attributs du corpus
    assert sample_corpus.nom == "Test Corpus"
    assert sample_corpus.cve == {}
    assert sample_corpus.link == {}
    assert sample_corpus.ndoc == 0

def test_corpus_add(sample_corpus): # Ajout d'une fausse CVE
    cve = CVE(  
        cveID="CVE-2023-1234",
        vulnerabilityName="Simple Test Vulnerability Name",
        shortDescription="Test description"
    )
    sample_corpus.add(cve)
    
    # Verification que la cve est bien ajoutée
    assert sample_corpus.ndoc == 1 
    assert sample_corpus.cve[1] == cve
    assert "CVE-2023-1234" in sample_corpus.link

def test_corpus_get_ndoc(sample_corpus): # Obtention du nb de doc CVE
    # Verification de la variable ndoc avant l'ajout
    assert sample_corpus.getNdoc() == 0
    
    # Ajout 
    cve = CVE(cveID="CVE-2023-1234")
    sample_corpus.add(cve)

    # Verification que la variable est à 1 après 1 ajout
    assert sample_corpus.getNdoc() == 1

def test_corpus_get_cve(sample_corpus): # Tester la fonction pour obtenir une CVE du corpus
    # Ajout 
    cve = CVE(cveID="CVE-2023-1234")
    sample_corpus.add(cve)
    
    # Verification des valeurs obtenues
    cves = sample_corpus.getCve()
    assert len(cves) == 1
    assert cves[1] == cve

# Tests pour la classe SearchingEngine
@pytest.fixture
def sample_search_engine(): 
    corpus = Corpus("Test Corpus") # Creation d'un corpus

    # Creation de CVEs
    cve1 = CVE(
        cveID="CVE-2023-1234",
        shortDescription="first test vulnerability description"
    )
    cve2 = CVE(
        cveID="CVE-2023-5678",
        shortDescription="second test vulnerability description"
    )
    
    # Ajout des CVEs au corpus
    corpus.add(cve1)
    corpus.add(cve2)
    
    return SearchingEngine(corpus) # Creation d'un objet SearchEngine 

def test_search_engine_init(sample_search_engine): # Test des valeurs d'initialisation
    assert sample_search_engine.ndoc > 0
    assert len(sample_search_engine.vocabulaire) > 0
    assert sample_search_engine.mat_TF is not None
    assert sample_search_engine.mat_TFIDF is not None

def test_search_engine_get_tf(sample_search_engine): # Test de la fonction calcul tf
    tf_matrix = sample_search_engine.getTF()
    assert tf_matrix is not None
    assert tf_matrix.shape[0] == sample_search_engine.ndoc # On verifie que le nb de lignes de la matrice est bien égale au nb de doc dans le corpus
    assert tf_matrix.shape[1] == len(sample_search_engine.vocabulaire) #On verifie qu'il y a autant de colonnes que de mots dans le vocabulaire

def test_search_engine_get_tfidf(sample_search_engine): # Test pour le clacul tfxidf
    tfidf_matrix = sample_search_engine.getTFIDF()
    assert tfidf_matrix is not None
    assert tfidf_matrix.shape[0] == sample_search_engine.ndoc # On verifie que le nb de lignes de la matrice est bien égale au nb de doc dans le corpus
    assert tfidf_matrix.shape[1] == len(sample_search_engine.vocabulaire) #On verifie qu'il y a autant de colonnes que de mots dans le vocabulaire

def test_search_engine_search(sample_search_engine): # Test pour la recherche
    results = sample_search_engine.search("test vulnerability", 2)
    assert isinstance(results, pd.DataFrame) # On verifie que le résultat est bien un DataFrame
    assert len(results) <= 2 # Qu'on a 2 ou plus résultats (2 documents)
    assert all(col in results.columns for col in ['Document ID', 'Score', 'Description', 'CVE Link', 'Arxiv related']) # On verifie que les colonnes correspondent bien
                                                                                                                       # Prouvant que la fonction fonctionne correctement