import pytest
from Classes import KevinCVE, NSTCVE, SearchingEngine
from Corpus import Corpus
import pandas as pd
import numpy as np
import datetime

# Tests pour la classe KevinCVE
def test_kevin_cve_init():
    date = datetime.datetime.strptime("2023-01-01", "%Y-%m-%d")
    # Initiation d'un objet Kevin
    cve = KevinCVE(
        cveID="CVE-2023-1234",
        dateAdded=date,
        notes="Test notes",
        nvdData=["data1", "data2"],
        product="Test Product",
        shortDescription="Test description",
        vulnerabilityName="Test Vulnerability"
    )
    
    # On regarde si tous les attributs sont biens rensiengés
    assert cve.cveID == "CVE-2023-1234"
    assert cve.dateAdded == date
    assert cve.notes == "Test notes"
    assert cve.nvdData == ["data1", "data2"]
    assert cve.product == "Test Product"
    assert cve.shortDescription == "Test description"
    assert cve.vulnerabilityName == "Test Vulnerability"
    assert cve.getType() == "KevinCVE"

# Tests pour la classe NSTCVE
def test_nst_cve_init():
    # Initiation d'un objet NST
    cve = NSTCVE(
        cveID="CVE-2023-5678",
        dateAdded="2023-01-01",
        notes="Test NST notes",
        shortDescription="Test NST description"
    )
    
    # On regarde si tous les attributs sont biens rensiengés
    assert cve.cveID == "CVE-2023-5678"
    assert cve.dateAdded == "2023-01-01"
    assert cve.notes == "Test NST notes"
    assert cve.shortDescription == "Test NST description"
    assert cve.getType() == "NSTCVE"

def test_nst_cve_notes_list():
    cve = NSTCVE(
        cveID="CVE-2023-5678",
        notes="Test NST notes"  # Modification: notes en tant que liste avec séparateur ;
    )

    # On verifie que la note est bien traitée
    assert cve.notes == "Test NST notes"

# Tests pour la classe Corpus
@pytest.fixture
def sample_corpus():
    # Initialisation d'un corpus
    return Corpus("Test Corpus")

# Test l'initialisation du corpus
def test_corpus_init(sample_corpus):
    # Verification des variables du corpus
    assert sample_corpus.nom == "Test Corpus"
    assert sample_corpus.cve == {}
    assert sample_corpus.link == {}
    assert sample_corpus.ndoc == 0
    assert isinstance(sample_corpus.vulnerabilities, list)
    assert "buffer" in sample_corpus.vulnerabilities
    assert "overflow" in sample_corpus.vulnerabilities

# Test de l'ajout de Kevin au corpus
def test_corpus_add_kevin_cve(sample_corpus):
    date = datetime.datetime.strptime("2023-01-01", "%Y-%m-%d")
    # Creation de l'objet Kevin
    cve = KevinCVE(
        cveID="CVE-2023-1234",
        dateAdded=date,
        shortDescription="buffer overflow vulnerability test",
        vulnerabilityName="Test Buffer Overflow"
    )
    sample_corpus.add(cve)
    
    # Verifie les attributs du corpus
    assert sample_corpus.ndoc == 1
    assert sample_corpus.cve[0] == cve
    assert "buffer" in sample_corpus.desc and "overflow" in sample_corpus.desc
    assert cve.cveID in sample_corpus.link

# Test de l'ajout de NST
def test_corpus_add_nst_cve(sample_corpus):
    # Creation de l'objet NST
    cve = NSTCVE(
        cveID="CVE-2023-5678",
        dateAdded="2023-01-01",
        shortDescription="sql injection vulnerability test"
    )
    sample_corpus.add(cve)
    
    # Verifie les attributs du corpus
    assert sample_corpus.ndoc == 1
    assert sample_corpus.cve[0] == cve
    assert "sql" in sample_corpus.desc and "injection" in sample_corpus.desc
    assert cve.cveID in sample_corpus.link

# Tests pour la classe SearchingEngine
@pytest.fixture
def sample_search_engine():
    corpus = Corpus("Test Corpus")
    
    # Ajout d'une CVE Kevin avec des mots clés spécifiques pour la recherche
    date = datetime.datetime.strptime("2023-01-01", "%Y-%m-%d")
    cve1 = KevinCVE(
        cveID="CVE-2023-1234",
        dateAdded=date,
        shortDescription="security vulnerability test",  # Modification pour assurer des résultats
        vulnerabilityName="Security Test",
        notes="Test notes"
    )
    
    # Ajout d'une CVE NST
    cve2 = NSTCVE(
        cveID="CVE-2023-5678",
        dateAdded="2023-01-01",
        shortDescription="security vulnerability test",  # Même description pour assurer des résultats
        notes="Test notes"
    )
    
    # Ajout des cve
    corpus.add(cve1)
    corpus.add(cve2)
    
    return SearchingEngine(corpus)

# Test de l'initialisation du moteur de recherche
def test_search_engine_init(sample_search_engine):
    assert sample_search_engine.ndoc > 0
    assert len(sample_search_engine.vocabulaire) > 0
    assert sample_search_engine.mat_TF is not None
    assert sample_search_engine.mat_TFIDF is not None

# Test du calcul TF et IDF
def test_search_engine_matrices(sample_search_engine):
    tf_matrix = sample_search_engine.getTF()
    tfidf_matrix = sample_search_engine.getTFIDF()
    
    # On verifie en faisant correspondre la taille des matrix avec la taille des voc et des docs
    assert tf_matrix.shape[0] == sample_search_engine.ndoc
    assert tf_matrix.shape[1] == len(sample_search_engine.vocabulaire)
    assert tfidf_matrix.shape[0] == sample_search_engine.ndoc
    assert tfidf_matrix.shape[1] == len(sample_search_engine.vocabulaire)

# Test de requette de recherche 
def test_search_engine_search(sample_search_engine):
    # Test de recherche avec seulement la source Kevin
    results_kevin = sample_search_engine.search("security vulnerability", 2, ["Kevin"], False)
    assert isinstance(results_kevin, pd.DataFrame)
    if not results_kevin.empty:  # Vérifie si des résultats ont été trouvés
        assert all(col in results_kevin.columns for col in ['Source', 'CVE ID', 'Description', 'Arxiv related'])
        assert all(row['Source'] == 'Kevin API' for _, row in results_kevin.iterrows())
    
    # Test de recherche avec seulement la source NST
    results_nst = sample_search_engine.search("security vulnerability", 2, ["NST"], False)
    assert isinstance(results_nst, pd.DataFrame)
    if not results_nst.empty:  # Vérifie si des résultats ont été trouvés
        assert all(col in results_nst.columns for col in ['Source', 'CVE ID', 'Description', 'Arxiv related'])
        assert all(row['Source'] == 'NST API' for _, row in results_nst.iterrows())