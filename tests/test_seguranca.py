"""
Suíte de testes ofensivos e defensivos para validação de SQL Injection e XSS.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)

# AUDITORIA OFENSIVA (Endpoints Vulneráveis)

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    # ARRANGE
    payload_malicioso = {"email": "admin@hubsolidario.org' --", "senha": "qualquer"}
    
    # ACT
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)
    
    # ASSERT
    assert resposta.status_code == 200
    assert resposta.json()["email"] == "admin@hubsolidario.org"

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    # ARRANGE
    payload_xss = {"autor": "Atacante", "conteudo": "<script>alert(1)</script>"}
    
    # ACT
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)
    
    # ASSERT
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]

@pytest.mark.security
def test_deve_explorar_sqli_union_em_campanhas():
    """Gabarito Exercício 1: Extração de dados (senhas) com UNION SELECT"""
    # ARRANGE: O payload fecha o LIKE com %', injeta o UNION e comenta o resto.
    # Como a tabela campanhas tem 3 colunas (id, titulo, meta), selecionamos 3 colunas da usuarios
    payload_union = "%' UNION SELECT id, email, senha FROM usuarios --"
    
    # ACT
    resposta = cliente.get(f"/vulneravel/campanhas/buscar?termo={payload_union}")
    
    # ASSERT: A senha secreta do admin deve vazar no campo "meta" ou "titulo" do JSON
    dados = resposta.json()
    assert resposta.status_code == 200
    textos_retornados = str(dados)
    assert "segredo_admin_123" in textos_retornados, "O ataque UNION SELECT falhou em extrair a senha."

@pytest.mark.security
def test_deve_burlar_filtro_xss_ingenuo_com_onerror():
    """Gabarito Exercício 2: Burlar o filtro da palavra <script> usando tags de imagem"""
    # ARRANGE: O vetor não contém "<script>", passando pelo filtro ingênuo.
    payload_imagem_maliciosa = {"avatar_html": "<img src='x' onerror='alert(document.cookie)'>"}
    
    # ACT
    resposta = cliente.post("/vulneravel/perfil/avatar", json=payload_imagem_maliciosa)
    
    # ASSERT: A tag perigosa é devolvida sem sanitização
    assert resposta.status_code == 200
    assert "<img src='x' onerror=" in resposta.json()["html_renderizado"]

# AUDITORIA DEFENSIVA (Endpoints Seguros)

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    # ARRANGE
    payload_malicioso = {"email": "admin@hubsolidario.org' --", "senha": "x"}
    
    # ACT
    resposta = cliente.post("/seguro/login", json=payload_malicioso)
    
    # ASSERT
    assert resposta.status_code == 401

@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    # ARRANGE
    payload_xss = {"autor": "Atacante", "conteudo": "<script>alert(1)</script>"}
    
    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)
    
    # ASSERT
    assert resposta.status_code == 200
    assert "<script>" not in resposta.json()["conteudo"]
    assert "&lt;script&gt;" in resposta.json()["conteudo"]

@pytest.mark.security
def test_seguro_deve_bloquear_sqli_union():
    """Gabarito Exercício 1 (Defesa)"""
    # ARRANGE
    payload_union = "%' UNION SELECT id, email, senha FROM usuarios --"
    
    # ACT
    resposta = cliente.get(f"/seguro/campanhas/buscar?termo={payload_union}")
    
    # ASSERT: O banco interpreta o termo como string literal e não acha campanhas com esse nome absurdo
    assert resposta.status_code == 200
    assert len(resposta.json()) == 0

@pytest.mark.security
def test_seguro_deve_sanitizar_imagem_com_onerror():
    """Gabarito Exercício 2 (Defesa)"""
    # ARRANGE
    payload = {"avatar_html": "<img src='x' onerror='alert(document.cookie)'>"}
    
    # ACT
    resposta = cliente.post("/seguro/perfil/avatar", json=payload)
    
    # ASSERT: As aspas e chaves do HTML devem ter sido convertidas
    html_retornado = resposta.json()["html_renderizado"]
    assert "<img" not in html_retornado
    assert "&lt;img" in html_retornado