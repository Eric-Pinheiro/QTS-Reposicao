"""
API do Hub Solidário com demonstração comparativa de vulnerabilidades e correções,
incluindo os gabaritos dos exercícios práticos.
"""

import html
import sqlite3
from fastapi import FastAPI, HTTPException, status, Query
from pydantic import BaseModel

app = FastAPI(title="Hub Solidario - Laboratorio de Seguranca")

def obter_banco():
    """Gera conexão com banco SQLite em memória com dados pré-carregados."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comentarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            conteudo TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campanhas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            meta REAL NOT NULL
        )
    """)
    
    # Inserção de dados iniciais
    cursor.execute("""
        INSERT INTO usuarios (nome, email, senha, is_admin)
        VALUES 
            ('Administrador', 'admin@hubsolidario.org', 'segredo_admin_123', 1),
            ('Voluntario Lucas', 'lucas@voluntariado.org', 'senha_lucas_456', 0)
    """)
    cursor.execute("""
        INSERT INTO campanhas (titulo, meta)
        VALUES 
            ('Agasalho Solidario', 5000.00),
            ('Sopa para Todos', 3000.00)
    """)
    conn.commit()
    return conn

db = obter_banco()

class RequisicaoLogin(BaseModel):
    email: str
    senha: str

class RequisicaoComentario(BaseModel):
    autor: str
    conteudo: str

class RequisicaoPerfil(BaseModel):
    avatar_html: str

# ENDPOINTS INTENCIONALMENTE VULNERÁVEIS

@app.post("/vulneravel/login")
def login_vulneravel(dados: RequisicaoLogin):
    cursor = db.cursor()
    query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
    cursor.execute(query)
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")

    return {"email": usuario[2], "is_admin": bool(usuario[3]), "status": "Autenticado com sucesso"}

@app.post("/vulneravel/comentarios")
def comentar_vulneravel(dados: RequisicaoComentario):
    cursor = db.cursor()
    cursor.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (dados.autor, dados.conteudo))
    db.commit()
    return {"autor": dados.autor, "conteudo": dados.conteudo}

@app.get("/vulneravel/campanhas/buscar")
def buscar_campanhas_vulneravel(termo: str = Query(...)):
    """Gabarito Exercício 1 (Vulnerável) - Permite UNION SELECT"""
    cursor = db.cursor()
    query = f"SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE '%{termo}%'"
    cursor.execute(query)
    resultados = cursor.fetchall()
    return [{"id": r[0], "titulo": r[1], "meta": r[2]} for r in resultados]

@app.post("/vulneravel/perfil/avatar")
def atualizar_avatar_vulneravel(dados: RequisicaoPerfil):
    """Gabarito Exercício 2 (Vulnerável) - Filtro ingênuo que barra <script> mas aceita onerror"""
    conteudo = dados.avatar_html
    if "<script>" in conteudo.lower():
        raise HTTPException(status_code=400, detail="Script detectado e bloqueado!")
    
    return {"status": "Avatar atualizado", "html_renderizado": conteudo}

# ENDPOINTS SEGUROS (OWASP)

@app.post("/seguro/login")
def login_seguro(dados: RequisicaoLogin):
    cursor = db.cursor()
    query = "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?"
    cursor.execute(query, (dados.email, dados.senha))
    usuario = cursor.fetchone()

    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas")

    return {"email": usuario[2], "is_admin": bool(usuario[3]), "status": "Autenticado com sucesso"}

@app.post("/seguro/comentarios")
def comentar_seguro(dados: RequisicaoComentario):
    autor_seguro = html.escape(dados.autor.strip())
    conteudo_seguro = html.escape(dados.conteudo.strip())

    cursor = db.cursor()
    cursor.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (autor_seguro, conteudo_seguro))
    db.commit()
    return {"autor": autor_seguro, "conteudo": conteudo_seguro}

@app.get("/seguro/campanhas/buscar")
def buscar_campanhas_seguro(termo: str = Query(...)):
    """Gabarito Exercício 1 (Seguro) - Uso de LIKE com Prepared Statements"""
    cursor = db.cursor()
    query = "SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE ?"
    cursor.execute(query, (f"%{termo}%",))
    resultados = cursor.fetchall()
    return [{"id": r[0], "titulo": r[1], "meta": r[2]} for r in resultados]

@app.post("/seguro/perfil/avatar")
def atualizar_avatar_seguro(dados: RequisicaoPerfil):
    """Gabarito Exercício 2 (Seguro) - Codificação total de entidades HTML"""
    conteudo_seguro = html.escape(dados.avatar_html)
    return {"status": "Avatar atualizado", "html_renderizado": conteudo_seguro}