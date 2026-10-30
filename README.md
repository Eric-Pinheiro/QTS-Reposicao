# 🛡️ Laboratório de Segurança OWASP: SQLi & XSS em APIs

Este é um projeto prático e educacional focado em simular, identificar e corrigir vulnerabilidades de segurança (Injeção de SQL e Cross-Site Scripting - XSS) em uma API construída com Python. 

O laboratório demonstra como códigos gerados de forma negligente (frequentemente por IAs) podem ser explorados e como a engenharia de testes automatizados ajuda a blindar a aplicação.

## Objetivos

- **Auditoria Ofensiva:** Explorar rotas de API vulneráveis usando técnicas de SQL Injection (como subversão de WHERE e UNION SELECT) e XSS (armazenado e bypass com `onerror`).
- **Auditoria Defensiva:** Refatorar o código utilizando boas práticas (Prepared Statements e HTML Escaping).
- **Testes Automatizados:** Utilizar o `pytest` e o padrão AAA (Arrange, Act, Assert) para garantir a segurança das rotas.

## Tecnologias Utilizadas

- **Python 3.10+**
- **FastAPI:** Criação da API.
- **SQLite:** Banco de dados relacional em memória.
- **Pytest & TestClient:** Framework de testes automatizados e simulação de requisições.
- **uv:** Gerenciador de pacotes e ambientes Python ultrarrápido.

## Estrutura do Projeto

```text
lab-seguranca-owasp/
├── pyproject.toml         # Configurações do projeto e do pytest
├── main.py                # Código da API (endpoints vulneráveis e seguros)
├── README.md              # Documentação do projeto
└── tests/
    ├── __init__.py        # Marca o diretório como pacote Python
    └── test_seguranca.py  # Suíte de testes ofensivos e defensivos