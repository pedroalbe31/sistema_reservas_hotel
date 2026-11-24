# Sistema de Reservas de Hotel — Estudo de Caso de Sistema Distribuído

Trabalho da disciplina de Aplicações Distribuídas (UNOESC – Campus de Videira). Reproduz o estudo de caso do roteiro
**até a versão 9** (OAuth2 + JWT, scopes, refresh token, sessões, timeout por inatividade e auditoria), usando
**a mesma linguagem e as mesmas bibliotecas** (Python, FastAPI, SQLModel/SQLite, Streamlit) e **modificando o modelo
conceitual** (estratégia 2 do enunciado): o CRUD de `vendas` foi trocado por um CRUD de **reservas de hotel**.

## Integrantes da equipe

- Pedro Henrique Albuquerque
- Jean Carlos Pinz
- Marcos Henrique

## Modelo de dados

| Roteiro (vendas) | Este projeto (reservas) | Tipo |
|---|---|---|
| `id` | `id` | inteiro, chave primária |
| `item` | `hospede` | texto (nome do hóspede) |
| `preco_unitario` | `valor_diaria` | decimal (R$ por diária, até 2 casas) |
| `quantidade` | `diarias` | inteiro > 0 (número de diárias) |

O "faturamento" do roteiro virou **receita total** (soma de `valor_diaria × diarias`). Demais tabelas, como no roteiro:
`usuario`, `refreshtoken`, `logauditoria` e `controleinicializacao`.

## Arquitetura

- **Backend:** API REST em FastAPI (`backend_fastapi.py`), banco SQLite (`hotel.db`, criado automaticamente).
- **Frontend:** Streamlit (`frontend_streamlit.py`), consome a API via HTTP.
- **Segurança (versões 4 a 9):** senha com hash Argon2, OAuth2 Password Flow (`POST /token`), JWT, scopes por rota
  (`reservas:read|create|update|delete`, `auditoria:read`), refresh token com rotação, sessão com `sid`, logout com
  revogação, timeout de 30 min de inatividade e auditoria (`GET /auditoria`).

## Como instalar e rodar

Requisitos: Python 3.10 ou superior e VS Code com a extensão Python (`ms-python.python`).

1. Abra a pasta do projeto no VS Code (`File > Open Folder`).
2. Crie o ambiente virtual e instale as dependências, no terminal do VS Code:

   Windows (PowerShell):
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
   Linux / macOS:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
   (No Windows, ajuste `python.defaultInterpreterPath` em `.vscode/settings.json` para `.venv\\Scripts\\python.exe`.)
3. Em um terminal, execute o **backend**:
   ```
   uvicorn backend_fastapi:app --reload
   ```
   A API fica em http://127.0.0.1:8000 e a documentação (Swagger) em http://127.0.0.1:8000/docs.
4. Em **outro** terminal (com o ambiente virtual ativo), execute o **frontend**:
   ```
   streamlit run frontend_streamlit.py
   ```
   Abra http://localhost:8501. Na primeira execução o Streamlit pede um e-mail: basta apertar Enter.
5. Faça login como administrador: usuário `admin`, senha `admin123`.

Atalho no VS Code: `Terminal > Run Task... > Iniciar tudo` sobe backend e frontend juntos.

### Usuários e permissões

- `admin` (criado na primeira execução): todos os scopes, inclusive excluir reservas e consultar a auditoria.
- Usuários criados pela tela "Criar usuário": podem consultar, cadastrar e alterar reservas, mas **não** excluir
  (a API responde `403 Forbidden`).

### Variáveis de ambiente (opcionais)

| Variável | Padrão | Uso |
|---|---|---|
| `JWT_SECRET` | chave de desenvolvimento | chave de assinatura do JWT (mínimo 32 bytes) |
| `ADMIN_USERNAME` | `admin` | usuário administrador inicial |
| `ADMIN_INITIAL_PASSWORD` | `admin123` | senha inicial do administrador |

Os valores padrão servem apenas para demonstração; troque-os fora do ambiente de estudo.

## Principais endpoints

| Método | Rota | Scope |
|---|---|---|
| POST | `/usuarios` | público |
| POST | `/token` | público (form OAuth2) |
| POST | `/refresh`, `/logout` | refresh token |
| GET | `/me` | autenticado |
| GET | `/reservas`, `/reservas/busca`, `/reservas/{id}`, `/reservas/contagem`, `/reservas/receita` | `reservas:read` |
| POST | `/reservas` | `reservas:create` |
| PUT | `/reservas/{id}` | `reservas:update` |
| DELETE | `/reservas/{id}` | `reservas:delete` |
| GET | `/auditoria` | `auditoria:read` |

## Uso de IA

Este trabalho foi desenvolvido com apoio de IA (permitido no enunciado), que adaptou o código do roteiro
para o novo domínio; o funcionamento foi validado manualmente.
