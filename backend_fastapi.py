import os
import sys
import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Literal, Optional
from uuid import uuid4

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from pydantic import field_validator
from sqlalchemy import func, inspect, update
from sqlmodel import Field, Session, SQLModel, create_engine, select
from pwdlib import PasswordHash

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(
    title="API de Reservas de Hotel",
    description=(
        "FastAPI + SQLModel + SQLite + OAuth2 Password Flow + JWT + Scopes "
        "+ Refresh Tokens + Sessões + Auditoria"
    ),
    version="9.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "sqlite:///hotel.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Chave local apenas para o exemplo didático. Em outros ambientes, configure
# JWT_SECRET com uma chave aleatória de pelo menos 32 bytes.
SECRET_KEY = os.getenv("JWT_SECRET", "chave-local-de-desenvolvimento-com-mais-de-32-bytes")
if len(SECRET_KEY.encode("utf-8")) < 32:
    raise RuntimeError("JWT_SECRET deve ter pelo menos 32 bytes para HS256.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
SESSION_IDLE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip().lower()
ADMIN_INITIAL_PASSWORD = os.getenv("ADMIN_INITIAL_PASSWORD", "admin123")

SCOPES = {
    "reservas:read": "Consultar reservas",
    "reservas:create": "Cadastrar reservas",
    "reservas:update": "Alterar reservas",
    "reservas:delete": "Excluir reservas",
    "auditoria:read": "Consultar registros de auditoria",
}

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes=SCOPES,
    auto_error=False,
)


class ReservaBase(SQLModel):
    hospede: str = Field(min_length=1)
    valor_diaria: Decimal = Field(gt=Decimal("0"), max_digits=10, decimal_places=2)
    diarias: int = Field(gt=0)

    @field_validator("hospede")
    @classmethod
    def validar_hospede(cls, valor: str) -> str:
        valor = valor.strip()
        if not valor:
            raise ValueError("O nome do hóspede não pode ficar vazio ou conter apenas espaços.")
        return valor


class Reserva(ReservaBase, table=True):
    id: int | None = Field(default=None, primary_key=True)


class ReservaSaida(SQLModel):
    id: int
    hospede: str
    valor_diaria: Decimal
    diarias: int


class ReservaOperacaoResponse(SQLModel):
    mensagem: str
    reserva: ReservaSaida


class ReservaBuscaSaida(SQLModel):
    hospede: str
    valor_diaria: Decimal
    diarias: int


class ContagemReservasResponse(SQLModel):
    quantidade_total: int


class ReceitaTotalResponse(SQLModel):
    receita_total: Decimal
    moeda: str


class UsuarioPerfil(SQLModel):
    id: int
    username: str
    role: str
    scopes: list[str]
    sessao_id: Optional[str] = None


class UsuarioCadastroResponse(SQLModel):
    mensagem: str
    id: int
    username: str
    role: str


class TokenResponse(SQLModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"]
    expires_in: int
    refresh_expires_in: int
    session_idle_seconds: int
    usuario: UsuarioPerfil


class MensagemResponse(SQLModel):
    mensagem: str


class StatusAPIResponse(SQLModel):
    mensagem: str
    versao: str


class RefreshEntrada(SQLModel):
    refresh_token: str = Field(min_length=1)


class AuditoriaSaida(SQLModel):
    id: int
    usuario: str
    operacao: str
    recurso: str
    recurso_id: int | None
    data_hora: datetime
    resultado: str
    detalhes: str | None


class Usuario(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, min_length=3, max_length=50)
    senha_hash: str
    role: str = Field(default="usuario")


class RefreshToken(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    usuario_id: int = Field(foreign_key="usuario.id", index=True)
    sessao_id: str = Field(index=True)
    token_hash: str = Field(index=True, unique=True)
    criado_em: int
    expira_em: int
    ultima_atividade: int
    revogado: bool = Field(default=False)
    # Preserva o conjunto concedido no login durante cada rotação.
    scopes: str = Field(default="")


class LogAuditoria(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    usuario: str = Field(index=True)
    operacao: str
    recurso: str
    recurso_id: int | None = None
    data_hora: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resultado: str
    detalhes: str | None = None


class ControleInicializacao(SQLModel, table=True):
    """Registra se a carga de demonstração já foi processada."""
    id: int = Field(default=1, primary_key=True)
    reservas_demo_inseridas: bool = False


class UsuarioCadastro(SQLModel):
    username: str = Field(min_length=3, max_length=50)
    senha: str = Field(min_length=6)

    @field_validator("username", mode="before")
    @classmethod
    def normalizar_username(cls, valor: object) -> object:
        return validar_username(valor)


def validar_username(valor: object) -> object:
    """Normaliza o username e rejeita texto vazio ou composto por espaços."""
    if not isinstance(valor, str):
        return valor

    normalizado = valor.strip().lower()

    if not normalizado:
        raise ValueError("O nome de usuário não pode ficar vazio ou conter apenas espaços.")

    return normalizado


def normalizar_username(username: str) -> str:
    return username.strip().lower()


def registrar_auditoria(
    usuario: str,
    operacao: str,
    recurso: str,
    resultado: str,
    recurso_id: int | None = None,
    detalhes: str | None = None,
    *,
    session: Session | None = None,
) -> None:
    """Adiciona auditoria à sessão informada ou grava em sessão própria."""
    log = LogAuditoria(
        usuario=usuario or "desconhecido",
        operacao=operacao,
        recurso=recurso,
        recurso_id=recurso_id,
        resultado=resultado,
        detalhes=detalhes,
    )

    if session is not None:
        session.add(log)
        return

    with Session(engine) as nova_session:
        nova_session.add(log)
        nova_session.commit()


def preparar_banco() -> None:
    SQLModel.metadata.create_all(engine)

    colunas_usuario = {
        coluna["name"] for coluna in inspect(engine).get_columns("usuario")
    }

    if "role" not in colunas_usuario:
        with engine.begin() as conexao:
            conexao.exec_driver_sql(
                "ALTER TABLE usuario "
                "ADD COLUMN role VARCHAR NOT NULL DEFAULT 'usuario'"
            )

    inspetor = inspect(engine)
    if inspetor.has_table("refreshtoken"):
        colunas_refresh = {
            coluna["name"]
            for coluna in inspetor.get_columns("refreshtoken")
        }

        if "ultima_atividade" not in colunas_refresh:
            agora = int(time.time())
            with engine.begin() as conexao:
                conexao.exec_driver_sql(
                    "ALTER TABLE refreshtoken "
                    f"ADD COLUMN ultima_atividade INTEGER NOT NULL DEFAULT {agora}"
                )

        if "sessao_id" not in colunas_refresh:
            with engine.begin() as conexao:
                conexao.exec_driver_sql("ALTER TABLE refreshtoken ADD COLUMN sessao_id VARCHAR")

        if "scopes" not in colunas_refresh:
            with engine.begin() as conexao:
                conexao.exec_driver_sql(
                    "ALTER TABLE refreshtoken "
                    "ADD COLUMN scopes VARCHAR NOT NULL DEFAULT ''"
                )

        # Refresh tokens ativos de uma versão anterior ainda podem renovar.
        with engine.begin() as conexao:
            registros_sem_sessao = conexao.exec_driver_sql(
                "SELECT id FROM refreshtoken WHERE sessao_id IS NULL"
            ).all()

            for (registro_id,) in registros_sem_sessao:
                conexao.exec_driver_sql(
                    "UPDATE refreshtoken SET sessao_id = ? WHERE id = ?",
                    (uuid4().hex, registro_id),
                )



def validar_configuracao_admin() -> None:
    if not 3 <= len(ADMIN_USERNAME) <= 50:
        raise RuntimeError("ADMIN_USERNAME deve ter entre 3 e 50 caracteres.")

    if len(ADMIN_INITIAL_PASSWORD) < 6:
        raise RuntimeError("ADMIN_INITIAL_PASSWORD deve ter pelo menos 6 caracteres.")


def inserir_dados_iniciais() -> None:
    validar_configuracao_admin()
    with Session(engine) as session:
        controle = session.get(ControleInicializacao, 1)

        if controle is None:
            # Dados existentes indicam que a carga demonstrativa já ocorreu.
            controle = ControleInicializacao(
                id=1,
                reservas_demo_inseridas=bool(
                    session.exec(select(Reserva.id)).first()
                ),
            )
            session.add(controle)
            session.flush()

        if not controle.reservas_demo_inseridas:
            session.add_all([
                Reserva(hospede="Ana Souza", valor_diaria=Decimal("280.00"), diarias=3),
                Reserva(hospede="Carlos Lima", valor_diaria=Decimal("350.00"), diarias=2),
                Reserva(hospede="Mariana Costa", valor_diaria=Decimal("420.00"), diarias=5),
                Reserva(hospede="Roberto Alves", valor_diaria=Decimal("199.90"), diarias=4),
            ])

            controle.reservas_demo_inseridas = True

        administrador = session.exec(
            select(Usuario).where(Usuario.role == "admin")
        ).first()

        if administrador is None:
            usuario_configurado = session.exec(
                select(Usuario).where(Usuario.username == ADMIN_USERNAME)
            ).first()

            if usuario_configurado is not None:
                raise RuntimeError(
                    f"Já existe '{ADMIN_USERNAME}' com perfil comum. "
                    "Escolha outro ADMIN_USERNAME ou ajuste o perfil no banco; "
                    "a aplicação não promoverá essa conta automaticamente."
                )

            session.add(
                Usuario(
                    username=ADMIN_USERNAME,
                    senha_hash=password_hash.hash(ADMIN_INITIAL_PASSWORD),
                    role="admin",
                )
            )

        session.commit()


def scopes_do_usuario(role: str) -> list[str]:
    if role == "admin":
        return list(SCOPES)

    return ["reservas:read", "reservas:create", "reservas:update"]


def scopes_para_token(role: str, solicitados: list[str]) -> list[str]:
    permitidos = set(scopes_do_usuario(role))
    pedidos = set(solicitados)

    if not pedidos:
        return sorted(permitidos)

    negados = pedidos - permitidos

    if negados:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Escopos não permitidos para este perfil: "
                f"{', '.join(sorted(negados))}"
            ),
        )

    return sorted(pedidos)


def autenticar_usuario(username: str, senha: str) -> dict | None:
    username_normalizado = normalizar_username(username)

    with Session(engine) as session:
        usuario = session.exec(
            select(Usuario).where(Usuario.username == username_normalizado)
        ).first()

        if usuario is None or not password_hash.verify(senha, usuario.senha_hash):
            return None

        return {
            "id": usuario.id,
            "username": usuario.username,
            "role": usuario.role,
            "scopes": scopes_do_usuario(usuario.role),
        }


def criar_access_token(usuario: dict, scopes: list[str], sessao_id: str) -> str:
    expiracao = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": usuario["username"],
        "role": usuario["role"],
        "scope": " ".join(scopes),
        "sid": sessao_id,
        "exp": expiracao,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def novo_refresh_token(usuario_id: int, sessao_id: str, scopes: list[str]) -> tuple[str, RefreshToken]:
    token = secrets.token_urlsafe(64)
    agora = int(time.time())

    registro = RefreshToken(
        usuario_id=usuario_id,
        sessao_id=sessao_id,
        token_hash=hash_refresh_token(token),
        criado_em=agora,
        expira_em=agora + REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        ultima_atividade=agora,
        revogado=False,
        scopes=" ".join(scopes),
    )

    return token, registro


def emitir_par_tokens(usuario: dict, scopes: list[str], sessao_id: str, session: Session) -> dict:
    access_token = criar_access_token(usuario, scopes, sessao_id)

    refresh_token, registro = novo_refresh_token(
        usuario["id"], sessao_id, scopes
    )

    session.add(registro)
    perfil = {**usuario, "scopes": scopes, "sessao_id": sessao_id}

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "refresh_expires_in": REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        "session_idle_seconds": SESSION_IDLE_MINUTES * 60,
        "usuario": perfil,
    }


def revogar_sessao(session: Session, sessao_id: str) -> int:
    registros = session.exec(
        select(RefreshToken).where(
            RefreshToken.sessao_id == sessao_id,
            RefreshToken.revogado == False,  # noqa: E712
        )
    ).all()

    for registro in registros:
        registro.revogado = True

    return len(registros)


def buscar_sessao_ativa(session: Session, sessao_id: str) -> RefreshToken | None:
    return session.exec(
        select(RefreshToken)
        .where(
            RefreshToken.sessao_id == sessao_id,
            RefreshToken.revogado == False,  # noqa: E712
        )
        .order_by(RefreshToken.id.desc())
    ).first()


def desafio_bearer(security_scopes: SecurityScopes) -> str:
    desafio = "Bearer"

    if security_scopes.scopes:
        desafio += f' scope="{security_scopes.scope_str}"'

    return desafio


def obter_usuario_atual(
    request: Request,
    security_scopes: SecurityScopes,
    token: Optional[str] = Depends(oauth2_scheme),
) -> dict:
    desafio = desafio_bearer(security_scopes)

    if token is None:
        registrar_auditoria(
            "desconhecido",
            request.method,
            request.url.path,
            "negado",
            detalhes="Token de acesso não informado",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token não informado",
            headers={"WWW-Authenticate": desafio},
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        sessao_id = payload.get("sid")
        scope_claim = payload.get("scope", "")

        if (
            not isinstance(username, str)
            or not username
            or not isinstance(sessao_id, str)
            or not sessao_id
            or not isinstance(scope_claim, str)
        ):
            raise InvalidTokenError("Token sem claims válidos")

        token_scopes = set(scope_claim.split())
    except ExpiredSignatureError:
        # A expiração normal do access token é esperada; não a registramos como
        # tentativa negada para evitar poluir a auditoria a cada renovação.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expirado",
            headers={"WWW-Authenticate": desafio},
        )
    except InvalidTokenError:
        registrar_auditoria(
            "desconhecido",
            request.method,
            request.url.path,
            "negado",
            detalhes="Access token inválido ou com claims incompletas",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token inválido",
            headers={"WWW-Authenticate": desafio},
        )

    agora = int(time.time())

    with Session(engine) as session:
        registro = buscar_sessao_ativa(session, sessao_id)

        if registro is None:
            registrar_auditoria(
                username,
                request.method,
                request.url.path,
                "negado",
                detalhes="Sessão inexistente ou revogada",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sessão inexistente ou encerrada",
                headers={"WWW-Authenticate": desafio},
            )

        if registro.expira_em <= agora:
            revogar_sessao(session, sessao_id)

            registrar_auditoria(
                username,
                "SESSION_EXPIRED",
                "sessao",
                "encerrada",
                detalhes="Refresh token expirado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expirado",
                headers={"WWW-Authenticate": desafio},
            )

        if agora - registro.ultima_atividade >= SESSION_IDLE_MINUTES * 60:
            revogar_sessao(session, sessao_id)

            registrar_auditoria(
                username,
                "SESSION_TIMEOUT",
                "sessao",
                "encerrada",
                detalhes="Sessão encerrada por inatividade",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sessão encerrada por inatividade",
                headers={"WWW-Authenticate": desafio},
            )

        usuario = session.exec(
            select(Usuario).where(Usuario.username == username)
        ).first()

        if usuario is None:
            revogar_sessao(session, sessao_id)

            registrar_auditoria(
                username,
                request.method,
                request.url.path,
                "negado",
                detalhes="Usuário do token não encontrado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário do token não encontrado",
                headers={"WWW-Authenticate": desafio},
            )

        # A role atual pode reduzir permissões de tokens já emitidos.
        scopes_atuais = set(scopes_do_usuario(usuario.role))
        scopes_efetivos = token_scopes & scopes_atuais

        faltantes = set(security_scopes.scopes) - scopes_efetivos
        if faltantes:
            escopos_exigidos = " ".join(security_scopes.scopes)

            registrar_auditoria(
                username,
                request.method,
                request.url.path,
                "negado",
                detalhes=f"Scopes ausentes: {', '.join(sorted(faltantes))}",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Permissão insuficiente. Requer: "
                    f"{', '.join(sorted(faltantes))}"
                ),
                headers={
                    "WWW-Authenticate": (
                        'Bearer error="insufficient_scope", '
                        f'scope="{escopos_exigidos}"'
                    )
                },
            )

        registro.ultima_atividade = agora
        session.add(registro)

        session.commit()

        return {
            "id": usuario.id,
            "username": usuario.username,
            "role": usuario.role,
            "scopes": sorted(scopes_efetivos),
            "sessao_id": sessao_id,
        }


preparar_banco()
inserir_dados_iniciais()


@app.get("/", response_model=StatusAPIResponse)
def home():
    return {"mensagem": "API está no ar!", "versao": "9"}


@app.post("/usuarios", status_code=status.HTTP_201_CREATED, response_model=UsuarioCadastroResponse)
def cadastrar_usuario(dados: UsuarioCadastro):
    username = dados.username

    with Session(engine) as session:
        existente = session.exec(
            select(Usuario).where(Usuario.username == username)
        ).first()

        if existente is not None:
            registrar_auditoria(
                username,
                "CREATE",
                "usuario",
                "negado",
                detalhes="Nome de usuário já cadastrado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Nome de usuário já cadastrado",
            )

        usuario = Usuario(username=username, senha_hash=password_hash.hash(dados.senha), role="usuario")

        session.add(usuario)
        session.flush()

        registrar_auditoria(
            username,
            "CREATE",
            "usuario",
            "sucesso",
            usuario.id,
            "Novo usuário cadastrado",
            session=session,
        )

        session.commit()
        session.refresh(usuario)

        return {
            "mensagem": "Usuário cadastrado com sucesso.",
            "id": usuario.id,
            "username": usuario.username,
            "role": usuario.role,
        }


@app.post("/token", response_model=TokenResponse)
def gerar_tokens(form_data: OAuth2PasswordRequestForm = Depends()):
    username = normalizar_username(form_data.username)
    usuario = autenticar_usuario(username, form_data.password)

    if usuario is None:
        registrar_auditoria(
            username or "desconhecido",
            "LOGIN",
            "autenticacao",
            "negado",
            detalhes="Usuário ou senha inválidos",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes_concedidos = scopes_para_token(usuario["role"], form_data.scopes)
    sessao_id = uuid4().hex

    with Session(engine) as session:
        resposta = emitir_par_tokens(usuario, scopes_concedidos, sessao_id, session)

        registrar_auditoria(
            usuario["username"],
            "LOGIN",
            "autenticacao",
            "sucesso",
            detalhes=f"Login realizado; sessão {sessao_id}",
            session=session,
        )
        session.commit()

    return resposta


@app.post("/refresh", response_model=TokenResponse)
def renovar_tokens(dados: RefreshEntrada):
    token_hash = hash_refresh_token(dados.refresh_token)
    agora = int(time.time())
    username_auditoria = "desconhecido"

    with Session(engine) as session:
        registro = session.exec(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        ).first()

        if registro is None:
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Refresh token não encontrado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )

        usuario_db = session.get(Usuario, registro.usuario_id)
        if usuario_db is not None:
            username_auditoria = usuario_db.username

        if registro.revogado:
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Refresh token revogado ou já utilizado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token revogado ou já utilizado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if registro.expira_em <= agora:
            revogar_sessao(session, registro.sessao_id)
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Refresh token expirado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not registro.sessao_id:
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Sessão sem identificador válido",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sessão inválida",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if agora - registro.ultima_atividade >= SESSION_IDLE_MINUTES * 60:
            revogar_sessao(session, registro.sessao_id)

            registrar_auditoria(
                username_auditoria,
                "SESSION_TIMEOUT",
                "sessao",
                "encerrada",
                detalhes="Refresh recusado após inatividade",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sessão encerrada por inatividade",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if usuario_db is None:
            revogar_sessao(session, registro.sessao_id)
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Usuário do refresh token não encontrado",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário não encontrado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        scopes_atuais = set(scopes_do_usuario(usuario_db.role))
        scopes_guardados = set(registro.scopes.split())
        # Tokens antigos sem scopes registrados recebem apenas os permitidos
        # hoje para o papel; tokens atuais mantêm o conjunto originalmente dado.
        scopes_efetivos = (
            scopes_guardados if scopes_guardados else scopes_atuais
        ) & scopes_atuais

        if not scopes_efetivos:
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Nenhum scope válido para renovar",
                session=session,
            )

            session.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nenhum escopo válido para renovar a sessão",
                headers={"WWW-Authenticate": "Bearer"},
            )

        sessao_id = registro.sessao_id

        resultado = session.exec(
            update(RefreshToken)
            .where(
                RefreshToken.id == registro.id,
                RefreshToken.revogado == False,  # noqa: E712
                RefreshToken.expira_em > agora,
                RefreshToken.ultima_atividade > agora - SESSION_IDLE_MINUTES * 60,
            )
            .values(revogado=True)
        )

        if resultado.rowcount != 1:
            session.rollback()
            registrar_auditoria(
                username_auditoria,
                "REFRESH",
                "autenticacao",
                "negado",
                detalhes="Refresh token usado simultaneamente ou inválido",
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token já utilizado ou inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )

        usuario = {
            "id": usuario_db.id,
            "username": usuario_db.username,
            "role": usuario_db.role,
            "scopes": sorted(scopes_efetivos),
        }

        resposta = emitir_par_tokens(usuario, sorted(scopes_efetivos), sessao_id, session)

        registrar_auditoria(
            usuario_db.username,
            "REFRESH",
            "autenticacao",
            "sucesso",
            detalhes=f"Refresh rotacionado na sessão {sessao_id}",
            session=session,
        )

        session.commit()

    return resposta


@app.post("/logout", response_model=MensagemResponse)
def logout(dados: RefreshEntrada):
    token_hash = hash_refresh_token(dados.refresh_token)

    with Session(engine) as session:
        registro = session.exec(select(RefreshToken).where(RefreshToken.token_hash == token_hash)).first()

        usuario_nome = "desconhecido"
        tokens_revogados = 0

        if registro is not None:
            usuario_db = session.get(Usuario, registro.usuario_id)
            if usuario_db is not None:
                usuario_nome = usuario_db.username
            if registro.sessao_id:
                tokens_revogados = revogar_sessao(session, registro.sessao_id)

        sessao_encerrada = tokens_revogados > 0

        registrar_auditoria(
            usuario_nome,
            "LOGOUT",
            "autenticacao",
            "sucesso" if sessao_encerrada else "ignorado",
            detalhes=(
                "Sessão encerrada"
                if sessao_encerrada
                else "Refresh token não encontrado ou sem sessão"
            ),
            session=session,
        )

        session.commit()

    return {"mensagem": "Logout realizado com sucesso."}


@app.get("/me", response_model=UsuarioPerfil)
def minha_conta(usuario: dict = Security(obter_usuario_atual, scopes=[])):
    return usuario


@app.get("/auditoria", response_model=list[AuditoriaSaida])
def listar_auditoria(
    limite: int = Query(100, ge=1, le=500),
    usuario: dict = Security(obter_usuario_atual, scopes=["auditoria:read"]),
):
    with Session(engine) as session:
        return session.exec(
            select(LogAuditoria)
            .order_by(LogAuditoria.id.desc())
            .limit(limite)
        ).all()


@app.get("/reservas", response_model=dict[int, ReservaBuscaSaida])
def listar_reservas(usuario: dict = Security(obter_usuario_atual, scopes=["reservas:read"])):
    with Session(engine) as session:
        reservas = session.exec(select(Reserva).order_by(Reserva.id)).all()

    return {
        reserva.id: {
            "hospede": reserva.hospede,
            "valor_diaria": reserva.valor_diaria,
            "diarias": reserva.diarias,
        }
        for reserva in reservas
    }


@app.get("/reservas/contagem", response_model=ContagemReservasResponse)
def contar_reservas(usuario: dict = Security(obter_usuario_atual, scopes=["reservas:read"])):
    with Session(engine) as session:
        total = session.exec(
            select(func.count()).select_from(Reserva)
        ).one()

    return {"quantidade_total": total}


@app.get("/reservas/receita", response_model=ReceitaTotalResponse)
def calcular_receita(usuario: dict = Security(obter_usuario_atual, scopes=["reservas:read"])):
    with Session(engine) as session:
        reservas = session.exec(select(Reserva)).all()

    total = sum(
        (reserva.valor_diaria * reserva.diarias for reserva in reservas),
        start=Decimal("0.00"),
    ).quantize(Decimal("0.01"))

    return {"receita_total": total, "moeda": "R$"}


@app.get("/reservas/busca", response_model=dict[int, ReservaBuscaSaida])
def buscar_reservas(
    nome: Optional[str] = Query(None, description="Parte do nome do hóspede"),
    min_diarias: Optional[int] = Query(None, ge=0, description="Mínimo de diárias"),
    usuario: dict = Security(obter_usuario_atual, scopes=["reservas:read"]),
):
    comando = select(Reserva)

    if nome and nome.strip():
        comando = comando.where(Reserva.hospede.contains(nome.strip()))

    if min_diarias is not None:
        comando = comando.where(Reserva.diarias >= min_diarias)

    with Session(engine) as session:
        reservas = session.exec(comando.order_by(Reserva.id)).all()

    return {
        reserva.id: {
            "hospede": reserva.hospede,
            "valor_diaria": reserva.valor_diaria,
            "diarias": reserva.diarias,
        }
        for reserva in reservas
    }


@app.get("/reservas/{id_reserva}", response_model=ReservaSaida)
def get_reserva(id_reserva: int, usuario: dict = Security(obter_usuario_atual, scopes=["reservas:read"])):
    with Session(engine) as session:
        reserva = session.get(Reserva, id_reserva)

        if reserva is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reserva não encontrada")

        return ReservaSaida(id=reserva.id, hospede=reserva.hospede, valor_diaria=reserva.valor_diaria,
diarias=reserva.diarias)


@app.post("/reservas", status_code=status.HTTP_201_CREATED, response_model=ReservaOperacaoResponse)
def criar_reserva(reserva: ReservaBase, usuario: dict = Security(obter_usuario_atual, scopes=["reservas:create"])):
    with Session(engine) as session:
        nova_reserva = Reserva(**reserva.model_dump())

        session.add(nova_reserva)
        session.flush()

        dados_reserva = ReservaSaida(
            id=nova_reserva.id, hospede=nova_reserva.hospede,
            valor_diaria=nova_reserva.valor_diaria, diarias=nova_reserva.diarias,
        )

        registrar_auditoria(
            usuario["username"],
            "CREATE",
            "reserva",
            "sucesso",
            nova_reserva.id,
            f"Hóspede: {nova_reserva.hospede}",
            session=session,
        )

        session.commit()

    return { "mensagem": f"Reserva cadastrada por {usuario['username']}.", "reserva": dados_reserva }


@app.put("/reservas/{id_reserva}", response_model=ReservaOperacaoResponse)
def atualizar_reserva(
    id_reserva: int,
    dados: ReservaBase,
    usuario: dict = Security(obter_usuario_atual, scopes=["reservas:update"]),
):
    with Session(engine) as session:
        reserva = session.get(Reserva, id_reserva)

        if reserva is None:
            registrar_auditoria(
                usuario["username"],
                "UPDATE",
                "reserva",
                "falha",
                id_reserva,
                "Reserva não encontrada",
                session=session,
            )

            session.commit()

            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reserva não encontrada")

        reserva.hospede = dados.hospede
        reserva.valor_diaria = dados.valor_diaria
        reserva.diarias = dados.diarias
        session.flush()

        dados_reserva = ReservaSaida(
            id=reserva.id, hospede=reserva.hospede, valor_diaria=reserva.valor_diaria, diarias=reserva.diarias
        )

        registrar_auditoria(
            usuario["username"],
            "UPDATE",
            "reserva",
            "sucesso",
            id_reserva,
            f"Hóspede: {dados.hospede}",
            session=session,
        )
        session.commit()

    return { "mensagem": f"Reserva {id_reserva} atualizada por {usuario['username']}.", "reserva": dados_reserva }


@app.delete("/reservas/{id_reserva}", response_model=MensagemResponse)
def excluir_reserva(id_reserva: int, usuario: dict = Security(obter_usuario_atual, scopes=["reservas:delete"])):
    with Session(engine) as session:
        reserva = session.get(Reserva, id_reserva)
        if reserva is None:
            registrar_auditoria(
                usuario["username"],
                "DELETE",
                "reserva",
                "falha",
                id_reserva,
                "Reserva não encontrada",
                session=session,
            )
            session.commit()

            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reserva não encontrada")

        hospede = reserva.hospede
        session.delete(reserva)

        registrar_auditoria(
            usuario["username"],
            "DELETE",
            "reserva",
            "sucesso",
            id_reserva,
            f"Hóspede: {hospede}",
            session=session,
        )
        session.commit()

    return { "mensagem": f"Reserva {id_reserva} excluída por {usuario['username']}." }
