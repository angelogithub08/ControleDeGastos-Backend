from sqlmodel import SQLModel, create_engine, Session
from typing import Generator
import os

# URL do banco de dados (SQLite por padrão para desenvolvimento)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./controle_gastos.db")

# Criar engine
engine = create_engine(
    DATABASE_URL,
    echo=True,  # Para debug - mostra as queries SQL
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)


def create_db_and_tables():
    """Criar todas as tabelas no banco de dados (apenas para desenvolvimento)
    Em produção, use Alembic migrations: alembic upgrade head
    """
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """Dependency para obter sessão do banco de dados"""
    with Session(engine) as session:
        yield session


# Importar todos os models para que o Alembic possa detectá-los
from models import User, TransactionType, Transaction
