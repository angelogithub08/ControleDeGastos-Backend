from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship


class TransactionTypeEnum(str, Enum):
    EXPENSE = "EXPENSE"
    INCOME = "INCOME"


class User(SQLModel, table=True):
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=255)
    email: str = Field(max_length=255, unique=True)
    password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relacionamento com transactions
    transactions: List["Transaction"] = Relationship(back_populates="user")


class TransactionType(SQLModel, table=True):
    __tablename__ = "transaction_types"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=255)
    type: TransactionTypeEnum = Field(description="Tipo da transação: EXPENSE ou INCOME")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relacionamento com transactions
    transactions: List["Transaction"] = Relationship(back_populates="transaction_type")


class Transaction(SQLModel, table=True):
    __tablename__ = "transactions"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    transaction_type_id: int = Field(foreign_key="transaction_types.id")
    value: Decimal = Field(decimal_places=2, max_digits=10)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relacionamentos
    user: Optional[User] = Relationship(back_populates="transactions")
    transaction_type: Optional[TransactionType] = Relationship(back_populates="transactions")


# Models para criação (sem campos auto-gerados)
class UserCreate(SQLModel):
    name: str = Field(max_length=255)
    email: str = Field(max_length=255)
    password: str = Field(max_length=255)


class TransactionTypeCreate(SQLModel):
    name: str = Field(max_length=255)
    type: TransactionTypeEnum


class TransactionCreate(SQLModel):
    user_id: int
    transaction_type_id: int
    value: Decimal = Field(decimal_places=2, max_digits=10)


# Models para leitura (com todos os campos)
class UserRead(SQLModel):
    id: int
    name: str
    email: str
    created_at: datetime
    updated_at: datetime


class TransactionTypeRead(SQLModel):
    id: int
    name: str
    type: TransactionTypeEnum
    created_at: datetime
    updated_at: datetime


class TransactionRead(SQLModel):
    id: int
    user_id: int
    transaction_type_id: int
    value: Decimal
    created_at: datetime
    updated_at: datetime
    transaction_type_type: TransactionTypeEnum
    transaction_type_name: str


# Models para atualização
class UserUpdate(SQLModel):
    name: Optional[str] = Field(default=None, max_length=255)
    email: Optional[str] = Field(default=None, max_length=255)
    password: Optional[str] = Field(default=None, max_length=255)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TransactionTypeUpdate(SQLModel):
    name: Optional[str] = Field(default=None, max_length=255)
    type: Optional[TransactionTypeEnum] = Field(default=None)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TransactionUpdate(SQLModel):
    user_id: Optional[int] = Field(default=None)
    transaction_type_id: Optional[int] = Field(default=None)
    value: Optional[Decimal] = Field(default=None, decimal_places=2, max_digits=10)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# Models para autenticação
class UserLogin(SQLModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=255)


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    user_id: Optional[int] = None
