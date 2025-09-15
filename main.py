from typing import List, Optional
from datetime import timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from decimal import Decimal

from database import get_session, create_db_and_tables
from models import (
    User, UserCreate, UserRead, UserUpdate, UserLogin, Token,
    TransactionType, TransactionTypeCreate, TransactionTypeRead, TransactionTypeUpdate,
    Transaction, TransactionCreate, TransactionRead, TransactionUpdate,
    TransactionTypeEnum
)
from auth import (
    get_password_hash, authenticate_user, create_access_token, 
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
)

# Criar instância do FastAPI
app = FastAPI(
    title="Controle de Gastos API",
    description="API para controle de gastos pessoais",
    version="1.0.0"
)

# Configurar CORS para permitir requests de qualquer origem
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite requests de qualquer origem
    allow_credentials=False,  # Deve ser False quando allow_origins=["*"]
    allow_methods=["*"],  # Permite todos os métodos HTTP
    allow_headers=["*"],  # Permite todos os headers
)

# ==================== FUNÇÕES AUXILIARES ====================

def calculate_balance_after_transaction(
    session: Session, 
    user_id: int, 
    new_transaction_value: Decimal, 
    new_transaction_type: TransactionTypeEnum,
    exclude_transaction_id: Optional[int] = None
) -> Decimal:
    """
    Calcular o saldo do usuário após uma transação hipotética.
    
    Args:
        session: Sessão do banco de dados
        user_id: ID do usuário
        new_transaction_value: Valor da nova transação
        new_transaction_type: Tipo da nova transação (INCOME ou EXPENSE)
        exclude_transaction_id: ID da transação a ser excluída do cálculo (para updates)
    
    Returns:
        Decimal: Saldo resultante após a transação
    """
    # Buscar todas as transações do usuário com seus tipos
    query = (
        select(Transaction, TransactionType)
        .join(TransactionType)
        .where(Transaction.user_id == user_id)
    )
    
    # Se estamos atualizando uma transação, excluí-la do cálculo
    if exclude_transaction_id:
        query = query.where(Transaction.id != exclude_transaction_id)
    
    transactions = session.exec(query).all()
    
    total_income = Decimal('0.00')
    total_expense = Decimal('0.00')
    
    # Calcular totais das transações existentes
    for transaction, transaction_type in transactions:
        if transaction_type.type == TransactionTypeEnum.INCOME:
            total_income += transaction.value
        else:
            total_expense += transaction.value
    
    # Adicionar a nova transação ao cálculo
    if new_transaction_type == TransactionTypeEnum.INCOME:
        total_income += new_transaction_value
    else:
        total_expense += new_transaction_value
    
    return total_income - total_expense

# Criar tabelas no startup (apenas para desenvolvimento)
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ==================== ENDPOINTS DE AUTENTICAÇÃO ====================

@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["Autenticação"])
def register(user: UserCreate, session: Session = Depends(get_session)):
    """Registrar um novo usuário (não requer autenticação)"""
    # Verificar se email já existe
    existing_user = session.exec(select(User).where(User.email == user.email)).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está em uso"
        )
    
    # Criptografar a senha antes de salvar
    user_data = user.model_dump()
    user_data["password"] = get_password_hash(user.password)
    
    db_user = User.model_validate(user_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.post("/auth/login", response_model=Token, tags=["Autenticação"])
def login(user_credentials: UserLogin, session: Session = Depends(get_session)):
    """Fazer login e obter token JWT"""
    user = authenticate_user(session, user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserRead, tags=["Autenticação"])
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Obter informações do usuário logado"""
    return current_user

# ==================== ENDPOINTS DE USUÁRIOS ====================

@app.post("/users/", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["Usuários"])
def create_user(user: UserCreate, session: Session = Depends(get_session)):
    """Criar um novo usuário"""
    # Verificar se email já existe
    existing_user = session.exec(select(User).where(User.email == user.email)).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está em uso"
        )
    
    # Criptografar a senha antes de salvar
    user_data = user.model_dump()
    user_data["password"] = get_password_hash(user.password)
    
    db_user = User.model_validate(user_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.get("/users/", response_model=List[UserRead], tags=["Usuários"])
def get_users(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Listar todos os usuários (requer autenticação)"""
    users = session.exec(select(User).offset(skip).limit(limit)).all()
    return users

@app.get("/users/{user_id}", response_model=UserRead, tags=["Usuários"])
def get_user(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Obter um usuário específico (requer autenticação)"""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    return user

@app.put("/users/{user_id}", response_model=UserRead, tags=["Usuários"])
def update_user(user_id: int, user_update: UserUpdate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Atualizar um usuário (apenas o próprio usuário pode se atualizar)"""
    # Verificar se o usuário está tentando atualizar a si mesmo
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode atualizar seu próprio perfil"
        )
    
    db_user = session.get(User, user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Verificar se novo email já existe (se fornecido)
    if user_update.email and user_update.email != db_user.email:
        existing_user = session.exec(select(User).where(User.email == user_update.email)).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )
    
    user_data = user_update.model_dump(exclude_unset=True)
    
    # Criptografar a senha se ela estiver presente
    if "password" in user_data and user_data["password"]:
        user_data["password"] = get_password_hash(user_data["password"])
    
    for key, value in user_data.items():
        setattr(db_user, key, value)
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Usuários"])
def delete_user(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Deletar um usuário (apenas o próprio usuário pode se deletar)"""
    # Verificar se o usuário está tentando deletar a si mesmo
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode deletar seu próprio perfil"
        )
    
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    session.delete(user)
    session.commit()

@app.get("/users/{user_id}/transactions", response_model=List[TransactionRead], tags=["Usuários"])
def get_user_transactions(
    user_id: int, 
    skip: int = 0, 
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Obter todas as transações de um usuário (apenas suas próprias transações)"""
    # Verificar se o usuário está tentando acessar suas próprias transações
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode acessar suas próprias transações"
        )
    
    # Verificar se usuário existe
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Query com join para obter dados do tipo de transação
    results = session.exec(
        select(Transaction, TransactionType)
        .join(TransactionType)
        .where(Transaction.user_id == user_id)
        .order_by(Transaction.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    
    # Converter para TransactionRead com dados do tipo de transação
    transactions_read = []
    for transaction, transaction_type in results:
        transaction_read = TransactionRead(
            id=transaction.id,
            user_id=transaction.user_id,
            transaction_type_id=transaction.transaction_type_id,
            value=transaction.value,
            created_at=transaction.created_at,
            updated_at=transaction.updated_at,
            transaction_type_type=transaction_type.type,
            transaction_type_name=transaction_type.name
        )
        transactions_read.append(transaction_read)
    
    return transactions_read

@app.get("/users/{user_id}/balance", tags=["Usuários"])
def get_user_balance(user_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Calcular o saldo do usuário (apenas seu próprio saldo)"""
    # Verificar se o usuário está tentando acessar seu próprio saldo
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode acessar seu próprio saldo"
        )
    
    # Verificar se usuário existe
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Buscar todas as transações do usuário com seus tipos
    transactions = session.exec(
        select(Transaction, TransactionType)
        .join(TransactionType)
        .where(Transaction.user_id == user_id)
    ).all()
    
    total_income = Decimal('0.00')
    total_expense = Decimal('0.00')
    
    for transaction, transaction_type in transactions:
        if transaction_type.type == TransactionTypeEnum.INCOME:
            total_income += transaction.value
        else:
            total_expense += transaction.value
    
    balance = total_income - total_expense
    
    return {
        "user_id": user_id,
        "total_income": total_income,
        "total_expense": total_expense,
        "balance": balance
    }

# ==================== ENDPOINTS DE TIPOS DE TRANSAÇÃO ====================

@app.post("/transaction-types/", response_model=TransactionTypeRead, status_code=status.HTTP_201_CREATED, tags=["Tipos de Transação"])
def create_transaction_type(transaction_type: TransactionTypeCreate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Criar um novo tipo de transação (requer autenticação)"""
    db_transaction_type = TransactionType.model_validate(transaction_type)
    session.add(db_transaction_type)
    session.commit()
    session.refresh(db_transaction_type)
    return db_transaction_type

@app.get("/transaction-types/", response_model=List[TransactionTypeRead], tags=["Tipos de Transação"])
def get_transaction_types(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Listar todos os tipos de transação (requer autenticação)"""
    transaction_types = session.exec(select(TransactionType).offset(skip).limit(limit)).all()
    return transaction_types

@app.get("/transaction-types/{transaction_type_id}", response_model=TransactionTypeRead, tags=["Tipos de Transação"])
def get_transaction_type(transaction_type_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Obter um tipo de transação específico (requer autenticação)"""
    transaction_type = session.get(TransactionType, transaction_type_id)
    if not transaction_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tipo de transação não encontrado"
        )
    return transaction_type

@app.put("/transaction-types/{transaction_type_id}", response_model=TransactionTypeRead, tags=["Tipos de Transação"])
def update_transaction_type(
    transaction_type_id: int, 
    transaction_type_update: TransactionTypeUpdate, 
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Atualizar um tipo de transação (requer autenticação)"""
    db_transaction_type = session.get(TransactionType, transaction_type_id)
    if not db_transaction_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tipo de transação não encontrado"
        )
    
    transaction_type_data = transaction_type_update.model_dump(exclude_unset=True)
    for key, value in transaction_type_data.items():
        setattr(db_transaction_type, key, value)
    
    session.add(db_transaction_type)
    session.commit()
    session.refresh(db_transaction_type)
    return db_transaction_type

@app.delete("/transaction-types/{transaction_type_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Tipos de Transação"])
def delete_transaction_type(transaction_type_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Deletar um tipo de transação (requer autenticação)"""
    transaction_type = session.get(TransactionType, transaction_type_id)
    if not transaction_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tipo de transação não encontrado"
        )
    
    # Verificar se existem transações usando este tipo
    existing_transactions = session.exec(
        select(Transaction).where(Transaction.transaction_type_id == transaction_type_id)
    ).first()
    
    if existing_transactions:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Não é possível excluir o tipo '{transaction_type.name}' pois existem transações associadas a ele. Exclua ou altere as transações primeiro."
        )
    
    try:
        session.delete(transaction_type)
        session.commit()
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor ao excluir tipo de transação"
        )

# ==================== ENDPOINTS DE TRANSAÇÕES ====================

@app.post("/transactions/", response_model=TransactionRead, status_code=status.HTTP_201_CREATED, tags=["Transações"])
def create_transaction(transaction: TransactionCreate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Criar uma nova transação (apenas para o usuário logado)"""
    # Verificar se o usuário está tentando criar uma transação para si mesmo
    if transaction.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode criar transações para si mesmo"
        )
    
    # Verificar se tipo de transação existe
    transaction_type = session.get(TransactionType, transaction.transaction_type_id)
    if not transaction_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de transação não encontrado"
        )
    
    # Verificar se a transação resultará em saldo negativo
    balance_after_transaction = calculate_balance_after_transaction(
        session=session,
        user_id=current_user.id,
        new_transaction_value=transaction.value,
        new_transaction_type=transaction_type.type
    )
    
    if balance_after_transaction < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transação não permitida: resultaria em saldo negativo de R$ {abs(balance_after_transaction):.2f}".replace(".", ",")
        )
    
    db_transaction = Transaction.model_validate(transaction)
    session.add(db_transaction)
    session.commit()
    session.refresh(db_transaction)
    
    # Criar o objeto de resposta com os dados do tipo de transação
    transaction_read = TransactionRead(
        id=db_transaction.id,
        user_id=db_transaction.user_id,
        transaction_type_id=db_transaction.transaction_type_id,
        value=db_transaction.value,
        created_at=db_transaction.created_at,
        updated_at=db_transaction.updated_at,
        transaction_type_type=transaction_type.type,
        transaction_type_name=transaction_type.name
    )
    
    return transaction_read

@app.get("/transactions/", response_model=List[TransactionRead], tags=["Transações"])
def get_transactions(
    skip: int = 0, 
    limit: int = 100, 
    transaction_type_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Listar transações do usuário logado com filtros opcionais"""
    # Query com join para obter dados do tipo de transação
    query = select(Transaction, TransactionType).join(TransactionType).where(Transaction.user_id == current_user.id)
    
    if transaction_type_id:
        query = query.where(Transaction.transaction_type_id == transaction_type_id)
    
    # Ordenar por created_at de forma decrescente (mais recentes primeiro)
    query = query.order_by(Transaction.created_at.desc())
    
    results = session.exec(query.offset(skip).limit(limit)).all()
    
    # Converter para TransactionRead com dados do tipo de transação
    transactions_read = []
    for transaction, transaction_type in results:
        transaction_read = TransactionRead(
            id=transaction.id,
            user_id=transaction.user_id,
            transaction_type_id=transaction.transaction_type_id,
            value=transaction.value,
            created_at=transaction.created_at,
            updated_at=transaction.updated_at,
            transaction_type_type=transaction_type.type,
            transaction_type_name=transaction_type.name
        )
        transactions_read.append(transaction_read)
    
    return transactions_read

@app.get("/transactions/{transaction_id}", response_model=TransactionRead, tags=["Transações"])
def get_transaction(transaction_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Obter uma transação específica (apenas suas próprias transações)"""
    # Query com join para obter dados do tipo de transação
    result = session.exec(
        select(Transaction, TransactionType)
        .join(TransactionType)
        .where(Transaction.id == transaction_id)
    ).first()
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transação não encontrada"
        )
    
    transaction, transaction_type = result
    
    # Verificar se a transação pertence ao usuário logado
    if transaction.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode acessar suas próprias transações"
        )
    
    # Criar o objeto de resposta com os dados do tipo de transação
    transaction_read = TransactionRead(
        id=transaction.id,
        user_id=transaction.user_id,
        transaction_type_id=transaction.transaction_type_id,
        value=transaction.value,
        created_at=transaction.created_at,
        updated_at=transaction.updated_at,
        transaction_type_type=transaction_type.type,
        transaction_type_name=transaction_type.name
    )
    
    return transaction_read

@app.put("/transactions/{transaction_id}", response_model=TransactionRead, tags=["Transações"])
def update_transaction(
    transaction_id: int, 
    transaction_update: TransactionUpdate, 
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Atualizar uma transação (apenas suas próprias transações)"""
    db_transaction = session.get(Transaction, transaction_id)
    if not db_transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transação não encontrada"
        )
    
    # Verificar se a transação pertence ao usuário logado
    if db_transaction.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode atualizar suas próprias transações"
        )
    
    # Não permitir alterar o user_id
    if transaction_update.user_id and transaction_update.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não pode alterar o proprietário da transação"
        )
    
    # Verificar se novo tipo de transação existe (se fornecido)
    transaction_type = None
    if transaction_update.transaction_type_id:
        transaction_type = session.get(TransactionType, transaction_update.transaction_type_id)
        if not transaction_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tipo de transação não encontrado"
            )
    
    # Determinar os valores finais da transação após a atualização
    final_value = transaction_update.value if transaction_update.value is not None else db_transaction.value
    final_type_id = transaction_update.transaction_type_id if transaction_update.transaction_type_id is not None else db_transaction.transaction_type_id
    
    # Obter o tipo de transação final
    final_transaction_type = transaction_type if transaction_type else session.get(TransactionType, final_type_id)
    
    # Verificar se a atualização resultará em saldo negativo
    balance_after_transaction = calculate_balance_after_transaction(
        session=session,
        user_id=current_user.id,
        new_transaction_value=final_value,
        new_transaction_type=final_transaction_type.type,
        exclude_transaction_id=transaction_id  # Excluir a transação atual do cálculo
    )
    
    if balance_after_transaction < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Atualização não permitida: resultaria em saldo negativo de R$ {abs(balance_after_transaction):.2f}".replace(".", ",")
        )
    
    transaction_data = transaction_update.model_dump(exclude_unset=True)
    # Garantir que o user_id não seja alterado
    if "user_id" in transaction_data:
        del transaction_data["user_id"]
    
    for key, value in transaction_data.items():
        setattr(db_transaction, key, value)
    
    session.add(db_transaction)
    session.commit()
    session.refresh(db_transaction)
    
    # Obter o tipo de transação atualizado
    if not transaction_type:
        transaction_type = session.get(TransactionType, db_transaction.transaction_type_id)
    
    # Criar o objeto de resposta com os dados do tipo de transação
    transaction_read = TransactionRead(
        id=db_transaction.id,
        user_id=db_transaction.user_id,
        transaction_type_id=db_transaction.transaction_type_id,
        value=db_transaction.value,
        created_at=db_transaction.created_at,
        updated_at=db_transaction.updated_at,
        transaction_type_type=transaction_type.type,
        transaction_type_name=transaction_type.name
    )
    
    return transaction_read

@app.delete("/transactions/{transaction_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Transações"])
def delete_transaction(transaction_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Deletar uma transação (apenas suas próprias transações)"""
    transaction = session.get(Transaction, transaction_id)
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transação não encontrada"
        )
    
    # Verificar se a transação pertence ao usuário logado
    if transaction.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você só pode deletar suas próprias transações"
        )
    
    session.delete(transaction)
    session.commit()

# ==================== ENDPOINT RAIZ ====================

@app.get("/", tags=["Sistema"])
def read_root():
    """Endpoint raiz da API"""
    return {
        "message": "Controle de Gastos API",
        "version": "1.0.0",
        "docs": "/docdirs",
        "redoc": "/redoc"
    }
