from sqlmodel import Session
from models import User
from database import engine
from auth import get_password_hash

def update_password(user_id: int, password: str):
    """Atualizar a senha do usuário"""
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            print(f"Usuário com ID {user_id} não encontrado")
            return None
        
        user.password = get_password_hash(password)
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"Senha do usuário {user.name} ({user.email}) atualizada com sucesso!")
        return user

if __name__ == "__main__":
    # Atualizar senha do usuário com ID 1
    update_password(2, "123456")