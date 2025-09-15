#!/usr/bin/env python3
"""
Script para facilitar operações de migration com Alembic
Uso: python migrations.py <comando> [argumentos]
"""
import subprocess
import sys
import os


def run_command(command: str) -> int:
    """Executar comando e retornar código de saída"""
    print(f"🔄 Executando: {command}")
    result = subprocess.run(command, shell=True)
    return result.returncode


def create_migration(message: str):
    """Criar nova migration"""
    if not message:
        print("❌ Erro: Mensagem da migration é obrigatória")
        print("Uso: python migrations.py create 'Descrição da mudança'")
        return 1
    
    cmd = f"alembic revision --autogenerate -m '{message}'"
    return run_command(cmd)


def upgrade(revision: str = "head"):
    """Aplicar migrations"""
    cmd = f"alembic upgrade {revision}"
    return run_command(cmd)


def downgrade(revision: str = "-1"):
    """Reverter migrations"""
    cmd = f"alembic downgrade {revision}"
    return run_command(cmd)


def history():
    """Ver histórico de migrations"""
    return run_command("alembic history --verbose")


def current():
    """Ver migration atual"""
    return run_command("alembic current --verbose")


def show_help():
    """Mostrar ajuda"""
    print("""
🗄️  Script de Migrations - Controle de Gastos

Comandos disponíveis:

📝 create <mensagem>     - Criar nova migration
   Exemplo: python migrations.py create "Adicionar tabela categorias"

⬆️  upgrade [revision]   - Aplicar migrations (padrão: todas)
   Exemplos: 
   - python migrations.py upgrade        # Aplicar todas
   - python migrations.py upgrade abc123 # Aplicar até revision específica

⬇️  downgrade [revision] - Reverter migrations (padrão: uma)
   Exemplos:
   - python migrations.py downgrade      # Reverter uma migration
   - python migrations.py downgrade abc123 # Reverter até revision específica

📋 history              - Ver histórico de migrations
📍 current              - Ver migration atual
❓ help                 - Mostrar esta ajuda

Exemplos de uso:
  python migrations.py create "Initial migration"
  python migrations.py upgrade
  python migrations.py history
  python migrations.py current
    """)


def main():
    """Função principal"""
    if len(sys.argv) < 2:
        show_help()
        return 1
    
    command = sys.argv[1].lower()
    
    # Verificar se estamos no diretório correto
    if not os.path.exists("alembic.ini"):
        print("❌ Erro: arquivo alembic.ini não encontrado")
        print("Execute este script no diretório raiz do projeto")
        return 1
    
    try:
        if command == "create":
            if len(sys.argv) < 3:
                print("❌ Erro: Mensagem da migration é obrigatória")
                print("Uso: python migrations.py create 'Descrição da mudança'")
                return 1
            message = " ".join(sys.argv[2:])
            return create_migration(message)
        
        elif command == "upgrade":
            revision = sys.argv[2] if len(sys.argv) > 2 else "head"
            return upgrade(revision)
        
        elif command == "downgrade":
            revision = sys.argv[2] if len(sys.argv) > 2 else "-1"
            return downgrade(revision)
        
        elif command == "history":
            return history()
        
        elif command == "current":
            return current()
        
        elif command in ["help", "-h", "--help"]:
            show_help()
            return 0
        
        else:
            print(f"❌ Comando '{command}' não reconhecido")
            show_help()
            return 1
    
    except KeyboardInterrupt:
        print("\n⚠️  Operação cancelada pelo usuário")
        return 1
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
