# Trabalho Prático 1.5 — Sistema de Autenticação com Decoradores e Hash de Senhas

# Este sistema simula o que acontece "por baixo dos panos" num login real.
# Aborda três problemas de segurança:
#   1. Como guardar senhas com segurança? → Hash com Salt
#   2. Como proteger funções de acesso? → Decoradores
#   3. Como limitar o que cada utilizador pode fazer? → Controlo por Roles


import hashlib                 # funções de hash criptográfico
import os                    # para gerar bytes aleatórios (salt)
from functools import wraps  # preserva o nome/docstring das funções decoradas



# SECÇÃO 1 — Armazenamento Simulado

# Em produção, estes dados estariam numa base de dados real.
# Aqui usamos dicionários para focar nos conceitos.
# Estrutura: usuarios[username] = { 'hash': ..., 'salt': ..., 'role': ... }

usuarios = {}       # simula a base de dados de utilizadores
current_user = None # representa a sessão activa (None = ninguém logado)



# SECÇÃO 2 — Hash de Senha com Salt

# Nunca guardamos a senha em texto puro. Guardamos o seu HASH — uma "impressão digital" irreversível. O SALT é um valor aleatório único
# por utilizador que garante que duas senhas iguais gerem hashes diferentes,
# protegendo contra ataques de rainbow tables.

def hash_senha(senha, salt=None):
    """
    aqui o Algoritmo Gera o hash SHA-256 de uma senha com salt.
    Se salt=None, gera um novo (usado no cadastro).
    Se salt for fornecido, reutiliza-o (usado no login).
    """
    if salt is None:
        salt = os.urandom(16).hex()  # 16 bytes aleatórios → string hexadecimal

    # isso permite juntar a  senha + salt, converte para bytes e aplica SHA-256
    hash_resultado = hashlib.sha256((senha + salt).encode()).hexdigest()
    return hash_resultado, salt



# SECÇÃO 3 — Esta é secção de  Cadastro, Login e Logout


def cadastrar(username, senha, role='user', conta=None, iban=None, saldo=None):
    """Regista um utilizador guardando apenas o hash+salt e os seus dados bancários."""
    hash_resultado, salt = hash_senha(senha)
    usuarios[username] = {
        'hash':  hash_resultado,
        'salt':  salt,
        'role':  role,
        'conta': conta or '**** **** 0000',
        'iban':  iban  or 'AO06 0000 0000 0000 0000 0000 0',
        'saldo': saldo or '0,00 Kz'
    }
    print(f"Utilizador '{username}' cadastrado. (role: {role})")


def login(username, senha):
    """
    Verifica as credenciais repetindo o hash com o mesmo salt do cadastro.
    Se os hashes baterem, a sessão é iniciada.
    """
    global current_user

    if username not in usuarios:
        print(" Utilizador não encontrado.")
        return False

    dados = usuarios[username]

    # Recalculamos o hash com o salt original — se a senha estiver certa, o resultado é igual
    hash_tentativa, _ = hash_senha(senha, salt=dados['salt'])

    if hash_tentativa == dados['hash']:
        current_user = {'username': username, 'role': dados['role']}
        print(f" Bem-vindo, {username}! (role: {current_user['role']})")
        return True
    else:
        # aqui Por segurança, não indicamos se foi o username ou a senha que falhou
        print("[✘] Credenciais inválidas.")
        return False


def logout():
    """Encerra a sessão limpando o current_user."""
    global current_user
    if current_user:
        print(f" Até logo, {current_user['username']}.")
    else:
        print("Nenhum utilizador estava logado.")
    current_user = None


# SECÇÃO 4 — Decorador @autenticado
# O decorador funciona como um segurança na porta: antes de executar qualquer
# função protegida, verifica se o utilizador está logado e se tem a role certa.
# Estrutura em 3 níveis (necessária para aceitar argumentos):
#   autenticado(roles),decorador(func),wrapper(*args)

def autenticado(roles=None):
    """
    Decorador de autenticação com controlo por roles.
    Uso: @autenticado(roles=['admin']) ou @autenticado(roles=['user','admin'])
    """
    def decorador(func):
        @wraps(func)
        def wrapper(*args, **kwargs):

            # este trecho permite Verificar se há sessão activa
            if current_user is None:
                print("[✘] Acesso negado: faz login primeiro.")
                return

            # aqui Verifica se a role do utilizador tem permissão
            if roles and current_user['role'] not in roles:
                print(f"[✘] Acesso negado: role '{current_user['role']}' sem permissão.")
                return

            return func(*args, **kwargs)

        return wrapper
    return decorador

# SECÇÃO 5 — Funções Protegidas
# Aplicamos o princípio do Menor Privilégio: cada utilizador só acede
# ao que é estritamente necessário para a sua função.

@autenticado(roles=['user', 'admin'])
def ver_dados_sensivel():
    """Dados bancários — cada utilizador vê apenas os seus próprios dados."""
    dados = usuarios[current_user['username']]  # busca os dados do utilizador logado
    print("\n--- DADOS BANCÁRIOS (CONFIDENCIAL) ---")
    print(f"  Titular    : {current_user['username']}")
    print(f"  Banco      : Millennium Atlântico")
    print(f"  Nº Conta   : {dados['conta']}")
    print(f"  IBAN       : {dados['iban']}")
    print(f"  Saldo      : {dados['saldo']}")
    print("--------------------------------------\n")


@autenticado(roles=['user', 'admin'])
def editar_perfil():
    """Editar perfil — disponível para todos os utilizadores logados."""
    print(f"A editar o perfil de '{current_user['username']}'...")
    print("    (simulação) Dados actualizados com sucesso.")


@autenticado(roles=['admin'])
def apagar_usuario():
    """Apagar utilizador — restrito ao admin (acção destrutiva e irreversível)."""
    print(" Acção de administrador: utilizador removido do sistema.")


# SECÇÃO 6 — Menu de Linha de Comando
# Interface simples para testar todas as funcionalidades.
# Dois utilizadores de teste são criados automaticamente no arranque:
#   admin / admin123  →  acesso total
#   joao  / joao456   →  acesso limitado

def menu():
    print("\n" + "=" * 50)
    print("   Sistema de Autenticação — Millennium Atlântico")
    print("=" * 50)

    print("\n[Sistema] A criar utilizadores de demonstração...")
    cadastrar("admin", "admin123", role="admin",
              conta="**** **** 9001",
              iban="AO06 0040 0000 1234 5678 9001 2",
              saldo="1.500.000,00 Kz")

    cadastrar("joao", "joao456", role="user",
              conta="**** **** 4782",
              iban="AO06 0040 0000 9148 1234 1015 4",
              saldo="250.000,00 Kz")

    while True:
        sessao = f"{current_user['username']} ({current_user['role']})" if current_user else "Nenhum"
        print(f"\n{'─' * 40}")
        print(f"  Utilizador activo: {sessao}")
        print(f"{'─' * 40}")
        print("  1. Login")
        print("  2. Logout")
        print("  3. Ver dados sensíveis")
        print("  4. Editar perfil")
        print("  5. Apagar utilizador  [só admin]")
        print("  0. Sair")
        print(f"{'─' * 40}")

        opcao = input("  Escolha: ").strip()

        if opcao == "1":
            u = input("  Username : ")
            s = input("  Senha    : ")
            login(u, s)
        elif opcao == "2":
            logout()
        elif opcao == "3":
            ver_dados_sensivel()
        elif opcao == "4":
            editar_perfil()
        elif opcao == "5":
            apagar_usuario()
        elif opcao == "0":
            print("\n[Sistema] Até logo!\n")
            break
        else:
            print(" Opção inválida.")


# Ponto de entrada — o menu só corre quando o ficheiro é executado directamente
if __name__ == "__main__":
    menu()