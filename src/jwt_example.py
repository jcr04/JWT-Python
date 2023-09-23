import jwt
import datetime
import logging

# Configuração de Logging
logging.basicConfig(filename='token_activity.log', level=logging.INFO)

# Simulando um banco de dados de tokens revogados e tokens na lista negra
revoked_tokens = set()
blacklisted_tokens = set()

def generate_token(user_id, username, role, is_mfa_enabled):
    secret_key = "my_secret_key"
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "is_mfa_enabled": is_mfa_enabled,
        "exp": expiration_time
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    logging.info(f"Token gerado para o usuário {username}")
    return token

def blacklist_token(token):
    blacklisted_tokens.add(token)
    logging.info(f"Token adicionado à lista negra: {token}")

def is_token_blacklisted(token):
    return token in blacklisted_tokens

def revoke_token(token):
    revoked_tokens.add(token)
    logging.info(f"Token revogado: {token}")

def is_token_revoked(token):
    return token in revoked_tokens

def verify_role(token, required_role):
    decoded_token = jwt.decode(token, "my_secret_key", algorithms=["HS256"])
    return decoded_token.get("role") == required_role

def verify_token(token):
    secret_key = "my_secret_key"
    try:
        if is_token_revoked(token):
            return "Token revogado!"
        if is_token_blacklisted(token):
            return "Token na lista negra!"

        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        logging.info(f"Token verificado para o usuário {decoded_token['username']}")
        return decoded_token
    except jwt.ExpiredSignatureError:
        return "Token expirado!"
    except jwt.InvalidTokenError:
        return "Token inválido!"

if __name__ == "__main__":
    user_id = 1
    username = "joao"
    role = "admin"
    is_mfa_enabled = True  # Simulando que MFA está ativado para este usuário

    token = generate_token(user_id, username, role, is_mfa_enabled)
    print(f"Token gerado: {token}")

    # Para teste, adicionando o token à lista negra
    # blacklist_token(token)

    verified_payload = verify_token(token)
    print(f"Payload verificado: {verified_payload}")

    is_admin = verify_role(token, "admin")
    print(f"É admin? {is_admin}")
