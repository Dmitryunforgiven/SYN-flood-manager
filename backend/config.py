import json
import os
from cryptography.fernet import Fernet, InvalidToken
from .utils import get_resource_path

def get_encryption_key():
    key_file = get_resource_path("encryption_key.key")
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
            try:
                Fernet(key)
                return key
            except ValueError:
                print(f"Invalid key in {key_file}. Regenerating a new key.")
    
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    return key

ENCRYPTION_KEY = get_encryption_key()
CIPHER = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    return CIPHER.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(encrypted_data):
    if not isinstance(encrypted_data, str):
        if isinstance(encrypted_data, dict) or isinstance(encrypted_data, list):
            return encrypted_data
        raise ValueError(f"Expected string, got {type(encrypted_data)}")
    try:
        return json.loads(CIPHER.decrypt(encrypted_data.encode()).decode())
    except InvalidToken:
        raise ValueError("Invalid encryption token")

def save_config(servers):
    config_file = get_resource_path("config.json")
    encrypted_servers = {k: encrypt_data(v) for k, v in servers.items()}
    with open(config_file, "w") as f:
        json.dump(encrypted_servers, f, indent=4)

def load_config():
    config_file = get_resource_path("config.json")
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            encrypted_servers = json.load(f)
        result = {}
        for k, v in encrypted_servers.items():
            try:
                result[k] = decrypt_data(v)
            except Exception as e:
                print(f"Failed to decrypt {k}: {e}")
                continue
        return result
    return {}

def delete_server(servers, server_name):
    if server_name in servers:
        del servers[server_name]
        save_config(servers)
        return True
    return False

def rename_server(servers, old_name, new_name):
    if old_name in servers and new_name not in servers:
        servers[new_name] = servers.pop(old_name)
        save_config(servers)
        return True
    return False

def edit_server(servers, server_name, ip=None, username=None, password=None):
    if server_name in servers:
        server_data = servers[server_name]
        if ip:
            server_data["ip"] = ip
        if username:
            server_data["username"] = username
        if password:
            server_data["password"] = password
        servers[server_name] = server_data
        save_config(servers)
        return True
    return False