import flet as ft
from frontend.ui import build_ui
from backend.SFM import SSHManager
from backend.config import load_config

def main(page: ft.Page):
    ssh_manager = SSHManager()
    servers = load_config()
    build_ui(page, ssh_manager, servers)

if __name__ == "__main__":
    ft.app(target=main)