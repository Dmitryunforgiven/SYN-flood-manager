import flet as ft
from backend.config import load_config, save_config, delete_server, rename_server, edit_server
from .themes import get_light_theme

def manage_servers_window(page: ft.Page, servers, server_dropdown, log_callback):
    page.window.width = 600
    page.window.height = 400
    page.title = "Manage Servers"
    page.theme = get_light_theme()
    page.padding = 20

    servers_list = ft.ListView(expand=True, spacing=10)
    message_field = ft.Text("", color="#D32F2F")

    def update_servers_list():
        servers_list.controls.clear()
        for server_name, server_data in servers.items():
            servers_list.controls.append(
                ft.Row([
                    ft.Text(server_name, width=200),
                    ft.ElevatedButton("Edit", data=server_name, on_click=open_edit_dialog),
                    ft.ElevatedButton("Delete", data=server_name, on_click=delete_server_handler)
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            )
        page.update()

    def delete_server_handler(e):
        server_name = e.control.data
        if delete_server(servers, server_name):
            update_servers_list()
            server_dropdown.options = [ft.dropdown.Option(k, k) for k in servers.keys()]
            server_dropdown.value = None
            server_dropdown.update()
            log_callback(f"Deleted {server_name}")
            message_field.value = f"Deleted {server_name}"
        else:
            message_field.value = f"Failed to delete {server_name}"
        page.update()

    def open_edit_dialog(e):
        server_name = e.control.data
        server_data = servers[server_name]

        new_name_field = ft.TextField(label="Server Name", value=server_name, width=300)
        new_ip_field = ft.TextField(label="IP Address", value=server_data["ip"], width=300)
        new_username_field = ft.TextField(label="Username", value=server_data["username"], width=300)
        new_password_field = ft.TextField(label="Password", value=server_data["password"], password=True, width=300)

        def save_changes(e):
            old_name = server_name
            new_name = new_name_field.value.strip()
            if not new_name:
                message_field.value = "Server name cannot be empty"
                page.update()
                return
            if new_name != old_name and new_name in servers:
                message_field.value = "Server name already exists"
                page.update()
                return
            if rename_server(servers, old_name, new_name):
                log_callback(f"Renamed {old_name} to {new_name}")
            edit_server(servers, new_name, new_ip_field.value, new_username_field.value, new_password_field.value)
            update_servers_list()
            server_dropdown.options = [ft.dropdown.Option(k, k) for k in servers.keys()]
            server_dropdown.value = None
            server_dropdown.update()
            log_callback(f"Updated {new_name}")
            message_field.value = f"Updated {new_name}"
            page.overlay.remove(edit_dialog)
            page.update()

        def close_dialog(e):
            page.overlay.remove(edit_dialog)
            page.update()

        edit_dialog = ft.AlertDialog(
            title=ft.Text(f"Edit {server_name}"),
            content=ft.Column([new_name_field, new_ip_field, new_username_field, new_password_field], spacing=10),
            actions=[
                ft.TextButton("Save", on_click=save_changes),
                ft.TextButton("Cancel", on_click=close_dialog)
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )
        page.overlay.append(edit_dialog)
        edit_dialog.open = True
        page.update()

    page.add(
        ft.Column([
            ft.Text("Manage Servers", size=20, weight=ft.FontWeight.BOLD),
            servers_list,
            ft.Row([message_field], alignment=ft.MainAxisAlignment.CENTER),
            ft.ElevatedButton("Close", on_click=lambda e: page.window.close())
        ], spacing=20, expand=True)
    )

    update_servers_list()