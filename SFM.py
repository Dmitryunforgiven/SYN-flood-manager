import flet as ft
import threading
import paramiko
import json
import os
import re
from threading import Lock
from cryptography.fernet import Fernet, InvalidToken
import sys

def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        return os.path.join(os.path.dirname(__file__), relative_path)
    
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

class SSHManager:
    def __init__(self):
        self.client = None
        self.lock = Lock()

    def connect(self, host, username, password):
        with self.lock:
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(host, username=username, password=password)
            except paramiko.AuthenticationException:
                raise Exception(f"Authentication failed for {username}@{host}. Check credentials.")
            except paramiko.SSHException as e:
                raise Exception(f"Failed to connect to {host}: {str(e)}")
            except Exception as e:
                raise Exception(f"Unexpected error connecting to {host}: {str(e)}")

    def execute_command(self, command, log_callback):
        if not self.client:
            raise Exception("Not connected to the server")
        
        with self.lock:
            stdin, stdout, stderr = self.client.exec_command(command)
            
        for line in iter(stdout.readline, ""):
            log_callback(line.strip())
        error = stderr.read().decode()
        if error:
            log_callback(f"Error: {error}")

    def close(self):
        with self.lock:
            if self.client:
                self.client.close()

def encrypt_data(data):
    return CIPHER.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(encrypted_data):
    if not isinstance(encrypted_data, str):
        if isinstance(encrypted_data, dict):
            return encrypted_data
        raise ValueError(f"Expected string, got {type(encrypted_data)}")
    return json.loads(CIPHER.decrypt(encrypted_data.encode()).decode())

def save_config(servers):
    config_file = get_resource_path("config.json")
    encrypted_servers = {k: encrypt_data(v) for k, v in servers.items()}
    with open(config_file, "w") as f:
        json.dump(encrypted_servers, f)

def load_config():
    config_file = get_resource_path("config.json")
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            encrypted_servers = json.load(f)
        result = {}
        for k, v in encrypted_servers.items():
            if isinstance(v, dict):
                result[k] = v
                encrypted_servers[k] = encrypt_data(v)
            else:
                try:
                    result[k] = decrypt_data(v)
                except Exception as e:
                    print(f"Failed to decrypt {k}: {e}")
                    continue
        with open(config_file, "w") as f:
            json.dump(encrypted_servers, f)
        return result
    return {}

def parse_whois_output(output):
    result = {}
    key_fields = {
        'inetnum': 'IP Range',
        'netname': 'Network Name',
        'country': 'Country',
        'org': 'Organization',
        'admin-c': 'Admin Contact',
        'tech-c': 'Tech Contact',
        'status': 'Status',
        'mnt-by': 'Maintained By',
        'created': 'Created',
        'last-modified': 'Last Modified'
    }
    
    lines = output.split('\n')
    for line in lines:
        for key, display_name in key_fields.items():
            if line.lower().startswith(key + ':'):
                value = line.split(':', 1)[1].strip()
                result[display_name] = value
                break
    
    formatted = "\n".join([f"{k}: {v}" for k, v in result.items()])
    return formatted if formatted else "No relevant data found"

def main(page: ft.Page):
    page.window.width = 800
    page.window.height = 600
    page.padding = 0
    page.window.resizable = True

    light_theme = ft.Theme(
        color_scheme=ft.ColorScheme(
            primary="#0288D1",
            secondary="#4FC3F7",
            background="#E3F2FD",
            surface="#FFFFFF",
            on_primary="#FFFFFF",
            on_background="#0D47A1",
            on_surface="#212121",
        ),
        visual_density=ft.VisualDensity.COMPACT,
    )
    dark_theme = ft.Theme(
        color_scheme=ft.ColorScheme(
            primary="#4FC3F7",
            secondary="#0288D1",
            background="#263238",
            surface="#37474F",
            on_primary="#000000",
            on_background="#FFFFFF",
            on_surface="#FFFFFF",
        ),
        visual_density=ft.VisualDensity.COMPACT,
    )
    page.theme = light_theme
    is_dark_mode = False

    ssh_manager = SSHManager()
    servers = load_config()
    unique_ips = set()
    drop_list = set()
    current_server_ip = None
    
    log_display = ft.Container(
        content=ft.TextField(
            multiline=True,
            read_only=True,
            expand=True,
            text_size=13,
            bgcolor="#F5F5F5",
            border_radius=8,
            border_color="#BBDEFB",
            text_style=ft.TextStyle(font_family="Roboto Mono", color="#212121"),
        ),
        padding=10,
        border_radius=8,
        bgcolor="#FFFFFF",
        shadow=ft.BoxShadow(blur_radius=8, color="#20000000"),
        expand=True,
    )
    ip_list = ft.ListView(expand=True, auto_scroll=False, padding=10)
    
    server_dropdown = ft.Dropdown(
        label="Select Server",
        hint_text="Choose a server",
        width=220,
        text_size=14,
        border_radius=8,
        bgcolor="#FFFFFF",
        border_color="#BBDEFB",
        filled=True,
        content_padding=10,
        text_style=ft.TextStyle(color="#212121"),
        options=[ft.dropdown.Option(key, key) for key in servers.keys()],
    )
    
    ip_field = ft.TextField(
        label="IP Address",
        width=160,
        text_size=14,
        border_radius=8,
        bgcolor="#FFFFFF",
        border_color="#BBDEFB",
        filled=True,
        content_padding=10,
        text_style=ft.TextStyle(color="#212121"),
    )
    username_field = ft.TextField(
        label="Username",
        width=160,
        text_size=14,
        border_radius=8,
        bgcolor="#FFFFFF",
        border_color="#BBDEFB",
        filled=True,
        content_padding=10,
        text_style=ft.TextStyle(color="#212121"),
    )
    password_field = ft.TextField(
        label="Password",
        password=True,
        width=160,
        text_size=14,
        border_radius=8,
        bgcolor="#FFFFFF",
        border_color="#BBDEFB",
        filled=True,
        content_padding=10,
        text_style=ft.TextStyle(color="#212121"),
    )
    install_packages_checkbox = ft.Checkbox(
        label="Install Packages",
        value=False,
        tooltip="Install iptables, tcpdump, whois",
        check_color="#0288D1",
        active_color="#4FC3F7",
        label_style=ft.TextStyle(color="#0D47A1"),
    )
    parse_whois_checkbox = ft.Checkbox(
        label="Summarize WhoIs output",
        value=False,
        tooltip="Show only key whois information",
        check_color="#0288D1",
        active_color="#4FC3F7",
        label_style=ft.TextStyle(color="#0D47A1"),
    )
    dark_mode_switch = ft.Switch(
        label="Dark Mode",
        value=False,
        on_change=lambda e: toggle_dark_mode(),
        active_color="#4FC3F7",
        label_style=ft.TextStyle(color="#0D47A1"),
    )
    loading_indicator = ft.ProgressBar(width=200, visible=False, color="#0288D1", bgcolor="#BBDEFB")

    button_style = ft.ButtonStyle(
        color="#FFFFFF",
        bgcolor="#0288D1",
        shape=ft.RoundedRectangleBorder(radius=8),
        elevation=2,
        overlay_color=ft.Colors.with_opacity(0.1, "#FFFFFF"),
    )
    connect_button = ft.ElevatedButton(text="Connect", width=110, height=40, style=button_style)
    add_server_button = ft.ElevatedButton(text="Add Server", width=110, height=40, style=button_style)
    view_iptables_button = ft.ElevatedButton(text="View IPTables rules", width=110, height=40, style=button_style, disabled=True)
    tcpdump_button = ft.ElevatedButton(text="Start TCPdump", width=110, height=40, style=button_style, disabled=True)
    stop_tcpdump_button = ft.ElevatedButton(text="Stop", width=90, height=40, style=button_style, disabled=True)
    whois_button = ft.ElevatedButton(text="Whois selected IP", width=90, height=40, style=button_style, disabled=True)
    add_drop_button = ft.ElevatedButton(text="Add IP to drop list", width=110, height=40, style=button_style, disabled=True)
    add_drop_subnet_button = ft.ElevatedButton(text="Drop IP by subnet", width=110, height=40, style=button_style, disabled=True)
    remove_drop_button = ft.ElevatedButton(text="Remove IP from drop list", width=110, height=40, style=button_style, disabled=True)

    tcpdump_thread = None

    def toggle_dark_mode():
        nonlocal is_dark_mode
        is_dark_mode = dark_mode_switch.value
        page.theme = dark_theme if is_dark_mode else light_theme
        
        log_display.content.bgcolor = "#37474F" if is_dark_mode else "#F5F5F5"
        log_display.content.text_style = ft.TextStyle(font_family="Roboto Mono", color="#FFFFFF" if is_dark_mode else "#212121")
        log_display.bgcolor = "#263238" if is_dark_mode else "#FFFFFF"
        
        ip_list_container.bgcolor = "#263238" if is_dark_mode else "#FFFFFF"
        
        for checkbox in ip_list.controls:
            checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#212121")
            checkbox.update()
        
        for control in [server_dropdown, ip_field, username_field, password_field]:
            control.bgcolor = "#37474F" if is_dark_mode else "#FFFFFF"
            control.border_color = "#0288D1" if is_dark_mode else "#BBDEFB"
            control.text_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#212121")
            control.update()
        
        for btn in [connect_button, add_server_button, view_iptables_button, tcpdump_button, 
                    stop_tcpdump_button, whois_button, add_drop_button, add_drop_subnet_button, 
                    remove_drop_button]:
            btn.style.bgcolor = "#0288D1"
            btn.update()
        
        main_container.gradient = ft.LinearGradient(
            begin=ft.Alignment(0, -1),
            end=ft.Alignment(0, 1),
            colors=["#37474F", "#263238"] if is_dark_mode else ["#E3F2FD", "#BBDEFB"]
        )
        
        header_text.color = "#4FC3F7" if is_dark_mode else "#0288D1"
        ip_list_header.color = "#4FC3F7" if is_dark_mode else "#0288D1"
        logs_header.color = "#4FC3F7" if is_dark_mode else "#0288D1"
        
        install_packages_checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#0D47A1")
        parse_whois_checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#0D47A1")
        dark_mode_switch.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#0D47A1")
        
        ip_list.update()
        page.update()

    def log_callback(message):
        formatted_message, parsed_ip = parse_log_line(message)
        if formatted_message:
            log_display.content.value += f"\n{formatted_message}"
            page.update()
        if (parsed_ip and parsed_ip not in unique_ips and 
            parsed_ip != current_server_ip and parsed_ip != ip_field.value):
            unique_ips.add(parsed_ip)
            checkbox = ft.Checkbox(
                label=parsed_ip,
                on_change=lambda e: update_ip_buttons(),
                check_color="#0288D1" if not is_dark_mode else "#4FC3F7",
                label_style=ft.TextStyle(color="#FFFFFF" if is_dark_mode else "#212121")
            )
            ip_list.controls.append(checkbox)
            ip_list.auto_scroll = False
            page.update()
            update_ip_buttons()

    def parse_log_line(line):
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            src_ip = match.group(1)
            return f"Source IP: {src_ip}", src_ip
        return line, None

    def clear_log():
        log_display.content.value = ""
        page.update()

    def connect_to_server():
        nonlocal current_server_ip
        selected_server = server_dropdown.value
        if not selected_server:
            log_callback("No server selected.")
            return

        server = servers.get(selected_server)
        if not server:
            log_callback("Selected server not found.")
            return

        clear_log()
        log_callback("Connecting...")
        loading_indicator.visible = True
        page.update()
        
        try:
            ssh_manager.connect(
                host=server["ip"],
                username=server["username"],
                password=server["password"],
            )
            current_server_ip = server["ip"]
            log_callback(f"Connected to {server['ip']}")
            
            if install_packages_checkbox.value:
                log_callback("Installing packages...")
                ssh_manager.execute_command(
                    "apt-get update && apt-get install -y iptables iptables-persistent tcpdump whois", 
                    log_callback
                )
                log_callback("Packages installed")
            
            log_callback('Connection successful')
            view_iptables_button.disabled = False
            tcpdump_button.disabled = False
        
        except Exception as e:
            log_callback(f"Connection error: {str(e)}")
            loading_indicator.visible = False
            page.update()
            return
        
        loading_indicator.visible = False
        page.update()

    def add_server():
        if not all([ip_field.value, username_field.value, password_field.value]):
            log_callback("Enter all credentials")
            return
            
        server_name = f"{ip_field.value} ({username_field.value})"
        if server_name in servers:
            log_callback("Server exists.")
            return
            
        servers[server_name] = {
            "ip": ip_field.value,
            "username": username_field.value,
            "password": password_field.value,
        }
        save_config(servers)
        server_dropdown.options.append(ft.dropdown.Option(server_name, server_name))
        server_dropdown.update()
        log_callback(f"Added {server_name}")
        ip_field.value = ""
        username_field.value = ""
        password_field.value = ""
        page.update()

    def view_iptables():
        def run_iptables():
            clear_log()
            try:
                loading_indicator.visible = True
                page.update()
                log_callback("Fetching iptables...")
                ssh_manager.execute_command(
                    "iptables -L -v -n --line-numbers",
                    log_callback
                )
            except Exception as e:
                log_callback(f"Error: {e}")
            finally:
                loading_indicator.visible = False
                page.update()

        threading.Thread(target=run_iptables, daemon=True).start()

    def start_tcpdump():
        nonlocal tcpdump_thread
        def run_tcpdump():
            clear_log()
            try:
                loading_indicator.visible = True
                page.update()
                log_callback("Starting tcpdump...")
                stop_tcpdump_button.disabled = False
                page.update()
                ssh_manager.execute_command(
                    "tcpdump -i any port 443 and 'tcp[13] & 2 != 0'",
                    log_callback
                )
            except Exception as e:
                log_callback(f"Error: {e}")
            finally:
                loading_indicator.visible = False
                page.update()

        tcpdump_thread = threading.Thread(target=run_tcpdump, daemon=True)
        tcpdump_thread.start()
        tcpdump_button.disabled = True
        page.update()

    def stop_tcpdump():
        clear_log()
        try:
            log_callback("Stopping tcpdump...")
            ssh_manager.execute_command("pkill tcpdump", log_callback)
            stop_tcpdump_button.disabled = True
            tcpdump_button.disabled = False
            update_ip_buttons()
            page.update()
        except Exception as e:
            log_callback(f"Error: {e}")

    def update_ip_buttons():
        selected_ips = [cb.label for cb in ip_list.controls if cb.value]
        add_drop_button.disabled = not selected_ips
        add_drop_subnet_button.disabled = not selected_ips
        remove_drop_button.disabled = not selected_ips
        whois_button.disabled = not selected_ips
        page.update()

    def add_to_drop():
        selected_ips = [cb.label for cb in ip_list.controls if cb.value]
        if not selected_ips:
            log_callback("No IPs selected")
            return
        clear_log()
        try:
            for ip in selected_ips:
                if ip not in drop_list:
                    log_callback(f"Adding {ip} to DROP...")
                    ssh_manager.execute_command(f"iptables -A INPUT -s {ip} -j DROP", log_callback)
                    drop_list.add(ip)
            log_callback("IPs added to DROP")
        except Exception as e:
            log_callback(f"Error: {e}")

    def add_drop_by_subnet():
        selected_ips = [cb.label for cb in ip_list.controls if cb.value]
        if not selected_ips:
            log_callback("No IPs selected")
            return
        clear_log()
        try:
            for ip in selected_ips:
                subnet = '.'.join(ip.split('.')[:-1]) + '.0/24'
                if subnet not in drop_list:
                    log_callback(f"Adding subnet {subnet} to DROP...")
                    ssh_manager.execute_command(f"iptables -A INPUT -s {subnet} -j DROP", log_callback)
                    drop_list.add(subnet)
                else:
                    log_callback(f"Subnet {subnet} already in DROP list")
            log_callback("Subnets added to DROP")
        except Exception as e:
            log_callback(f"Error: {e}")

    def remove_from_drop():
        selected_ips = [cb.label for cb in ip_list.controls if cb.value]
        if not selected_ips:
            log_callback("No IPs selected")
            return
        clear_log()
        try:
            for ip in selected_ips:
                subnet = '.'.join(ip.split('.')[:-1]) + '.0/24'
                if subnet in drop_list:
                    log_callback(f"Removing subnet {subnet}...")
                    ssh_manager.execute_command(f"iptables -D INPUT -s {subnet} -j DROP", log_callback)
                    drop_list.remove(subnet)
                elif ip in drop_list:
                    log_callback(f"Removing {ip}...")
                    ssh_manager.execute_command(f"iptables -D INPUT -s {ip} -j DROP", log_callback)
                    drop_list.remove(ip)
                else:
                    log_callback(f"{ip} or its subnet not found in DROP list")
            log_callback("Selected IPs/subnets removed from DROP")
        except Exception as e:
            log_callback(f"Error: {e}")

    def run_whois():
        selected_ips = [cb.label for cb in ip_list.controls if cb.value]
        clear_log()
        for ip in selected_ips:
            try:
                log_callback(f"Whois for {ip}...")
                if parse_whois_checkbox.value:
                    output_lines = []
                    def collect_output(line):
                        output_lines.append(line)
                    
                    ssh_manager.execute_command(f"whois {ip}", collect_output)
                    threading.Event().wait(1)
                    if output_lines:
                        full_output = "\n".join(output_lines)
                        parsed_output = parse_whois_output(full_output)
                        log_display.content.value = parsed_output
                        page.update()
                    else:
                        log_callback("No whois data received")
                else:
                    ssh_manager.execute_command(f"whois {ip}", log_callback)
            except Exception as e:
                log_callback(f"Error: {e}")

    header_text = ft.Text("SYN Flood Manager", size=24, weight=ft.FontWeight.BOLD, color="#0288D1")
    ip_list_header = ft.Text("Unique IPs", size=16, weight=ft.FontWeight.BOLD, color="#0288D1")
    logs_header = ft.Text("Logs", size=16, weight=ft.FontWeight.BOLD, color="#0288D1")
    
    ip_list_container = ft.Container(
        content=ft.Row([
            ft.Column([
                ip_list_header,
                ft.Container(ip_list, expand=True)
            ], expand=True, spacing=12),
            ft.Column([
                logs_header,
                ft.Container(
                    log_display,
                    expand=True,
                    height=150,
                )
            ], expand=True, spacing=12)
        ], expand=True, spacing=20, alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        bgcolor="#FFFFFF",
        border_radius=10,
        padding=15,
        shadow=ft.BoxShadow(blur_radius=10, color="#30000000"),
        expand=True,
    )

    main_content = ft.Column([
        header_text,
        ft.Row([
            server_dropdown,
            connect_button,
            ft.Row([install_packages_checkbox, parse_whois_checkbox], spacing=20),
        ], spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            ip_field,
            username_field,
            password_field,
            add_server_button
        ], spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([loading_indicator], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            view_iptables_button,
            tcpdump_button,
            stop_tcpdump_button
        ], spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([
            add_drop_button,
            add_drop_subnet_button,
            remove_drop_button,
            whois_button
        ], spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ip_list_container
    ], spacing=20, expand=True)

    main_container = ft.Container(
        content=ft.Row([
            main_content,
            ft.Container(width=50),
            ft.Column([dark_mode_switch], alignment=ft.MainAxisAlignment.CENTER, expand=False)
        ], expand=True, spacing=10),
        gradient=ft.LinearGradient(
            begin=ft.Alignment(0, -1),
            end=ft.Alignment(0, 1),
            colors=["#E3F2FD", "#BBDEFB"]
        ),
        padding=25,
        border_radius=15,
        expand=True,
    )

    page.add(main_container)

    connect_button.on_click = lambda _: connect_to_server()
    add_server_button.on_click = lambda _: add_server()
    view_iptables_button.on_click = lambda _: view_iptables()
    tcpdump_button.on_click = lambda _: start_tcpdump()
    stop_tcpdump_button.on_click = lambda _: stop_tcpdump()
    add_drop_button.on_click = lambda _: add_to_drop()
    add_drop_subnet_button.on_click = lambda _: add_drop_by_subnet()
    remove_drop_button.on_click = lambda _: remove_from_drop()
    whois_button.on_click = lambda _: run_whois()

if __name__ == "__main__":
    ft.app(target=main)