import threading
from backend.config import save_config, delete_server, rename_server, edit_server
from backend.utils import parse_log_line, parse_whois_output
from .themes import get_light_theme, get_dark_theme
import flet as ft

def toggle_dark_mode(page, is_dark_mode, log_display, ip_list, server_dropdown, ip_field, username_field, password_field,
                     connect_button, add_server_button, manage_servers_button, view_iptables_button, tcpdump_button,
                     stop_tcpdump_button, whois_button, add_drop_button, add_drop_subnet_button, remove_drop_button,
                     main_container, header_text, ip_list_header, logs_header, install_packages_checkbox,
                     parse_whois_checkbox, dark_mode_switch, ip_list_container):
    is_dark_mode[0] = dark_mode_switch.value
    page.theme = get_dark_theme() if is_dark_mode[0] else get_light_theme()
    page.theme_mode = ft.ThemeMode.DARK if is_dark_mode[0] else ft.ThemeMode.LIGHT
    log_display.content.bgcolor = "#37474F" if is_dark_mode[0] else "#F5F5F5"
    log_display.content.text_style = ft.TextStyle(font_family="Roboto Mono", color="#FFFFFF" if is_dark_mode[0] else "#212121")
    log_display.bgcolor = "#263238" if is_dark_mode[0] else "#FFFFFF"
    ip_list_container.bgcolor = "#263238" if is_dark_mode[0] else "#FFFFFF"
    for checkbox in ip_list.controls:
        checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#212121")
        checkbox.update()
    for control in [server_dropdown, ip_field, username_field, password_field]:
        control.bgcolor = "#37474F" if is_dark_mode[0] else "#FFFFFF"
        control.border_color = "#0288D1" if is_dark_mode[0] else "#BBDEFB"
        control.text_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#212121")
        control.update()
    for btn in [connect_button, add_server_button, manage_servers_button, view_iptables_button, tcpdump_button,
                stop_tcpdump_button, whois_button, add_drop_button, add_drop_subnet_button, remove_drop_button]:
        btn.style.bgcolor = "#0288D1"
        btn.update()
    main_container.gradient = ft.LinearGradient(
        begin=ft.Alignment(0, -1), end=ft.Alignment(0, 1),
        colors=["#37474F", "#263238"] if is_dark_mode[0] else ["#E3F2FD", "#BBDEFB"]
    )
    header_text.color = "#4FC3F7" if is_dark_mode[0] else "#0288D1"
    ip_list_header.color = "#4FC3F7" if is_dark_mode[0] else "#0288D1"
    logs_header.color = "#4FC3F7" if is_dark_mode[0] else "#0288D1"
    install_packages_checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#0D47A1")
    parse_whois_checkbox.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#0D47A1")
    dark_mode_switch.label_style = ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#0D47A1")
    ip_list.update()
    page.update()

def log_callback(message, log_display, unique_ips, ip_list, current_server_ip, ip_field, is_dark_mode,
                 add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button):
    formatted_message, parsed_ip = parse_log_line(message)
    if formatted_message:
        log_display.content.value += f"\n{formatted_message}"
        log_display.content.update()
    if parsed_ip and parsed_ip not in unique_ips and parsed_ip != current_server_ip[0] and parsed_ip != ip_field.value:
        unique_ips.add(parsed_ip)
        checkbox = ft.Checkbox(
            label=parsed_ip, on_change=lambda e: update_ip_buttons(ip_list, add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button),
            check_color="#0288D1" if not is_dark_mode[0] else "#4FC3F7",
            label_style=ft.TextStyle(color="#FFFFFF" if is_dark_mode[0] else "#212121")
        )
        ip_list.controls.append(checkbox)
        ip_list.update()
        update_ip_buttons(ip_list, add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button)

def clear_log(log_display):
    log_display.content.value = ""
    log_display.content.update()

def connect_to_server(page, server_dropdown, servers, ssh_manager, current_server_ip, log_callback,
                      loading_indicator, install_packages_checkbox, view_iptables_button, tcpdump_button,
                      selected_server_label, log_display):
    selected_server = server_dropdown.value
    if not selected_server:
        log_callback("No server selected.")
        return
    server = servers.get(selected_server)
    if not server:
        log_callback("Selected server not found.")
        return
    clear_log(log_display)
    log_callback("Connecting...")
    loading_indicator.visible = True
    page.update()
    try:
        ssh_manager.connect(host=server["ip"], username=server["username"], password=server["password"])
        current_server_ip[0] = server["ip"]
        selected_server_label.value = f"Connected: {selected_server}"
        selected_server_label.color = "#0288D1" if page.theme_mode == ft.ThemeMode.LIGHT else "#4FC3F7"
        log_callback(f"Connected to {server['ip']}")
        if install_packages_checkbox.value:
            log_callback("Installing packages...")
            ssh_manager.execute_command(
                "apt-get update && apt-get install -y iptables iptables-persistent tcpdump whois",
                log_callback
            )
            log_callback("Packages installed")
        log_callback("Connection successful")
        view_iptables_button.disabled = False
        tcpdump_button.disabled = False
    except Exception as e:
        log_callback(f"Connection error: {str(e)}")
        selected_server_label.value = "Connection failed"
        selected_server_label.color = "#D32F2F"
    finally:
        loading_indicator.visible = False
        page.update()

def add_server(servers, server_dropdown, ip_field, username_field, password_field, log_callback):
    if not all([ip_field.value, username_field.value, password_field.value]):
        log_callback("Enter all credentials")
        return
    server_name = f"{ip_field.value} ({username_field.value})"
    if server_name in servers:
        log_callback("Server exists.")
        return
    servers[server_name] = {"ip": ip_field.value, "username": username_field.value, "password": password_field.value}
    save_config(servers)
    server_dropdown.options.append(ft.dropdown.Option(server_name, server_name))
    server_dropdown.update()
    log_callback(f"Added {server_name}")
    ip_field.value = username_field.value = password_field.value = ""
    ip_field.update()
    username_field.update()
    password_field.update()

def manage_servers(page, servers, server_dropdown, log_callback, is_dark_mode):
    servers_list = ft.ListView(expand=True, spacing=10)
    message_field = ft.Text("", color="#FF5252")

    def update_servers_list():
        servers_list.controls.clear()
        for server_name, server_data in servers.items():
            servers_list.controls.append(
                ft.Row([
                    ft.Text(server_name, width=200, color="#212121" if not is_dark_mode[0] else "#E0E0E0"),
                    ft.ElevatedButton("Edit", data=server_name, on_click=open_edit_dialog,
                                      style=ft.ButtonStyle(bgcolor="#0288D1", color="#FFFFFF",
                                                           overlay_color=ft.Colors.with_opacity(0.2, "#FFFFFF"))),
                    ft.ElevatedButton("Delete", data=server_name, on_click=delete_server_handler,
                                      style=ft.ButtonStyle(bgcolor="#D32F2F", color="#FFFFFF",
                                                           overlay_color=ft.Colors.with_opacity(0.2, "#FFFFFF")))
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            )
        servers_list.update()

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

        new_name_field = ft.TextField(label="Server Name", value=server_name, width=300,
                                      bgcolor="#FFFFFF" if not is_dark_mode[0] else "#424242",
                                      border_color="#0288D1", text_style=ft.TextStyle(color="#212121" if not is_dark_mode[0] else "#E0E0E0"))
        new_ip_field = ft.TextField(label="IP Address", value=server_data["ip"], width=300,
                                    bgcolor="#FFFFFF" if not is_dark_mode[0] else "#424242",
                                    border_color="#0288D1", text_style=ft.TextStyle(color="#212121" if not is_dark_mode[0] else "#E0E0E0"))
        new_username_field = ft.TextField(label="Username", value=server_data["username"], width=300,
                                          bgcolor="#FFFFFF" if not is_dark_mode[0] else "#424242",
                                          border_color="#0288D1", text_style=ft.TextStyle(color="#212121" if not is_dark_mode[0] else "#E0E0E0"))
        new_password_field = ft.TextField(label="Password", value=server_data["password"], password=True, width=300,
                                          bgcolor="#FFFFFF" if not is_dark_mode[0] else "#424242",
                                          border_color="#0288D1", text_style=ft.TextStyle(color="#212121" if not is_dark_mode[0] else "#E0E0E0"))

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
            if new_name != old_name and rename_server(servers, old_name, new_name):
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
            title=ft.Text(f"Edit {server_name}", size=18, weight=ft.FontWeight.BOLD, color="#0288D1" if not is_dark_mode[0] else "#4FC3F7"),
            content=ft.Column([new_name_field, new_ip_field, new_username_field, new_password_field], spacing=10),
            actions=[
                ft.TextButton("Save", on_click=save_changes),
                ft.TextButton("Cancel", on_click=close_dialog)
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            bgcolor="#F0F0F0" if not is_dark_mode[0] else "#2D2D2D",
            shape=ft.RoundedRectangleBorder(radius=10)
        )
        page.overlay.append(edit_dialog)
        edit_dialog.open = True
        page.update()

    def close_management(e):
        page.controls.remove(management_container)
        page.update()

    management_container = ft.Container(
        content=ft.Column([
            ft.Text("Manage Servers", size=22, weight=ft.FontWeight.BOLD, color="#0288D1" if not is_dark_mode[0] else "#4FC3F7"),
            servers_list,
            ft.Row([message_field], alignment=ft.MainAxisAlignment.CENTER),
            ft.ElevatedButton("Close", on_click=close_management, style=ft.ButtonStyle(bgcolor="#0288D1", color="#FFFFFF"))
        ], spacing=20, expand=True),
        gradient=ft.LinearGradient(begin=ft.Alignment(0, -1), end=ft.Alignment(0, 1),
                                   colors=["#FFFFFF", "#E0E0E0"] if not is_dark_mode[0] else ["#1E1E1E", "#2D2D2D"]),
        padding=20,
        expand=True,
        border_radius=10,
        shadow=ft.BoxShadow(blur_radius=15, color="#40000000")
    )

    page.controls.append(management_container)
    page.update()
    update_servers_list()

def view_iptables(ssh_manager, log_callback, loading_indicator, log_display):
    def run_iptables():
        clear_log(log_display)
        try:
            loading_indicator.visible = True
            loading_indicator.update()
            log_callback("Fetching iptables...")
            ssh_manager.execute_command("iptables -L -v -n --line-numbers", log_callback)
        except Exception as e:
            log_callback(f"Error: {e}")
        finally:
            loading_indicator.visible = False
            loading_indicator.update()
    threading.Thread(target=run_iptables, daemon=True).start()

def start_tcpdump(ssh_manager, log_callback, loading_indicator, tcpdump_button, stop_tcpdump_button, tcpdump_running, tcpdump_thread, log_display):
    def run_tcpdump():
        clear_log(log_display)
        try:
            if not ssh_manager.client:
                log_callback("SSH client not initialized")
                return

            loading_indicator.visible = True
            loading_indicator.update()
            log_callback("Starting tcpdump...")
            stop_tcpdump_button.disabled = False
            stop_tcpdump_button.update()
            tcpdump_running.set()

            log_callback("Checking tcpdump availability...")
            stdin_check, stdout_check, stderr_check = ssh_manager.client.exec_command("which tcpdump")
            check_output = stdout_check.read().decode().strip()
            check_error = stderr_check.read().decode().strip()
            if not check_output:
                log_callback(f"tcpdump not found: {check_error or 'command not available'}")
                return
            else:
                log_callback(f"tcpdump found at: {check_output}")

            log_callback("Executing tcpdump command...")
            stdin, stdout, stderr = ssh_manager.client.exec_command("tcpdump -l -i any port 443 and 'tcp[13] & 2 != 0'")
            for line in iter(stdout.readline, ""):
                if not tcpdump_running.is_set():
                    break
                log_callback(line.strip())
            error_output = stderr.read().decode().strip()
            if error_output:
                log_callback(f"Error output: {error_output}")
            exit_status = stdout.channel.recv_exit_status()
            log_callback(f"tcpdump exited with status: {exit_status}")
        except Exception as e:
            log_callback(f"Exception caught: {type(e).__name__}: {str(e)}")
            error_output = stderr.read().decode().strip() if 'stderr' in locals() else "No stderr available"
            log_callback(f"Additional error info: {error_output}")
        finally:
            tcpdump_running.clear()
            loading_indicator.visible = False
            stop_tcpdump_button.disabled = True
            tcpdump_button.disabled = False
            stop_tcpdump_button.update()
            tcpdump_button.update()
            loading_indicator.update()
            log_callback("tcpdump process finished")

    tcpdump_running.clear()
    tcpdump_thread[0] = threading.Thread(target=run_tcpdump, daemon=True)
    tcpdump_thread[0].start()
    tcpdump_button.disabled = True
    tcpdump_button.update()

def stop_tcpdump(ssh_manager, log_callback, tcpdump_button, stop_tcpdump_button, tcpdump_running, tcpdump_thread, 
                 loading_indicator, ip_list, log_display, add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button):
    clear_log(log_display)
    try:
        log_callback("Stopping tcpdump...")
        tcpdump_running.clear()
        ssh_manager.execute_command("pkill tcpdump", log_callback)
        if tcpdump_thread[0]:
            tcpdump_thread[0].join(timeout=2)
        stop_tcpdump_button.disabled = True
        tcpdump_button.disabled = False
        loading_indicator.visible = False
        stop_tcpdump_button.update()
        tcpdump_button.update()
        loading_indicator.update()
        update_ip_buttons(ip_list, add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button)
    except Exception as e:
        log_callback(f"Error: {e}")

def update_ip_buttons(ip_list, add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button):
    selected_ips = [cb.label for cb in ip_list.controls if cb.value]
    add_drop_button.disabled = not selected_ips
    add_drop_subnet_button.disabled = not selected_ips
    remove_drop_button.disabled = not selected_ips
    whois_button.disabled = not selected_ips
    add_drop_button.update()
    add_drop_subnet_button.update()
    remove_drop_button.update()
    whois_button.update()

def add_to_drop(ssh_manager, ip_list, drop_list, log_callback, log_display):
    selected_ips = [cb.label for cb in ip_list.controls if cb.value]
    if not selected_ips:
        log_callback("No IPs selected")
        return
    clear_log(log_display)
    try:
        for ip in selected_ips:
            if ip not in drop_list:
                log_callback(f"Adding {ip} to DROP...")
                ssh_manager.execute_command(f"iptables -A INPUT -s {ip} -j DROP", log_callback)
                drop_list.add(ip)
        log_callback("IPs added to DROP")
    except Exception as e:
        log_callback(f"Error: {e}")

def add_drop_by_subnet(ssh_manager, ip_list, drop_list, log_callback, log_display):
    selected_ips = [cb.label for cb in ip_list.controls if cb.value]
    if not selected_ips:
        log_callback("No IPs selected")
        return
    clear_log(log_display)
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

def remove_from_drop(ssh_manager, ip_list, drop_list, log_callback, log_display):
    selected_ips = [cb.label for cb in ip_list.controls if cb.value]
    if not selected_ips:
        log_callback("No IPs selected")
        return
    clear_log(log_display)
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

def configure_whois_fields(page, parse_whois_checkbox, whois_fields):
    fields = {
        "inetnum": "IP Range", "netname": "Network Name", "country": "Country", "org": "Organization",
        "admin-c": "Admin Contact", "tech-c": "Tech Contact", "status": "Status", "mnt-by": "Maintained By",
        "created": "Created", "last-modified": "Last Modified"
    }
    checkboxes = [ft.Checkbox(label=display_name, value=key in whois_fields[0], data=key) for key, display_name in fields.items()]

    def save_fields(e):
        selected_fields = [cb.data for cb in checkboxes if cb.value]
        whois_fields[0] = selected_fields
        page.overlay.remove(config_dialog)
        page.update()

    config_dialog = ft.AlertDialog(
        title=ft.Text("Select WhoIs Fields"),
        content=ft.Column(checkboxes, scroll=ft.ScrollMode.AUTO, height=200),
        actions=[ft.TextButton("Save", on_click=save_fields), ft.TextButton("Cancel", on_click=lambda e: page.overlay.remove(config_dialog))],
        actions_alignment=ft.MainAxisAlignment.END
    )
    page.overlay.append(config_dialog)
    config_dialog.open = True
    page.update()

def run_whois(ssh_manager, ip_list, log_display, parse_whois_checkbox, log_callback, whois_fields):
    selected_ips = [cb.label for cb in ip_list.controls if cb.value]
    if not selected_ips:
        log_callback("No IPs selected")
        return
    clear_log(log_display)
    for ip in selected_ips:
        try:
            log_callback(f"Running whois for {ip}...")
            if parse_whois_checkbox.value:
                output_lines = []
                def collect_output(line):
                    output_lines.append(line)
                ssh_manager.execute_command(f"whois {ip}", collect_output)
                threading.Event().wait(1)
                if output_lines:
                    full_output = "\n".join(output_lines)
                    parsed_output = parse_whois_output(full_output, whois_fields[0])
                    log_display.content.value = parsed_output
                    log_display.content.text_style = ft.TextStyle(color="#0288D1" if page.theme_mode == ft.ThemeMode.LIGHT else "#4FC3F7")
                    log_display.content.update()
                else:
                    log_callback("No whois data received")
            else:
                ssh_manager.execute_command(f"whois {ip}", log_callback)
        except Exception as e:
            log_callback(f"Error: {e}")