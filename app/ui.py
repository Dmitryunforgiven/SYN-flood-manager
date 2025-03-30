import flet as ft
import threading
from .themes import get_light_theme
from backend.config import load_config
from .handlers import (toggle_dark_mode, log_callback, connect_to_server, add_server, manage_servers,
                      view_iptables, start_tcpdump, stop_tcpdump, update_ip_buttons, add_to_drop,
                      add_drop_by_subnet, remove_from_drop, run_whois, configure_whois_fields)

def build_ui(page: ft.Page, ssh_manager, servers):
    page.window.width = 800
    page.window.height = 600
    page.padding = 0
    page.window.resizable = True
    page.theme = get_light_theme()
    is_dark_mode = [False]

    servers = load_config()
    whois_fields = [["inetnum", "netname", "country", "org"]]

    unique_ips = set()
    drop_list = set()
    current_server_ip = [None]
    tcpdump_thread = [None]
    tcpdump_running = threading.Event()

    log_display = ft.Container(
        content=ft.TextField(
            multiline=True, read_only=True, expand=True, text_size=13,
            bgcolor="#F5F5F5", border_radius=8, border_color="#BBDEFB",
            text_style=ft.TextStyle(font_family="Roboto Mono", color="#212121"),
        ),
        padding=10, border_radius=8, bgcolor="#FFFFFF",
        shadow=ft.BoxShadow(blur_radius=8, color="#20000000"), expand=True,
    )
    ip_list = ft.ListView(expand=True, auto_scroll=False, padding=10)

    server_dropdown = ft.Dropdown(label="Select Server", hint_text="Choose a server", width=220, text_size=14,
                                  border_radius=8, bgcolor="#FFFFFF", border_color="#BBDEFB", filled=True,
                                  content_padding=10, text_style=ft.TextStyle(color="#212121"),
                                  options=[ft.dropdown.Option(key, key) for key in servers.keys()])
    ip_field = ft.TextField(label="IP Address", width=160, text_size=14, border_radius=8, bgcolor="#FFFFFF",
                            border_color="#BBDEFB", filled=True, content_padding=10,
                            text_style=ft.TextStyle(color="#212121"))
    username_field = ft.TextField(label="Username", width=160, text_size=14, border_radius=8, bgcolor="#FFFFFF",
                                  border_color="#BBDEFB", filled=True, content_padding=10,
                                  text_style=ft.TextStyle(color="#212121"))
    password_field = ft.TextField(label="Password", password=True, width=160, text_size=14, border_radius=8,
                                  bgcolor="#FFFFFF", border_color="#BBDEFB", filled=True, content_padding=10,
                                  text_style=ft.TextStyle(color="#212121"))
    install_packages_checkbox = ft.Checkbox(label="Install Packages", value=False,
                                            tooltip="Install iptables, tcpdump, whois", check_color="#0288D1",
                                            active_color="#4FC3F7", label_style=ft.TextStyle(color="#0D47A1"))
    parse_whois_checkbox = ft.Checkbox(label="Summarize WhoIs output", value=False,
                                       tooltip="Show only key whois information", check_color="#0288D1",
                                       active_color="#4FC3F7", label_style=ft.TextStyle(color="#0D47A1"))
    dark_mode_switch = ft.Switch(label="Dark Mode", value=False, active_color="#4FC3F7",
                                 label_style=ft.TextStyle(color="#0D47A1"))
    loading_indicator = ft.ProgressBar(width=200, visible=False, color="#0288D1", bgcolor="#BBDEFB")

    button_style = ft.ButtonStyle(color="#FFFFFF", bgcolor="#0288D1", shape=ft.RoundedRectangleBorder(radius=8),
                                  elevation=2, overlay_color=ft.Colors.with_opacity(0.1, "#FFFFFF"))
    connect_button = ft.ElevatedButton(text="Connect", width=110, height=40, style=button_style)
    add_server_button = ft.ElevatedButton(text="Add Server", width=110, height=40, style=button_style)
    manage_servers_button = ft.ElevatedButton(text="Manage Servers", width=110, height=40, style=button_style)
    view_iptables_button = ft.ElevatedButton(text="View IPTables rules", width=110, height=40, style=button_style, disabled=True)
    tcpdump_button = ft.ElevatedButton(text="Start TCPdump", width=110, height=40, style=button_style, disabled=True)
    stop_tcpdump_button = ft.ElevatedButton(text="Stop TCPdump", width=90, height=40, style=button_style, disabled=True)
    whois_button = ft.ElevatedButton(text="Whois selected IP", width=90, height=40, style=button_style, disabled=True)
    add_drop_button = ft.ElevatedButton(text="Add IP to drop list", width=110, height=40, style=button_style, disabled=True)
    add_drop_subnet_button = ft.ElevatedButton(text="Drop IP by subnet", width=110, height=40, style=button_style, disabled=True)
    remove_drop_button = ft.ElevatedButton(text="Remove IP from drop list", width=110, height=40, style=button_style, disabled=True)
    whois_config_button = ft.ElevatedButton(text="Config WhoIs", width=110, height=40, style=button_style)

    header_text = ft.Text("SYN Flood Manager", size=24, weight=ft.FontWeight.BOLD, color="#0288D1")
    ip_list_header = ft.Text("Unique IPs", size=16, weight=ft.FontWeight.BOLD, color="#0288D1")
    logs_header = ft.Text("Logs", size=16, weight=ft.FontWeight.BOLD, color="#0288D1")
    selected_server_label = ft.Text("", size=14, color="#0288D1", weight=ft.FontWeight.BOLD)

    ip_list_container = ft.Container(
        content=ft.Row([
            ft.Column([ip_list_header, ft.Container(ip_list, expand=True)], expand=True, spacing=12),
            ft.Column([logs_header, ft.Container(log_display, expand=True, height=150)], expand=True, spacing=12)
        ], expand=True, spacing=20, alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        bgcolor="#FFFFFF", border_radius=10, padding=15,
        shadow=ft.BoxShadow(blur_radius=10, color="#30000000"), expand=True,
    )

    main_content = ft.Column([
        header_text,
        ft.Row([server_dropdown, connect_button, manage_servers_button,
                ft.Row([install_packages_checkbox, parse_whois_checkbox, whois_config_button], spacing=20)],
               spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([selected_server_label], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([ip_field, username_field, password_field, add_server_button],
               spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([loading_indicator], alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([view_iptables_button, tcpdump_button, stop_tcpdump_button],
               spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button],
               spacing=15, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
        ip_list_container
    ], spacing=20, expand=True)

    main_container = ft.Container(
        content=ft.Row([main_content, ft.Container(width=50),
                        ft.Column([dark_mode_switch], alignment=ft.MainAxisAlignment.CENTER, expand=False)],
                       expand=True, spacing=10),
        gradient=ft.LinearGradient(begin=ft.Alignment(0, -1), end=ft.Alignment(0, 1),
                                   colors=["#E3F2FD", "#BBDEFB"]),
        padding=25, border_radius=15, expand=True,
    )

    page.add(main_container)

    def log_with_callback(message):
        log_callback(message, log_display, unique_ips, ip_list, current_server_ip, ip_field, is_dark_mode,
                     add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button)

    dark_mode_switch.on_change = lambda e: toggle_dark_mode(page, is_dark_mode, log_display, ip_list, server_dropdown,
                                                            ip_field, username_field, password_field, connect_button,
                                                            add_server_button, manage_servers_button, view_iptables_button,
                                                            tcpdump_button, stop_tcpdump_button, whois_button,
                                                            add_drop_button, add_drop_subnet_button, remove_drop_button,
                                                            main_container, header_text, ip_list_header, logs_header,
                                                            install_packages_checkbox, parse_whois_checkbox, dark_mode_switch,
                                                            ip_list_container)
    connect_button.on_click = lambda _: connect_to_server(page, server_dropdown, servers, ssh_manager, current_server_ip,
                                                          log_with_callback, loading_indicator, install_packages_checkbox,
                                                          view_iptables_button, tcpdump_button, selected_server_label,
                                                          log_display)
    add_server_button.on_click = lambda _: add_server(servers, server_dropdown, ip_field, username_field, password_field,
                                                      log_with_callback)
    manage_servers_button.on_click = lambda _: manage_servers(page, servers, server_dropdown, log_with_callback,
                                                              is_dark_mode)
    view_iptables_button.on_click = lambda _: view_iptables(ssh_manager, log_with_callback, loading_indicator,
                                                            log_display)
    tcpdump_button.on_click = lambda _: start_tcpdump(ssh_manager, log_with_callback, loading_indicator,
                                                      tcpdump_button, stop_tcpdump_button, tcpdump_running,
                                                      tcpdump_thread, log_display)
    stop_tcpdump_button.on_click = lambda _: stop_tcpdump(ssh_manager, log_with_callback, tcpdump_button,
                                                          stop_tcpdump_button, tcpdump_running, tcpdump_thread,
                                                          loading_indicator, ip_list, log_display,
                                                          add_drop_button, add_drop_subnet_button, remove_drop_button, whois_button)
    add_drop_button.on_click = lambda _: add_to_drop(ssh_manager, ip_list, drop_list, log_with_callback, log_display)
    add_drop_subnet_button.on_click = lambda _: add_drop_by_subnet(ssh_manager, ip_list, drop_list, log_with_callback,
                                                                   log_display)
    remove_drop_button.on_click = lambda _: remove_from_drop(ssh_manager, ip_list, drop_list, log_with_callback,
                                                             log_display)
    whois_button.on_click = lambda _: run_whois(ssh_manager, ip_list, log_display, parse_whois_checkbox,
                                                log_with_callback, whois_fields)
    whois_config_button.on_click = lambda _: configure_whois_fields(page, parse_whois_checkbox, whois_fields)