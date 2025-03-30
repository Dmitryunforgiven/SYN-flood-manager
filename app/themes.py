import flet as ft

def get_light_theme():
    return ft.Theme(
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

def get_dark_theme():
    return ft.Theme(
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