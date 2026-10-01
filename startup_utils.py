"""
Startup & Tray Mode Utilities — shared by NetGuard, MailShield, CleanGuard, and VPN Guard
Handles Windows startup registration and system tray (stealth) mode.
"""

import os
import sys
import threading

IS_WINDOWS = sys.platform == "win32"

# ═══════════════════════════════════════════════════════════════════════════
# WINDOWS STARTUP REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════

STARTUP_REG_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def is_startup_enabled(program_name: str) -> bool:
    """Check if a program is registered to start at Windows boot"""
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REG_PATH, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, program_name)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            return False
    except Exception:
        return False


def enable_startup(program_name: str, bat_path: str) -> bool:
    """Register a program to start at Windows boot via registry"""
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        bat_path = os.path.abspath(bat_path)
        if not os.path.exists(bat_path):
            return False
        # Use cmd /c to run the bat minimized
        cmd = f'cmd /c start /min "" "{bat_path}"'
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REG_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, program_name, 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"[!] Erreur enregistrement startup {program_name}: {e}")
        return False


def disable_startup(program_name: str) -> bool:
    """Remove a program from Windows startup"""
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REG_PATH, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, program_name)
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"[!] Erreur suppression startup {program_name}: {e}")
        return False


def toggle_startup(program_name: str, bat_path: str) -> bool:
    """Toggle startup registration, returns new state"""
    if is_startup_enabled(program_name):
        disable_startup(program_name)
        return False
    else:
        enable_startup(program_name, bat_path)
        return True


def get_all_startup_states() -> dict:
    """Get startup states for all NetGuard AI programs"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "NetGuard AI": is_startup_enabled("NetGuard AI"),
        "MailShield Pro": is_startup_enabled("MailShield Pro"),
        "CleanGuard Pro": is_startup_enabled("CleanGuard Pro"),
        "VPN Guard Pro": is_startup_enabled("VPN Guard Pro"),
    }


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM TRAY (STEALTH MODE) — uses pystray
# ═══════════════════════════════════════════════════════════════════════════

def create_tray_icon(program_name: str, on_show=None, on_quit=None):
    """Create a system tray icon for stealth mode.
    Returns (icon, thread) — call icon.stop() to remove.
    on_show: callback when user clicks 'Show'
    on_quit: callback when user clicks 'Quit'
    """
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        print(f"[!] pystray ou Pillow non installe. pip install pystray Pillow")
        return None, None

    # Create a simple colored icon
    colors = {
        "NetGuard AI": "#4d9fff",
        "MailShield Pro": "#3dffb4",
        "CleanGuard Pro": "#ffb347",
        "VPN Guard Pro": "#00d4ff",
    }
    color = colors.get(program_name, "#4d9fff")

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield shape
    draw.rounded_rectangle([8, 4, 56, 56], radius=10, fill=color)
    # Letter in center
    letter = program_name[0]
    try:
        draw.text((22, 12), letter, fill="white")
    except Exception:
        pass

    def _on_show(icon, item):
        if on_show:
            on_show()

    def _on_quit(icon, item):
        icon.stop()
        if on_quit:
            on_quit()

    menu = pystray.Menu(
        pystray.MenuItem(f"Afficher {program_name}", _on_show, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quitter", _on_quit),
    )

    icon = pystray.Icon(program_name, img, program_name, menu)

    tray_thread = threading.Thread(target=icon.run, daemon=True)
    tray_thread.start()

    return icon, tray_thread


def minimize_to_tray(window, program_name: str, on_quit=None):
    """Minimize a pywebview window to system tray.
    Returns the tray icon object.
    """
    def _on_show():
        try:
            window.show()
            window.restore()
        except Exception:
            pass

    icon, _ = create_tray_icon(program_name, on_show=_on_show, on_quit=on_quit)
    if icon:
        try:
            window.hide()
        except Exception:
            pass
    return icon
