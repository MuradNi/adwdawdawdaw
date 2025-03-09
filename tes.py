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

REGISTERED_WEBHOOK_URL = "https://discord.com/api/webhooks/1264239620409786472/lZCfJXb4ySeqrW4Nr0z1kqcdHZGV8VEvqBx0xda2G_A1b5p6iW56eoPIPkRT5qanVm8p"
UNREGISTERED_WEBHOOK_URL = "https://discord.com/api/webhooks/1266059205824086036/sK4_8FGJR-ZNToMwV2KQsAb1bCTkO32fMXSF4CLTyL9W1pwZO2D27vOJoeHS23TI66es"
GITHUB_API_URL = "https://api.github.com/repos/MuradNi/wdawdawda"
GITHUB_TOKEN = "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"

def log_and_print(message):
    print(message)
    logging.info(message)

def send_uuid_status_webhook(url, content, is_registered=True, user_id=None):
    log_and_print(f"Sending webhook to {url}")
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = 0x00FF00 if is_registered else 0xFF0000
        title = "Registered User Login" if is_registered else "Unregistered User Attempt"
        
        description = f"<@{user_id}>" if is_registered and user_id else content

        banner_url = "https://i.ibb.co.com/f1ZScNq/standard-2.gif"

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "image": {"url": banner_url},
            "footer": {
                "text": "Auto Message Log",
                "icon_url": "https://i.ibb.co/FwddMLs/image.png"
            },
            "thumbnail": {
                "url": "https://i.ibb.co/FwddMLs/image.png"
            },
            "fields": [
                {"name": "Time", "value": current_time, "inline": True},
                {"name": "Status", "value": "Access Granted" if is_registered else "Access Denied", "inline": True}
            ]
        }
        payload = {
            "embeds": [embed],
            "username": "SECURITY AUTO POSTED",
            "avatar_url": "https://ibb.co.com/Y8JHcjh"
        }
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        log_and_print(f"UUID status webhook sent successfully to {url}")
    except Exception as e:
        log_and_print(f"Error sending UUID status webhook: {str(e)}")
    pass

def generate_device_id():
    c = wmi.WMI()
    cpu = c.Win32_Processor()[0]
    bios = c.Win32_BIOS()[0]
    return hashlib.sha256(f"{cpu.ProcessorId}.{bios.SerialNumber}".encode()).hexdigest()

def get_valid_keys():
    try:
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        url = f"{GITHUB_API_URL}/contents/keys.json"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content = base64.b64decode(response.json()["content"]).decode('utf-8')
        return json.loads(content)
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error saat mengambil keys dari GitHub: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Error saat mendecode JSON dari GitHub: {e}")
    except Exception as e:
        logging.error(f"Error tidak terduga saat mengambil keys dari GitHub: {e}")
    return {"keys": {}}

def check_key():
    try:
        device_id = generate_device_id()
        valid_keys = get_valid_keys()
        
        for key, info in valid_keys['keys'].items():
            if info.get('device_id') == device_id and info['status'] == 'used':
                send_uuid_status_webhook(REGISTERED_WEBHOOK_URL, "", is_registered=True, user_id=info['discord_id'])
                return True, "Key valid untuk perangkat ini."
        
        send_uuid_status_webhook(UNREGISTERED_WEBHOOK_URL, "No valid key", is_registered=False)
        return False, "Tidak ada key yang aktif untuk perangkat ini atau key sudah tidak valid."
    except Exception as e:
        log_and_print(f"Error checking key: {str(e)}")
        return False, f"Terjadi kesalahan saat memeriksa key: {str(e)}"

def update_github_keys(updated_keys):
    try:
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Dapatkan informasi file saat ini
        current_file = requests.get(f"{GITHUB_API_URL}/contents/keys.json", headers=headers)
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
        
        response = requests.put(f"{GITHUB_API_URL}/contents/keys.json", headers=headers, json=data)
        response.raise_for_status()
        log_and_print("Keys updated successfully in GitHub")
        return True
    except requests.exceptions.RequestException as e:
        log_and_print(f"Error updating keys in GitHub: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            log_and_print(f"Response content: {e.response.content}")
        return False

def activate_key(entered_key):
    valid_keys = get_valid_keys()
    if entered_key in valid_keys['keys']:
        if valid_keys['keys'][entered_key]['status'] == 'active':
            device_id = generate_device_id()
            
            discord_id = simpledialog.askstring("Discord ID", "Masukkan User ID Discord Anda:")
            if not discord_id:
                return False, "User ID Discord diperlukan.", None
            
            if valid_keys['keys'][entered_key].get('device_id'):
                return False, "Key ini sudah digunakan pada perangkat lain.", None
            
            valid_keys['keys'][entered_key]['status'] = 'used'
            valid_keys['keys'][entered_key]['discord_id'] = discord_id
            valid_keys['keys'][entered_key]['device_id'] = device_id
            
            if update_github_keys(valid_keys):
                send_uuid_status_webhook(REGISTERED_WEBHOOK_URL, "", is_registered=True, user_id=discord_id)
                return True, "Key berhasil diaktifkan.", entered_key
            else:
                return False, "Gagal mengupdate status key. Coba lagi.", None
        else:
            return False, "Key sudah digunakan.", None
    else:
        return False, "Key tidak valid.", None
    
class AutoSpamGUI:
    def __init__(self, master):
        self.master = master
        master.title("Auto Spam by Murad")
        master.geometry("900x600")

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
            channel_id = self.status_tree.item(item, "text")
            current_status = self.status_tree.item(item, "values")[1]
            if current_status == "Running":
                self.stop_single_spam(channel_id)
            else:
                channel_config = self.get_channel_config(channel_id)
                if channel_config:
                    self.start_single_spam(channel_config)

    def on_tree_click(self, event):
        region = self.status_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.status_tree.identify_column(event.x)
            if column == "#7":  # Action column
                item = self.status_tree.identify_row(event.y)
                channel_id = self.status_tree.item(item, "text")
                current_status = self.status_tree.item(item, "values")[1]
                if current_status == "Running":
                    if messagebox.askyesno("Confirm Stop", f"Are you sure you want to stop the spam for channel {channel_id}?"):
                        self.stop_single_spam(channel_id)
                else:
                    channel_config = self.get_channel_config(channel_id)
                    if channel_config:
                        self.start_single_spam(channel_config)

    def get_channel_config(self, channel_id):
        for channel in self.config.get('channels', []):
            if channel.get('channel_id') == channel_id:
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
        if self.status_tree is None or not self.status_tree.winfo_exists():
            logging.error("Status tree is not initialized or no longer exists")
            return

        try:
            # Clear existing items
            for item in self.status_tree.get_children():
                self.status_tree.delete(item)

            total_messages = 0
            any_running = False

            # Update items
            with self.channel_status_lock:
                for channel_id, status in self.channel_status.items():
                    channel_config = self.get_channel_config(channel_id)
                    if not channel_config:
                        logging.warning(f"Channel config not found for {channel_id}")
                        continue

                    channel_name = status.get('channel_name', f"Channel {channel_id}")
                    is_running = status.get('status', '') == 'Running'
                    any_running |= is_running

                    running_time = self.format_time_difference(time.time() - status.get('start_time', time.time())) if is_running else '--'
                    last_message_time = self.format_time_difference(time.time() - status.get('last_message_time', time.time())) if status.get('last_message_time') else 'Never'

                    interval = self.format_time_config(status.get('time_config', {}))

                    total_messages += status.get('message_count', 0)

                    action_text = "Stop" if is_running else "Start"

                    self.status_tree.insert("", "end", text=channel_id, values=(
                        channel_name,
                        status.get('status', 'Unknown'),
                        running_time,
                        str(status.get('message_count', 0)),
                        last_message_time,
                        interval,
                        action_text
                    ))

            # Update overall status
            if hasattr(self, 'overall_status_label') and self.overall_status_label.winfo_exists():
                self.overall_status_label.config(text=f"Overall Status: {'Running' if any_running else 'Stopped'}")
            if hasattr(self, 'total_messages_label') and self.total_messages_label.winfo_exists():
                self.total_messages_label.config(text=f"Total Messages Sent: {total_messages}")

            # Schedule the next update
            self.master.after(1000, self.update_status_display)

        except tk.TclError as e:
            logging.error(f"Tkinter error in update_status_display: {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error in update_status_display: {str(e)}")

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
                {"name": "📝 Message", "value": "```This is a test message from Auto Spam by Murad.```", "inline": False},
            ],
            "footer": {"text": "Auto Post Message | Creator: Murad"}
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

        edit_window = tk.Toplevel(self.master)
        edit_window.title("Edit Channel Configuration")
        edit_window.geometry("400x650")

        ttk.Label(edit_window, text="Channel ID:").pack(pady=5)
        channel_id_entry = ttk.Entry(edit_window, width=50)
        channel_id_entry.insert(0, channel["channel_id"])
        channel_id_entry.pack(pady=5)

        ttk.Label(edit_window, text="Channel Name:").pack(pady=5)
        channel_name_entry = ttk.Entry(edit_window, width=50)
        channel_name_entry.insert(0, channel.get("channel_name", ""))
        channel_name_entry.pack(pady=5)

        ttk.Label(edit_window, text="Message:").pack(pady=5)
        message_text = tk.Text(edit_window, height=5, width=50)
        message_text.insert("1.0", channel["message"])
        message_text.pack(pady=5)

        ttk.Label(edit_window, text="Time Interval:").pack(pady=5)
        time_frame = ttk.Frame(edit_window)
        time_frame.pack(pady=5)

        time_entries = {}
        for unit in ["weeks", "days", "hours", "minutes", "seconds"]:
            ttk.Label(time_frame, text=f"{unit.capitalize()}:").pack(side=tk.LEFT)
            entry = ttk.Entry(time_frame, width=5)
            entry.insert(0, str(channel["time_config"].get(unit, "")))
            entry.pack(side=tk.LEFT, padx=2)
            time_entries[unit] = entry

        ttk.Label(edit_window, text="Ping User ID:").pack(pady=5)
        ping_user_entry = ttk.Entry(edit_window, width=50)
        ping_user_entry.insert(0, channel.get("ping_user", ""))
        ping_user_entry.pack(pady=5)

        is_dm_var = tk.BooleanVar(value=channel.get("is_dm", False))
        ttk.Checkbutton(edit_window, text="Send as DM", variable=is_dm_var).pack(pady=5)

        auto_delete_var = tk.BooleanVar(value=channel.get("auto_delete", False))
        ttk.Checkbutton(edit_window, text="Auto Delete Previous Message", variable=auto_delete_var).pack(pady=5)

        ttk.Label(edit_window, text="Token:").pack(pady=5)
        token_combobox = ttk.Combobox(edit_window, values=list(self.config["tokens"].keys()))
        token_combobox.set(channel.get("token_name", ""))
        token_combobox.pack(pady=5)

        def save_changes():
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
        
            if self.update_channel(channel["channel_id"], new_config):
                messagebox.showinfo("Success", "Channel configuration updated successfully")
                self.update_status_display()  # Refresh the status display
            else:
                messagebox.showerror("Error", "Failed to update channel configuration")
            edit_window.destroy()
    
        # Add this line to create the Save Changes button
        ttk.Button(edit_window, text="Save Changes", command=save_changes).pack(pady=10)
    
        # If you want to add a cancel button as well, you can add this:
        ttk.Button(edit_window, text="Cancel", command=edit_window.destroy).pack(pady=5)
        self.update_channel_status()

    def save_settings(self):
        self.config["webhook_url"] = self.webhook_url_entry.get()
        self.config["webhook_channel_id"] = self.webhook_channel_id_entry.get()
        
        # Save token configurations
        for token_name in self.config["tokens"]:
            token_value = self.config["tokens"][token_name]
            self.config["tokens"][token_name] = token_value

        # Save channel configurations
        for channel in self.config["channels"]:
            channel_id = channel["channel_id"]
            channel_name = channel.get("channel_name", "")
            message = channel["message"]
            time_config = channel["time_config"]
            is_dm = channel.get("is_dm", False)
            ping_user = channel.get("ping_user", "")
            auto_delete = channel.get("auto_delete", False)
            token_name = channel.get("token_name", "")

            channel.update({
                "channel_id": channel_id,
                "channel_name": channel_name,
                "message": message,
                "time_config": time_config,
                "is_dm": is_dm,
                "ping_user": ping_user,
                "auto_delete": auto_delete,
                "token_name": token_name
            })

        self.save_config()
        logging.info(f"Settings saved. Webhook URL: {self.config['webhook_url']}")
        logging.info(f"Number of tokens saved: {len(self.config['tokens'])}")
        logging.info(f"Number of channels saved: {len(self.config['channels'])}")
        messagebox.showinfo("Success", "Settings saved successfully")

    def start_single_spam(self, config):
        channel_id = config.get("channel_id")
        token_name = config.get("token_name")

        if not channel_id or not token_name or token_name not in self.config.get("tokens", {}):
            messagebox.showerror("Error", f"Invalid configuration for channel {channel_id}")
            logging.error(f"Failed to start spam for channel {channel_id}: Invalid configuration")
            return

        token = self.config["tokens"][token_name]
        thread_key = f"{channel_id}_{token_name}"

        if thread_key in self.channel_threads and self.channel_threads[thread_key].is_alive():
            messagebox.showinfo("Info", f"Spam thread for channel {channel_id} with token {token_name} is already running")
            logging.info(f"Attempted to start an already running spam thread for channel {channel_id} with token {token_name}")
            return

        thread = threading.Thread(
            target=self.spam_loop,
            args=(
                channel_id,
                config.get("message", ""),
                token,
                config.get("time_config", {}),
                config.get("ping_user", ""),
                config.get("auto_delete", False),
                config.get("is_dm", False),
                token_name
            )
        )
        thread.daemon = True
        self.channel_threads[thread_key] = thread

        try:
            thread.start()

            with self.channel_status_lock:
                self.channel_status[thread_key] = {
                    "start_time": time.time(),
                    "status": "Running",
                    "message_count": 0,
                    "last_message_time": None,
                    "time_config": config.get('time_config', {}),
                    "channel_name": config.get("channel_name", ""),
                    "is_dm": config.get("is_dm", False)
                }

            self.update_status_display()

            channel_name = config.get("channel_name", "")
            display_name = f"{channel_name} - " if channel_name else ""
            message = f"Spam thread started for {'DM' if config.get('is_dm', False) else 'channel'} {display_name}{channel_id} using token {token_name}"

            messagebox.showinfo("Started", message)
            logging.info(message)

        except Exception as e:
            error_message = f"Failed to start spam thread for channel {channel_id} with token {token_name}: {str(e)}"
            messagebox.showerror("Error", error_message)
            logging.error(error_message)

            if thread_key in self.channel_threads:
                del self.channel_threads[thread_key]

            with self.channel_status_lock:
                if thread_key in self.channel_status:
                    self.channel_status[thread_key]["status"] = "Failed to Start"

            self.update_status_display()

    def get_channel_running_time(self, channel_id):
        with self.channel_status_lock:
            if channel_id in self.channel_status:
                start_time = self.channel_status[channel_id]["start_time"]
                stop_time = self.channel_status[channel_id].get("stop_time", time.time())
                return stop_time - start_time
        return 0

    def stop_single_spam(self, channel_id):
        if channel_id in self.channel_threads:
            # Set a flag in the thread to signal it to stop
            self.channel_threads[channel_id].stop_flag = True
            self.channel_threads[channel_id].join(timeout=5)  # Wait up to 5 seconds for the thread to finish
            if self.channel_threads[channel_id].is_alive():
                logging.warning(f"Thread for channel {channel_id} did not stop properly")
            del self.channel_threads[channel_id]

        with self.channel_status_lock:
            if channel_id in self.channel_status:
                self.channel_status[channel_id]["status"] = "Stopped"
                self.channel_status[channel_id]["stop_time"] = time.time()

        self.update_status_display()
        logging.info(f"Spam thread stopped for channel {channel_id}")

        # Show alert
        messagebox.showinfo("Stopped", f"Spam thread for channel {channel_id} has been stopped")

    def load_initial_configurations(self):
        self.channel_status = {}  # Reset channel_status
        for channel_config in self.config.get("channels", []):
            channel_id = channel_config.get("channel_id")
            if channel_id:
                with self.channel_status_lock:
                    self.channel_status[channel_id] = {
                        "status": "Stopped",
                        "message_count": 0,
                        "last_message_time": None,
                        "time_config": channel_config.get('time_config', {}),
                        "channel_name": channel_config.get("channel_name", f"Channel {channel_id}"),
                        "is_dm": channel_config.get("is_dm", False)
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
        self.stop_event.set()
        for channel_id in list(self.channel_threads.keys()):
            self.stop_single_spam(channel_id)
        self.is_running = False
        self.overall_status_label.config(text="Overall Status: Stopped")
        messagebox.showinfo("Stopped", "All spam threads have been stopped")
        logging.info("All spam threads stopped")

    def spam_loop(self, channel_id, message, token, time_config, ping_user, auto_delete, is_dm, token_name):
        thread_key = f"{channel_id}_{token_name}"
        thread = threading.current_thread()
        thread.stop_flag = False
        last_message_id = None

        while not thread.stop_flag:
            try:
                # Send the message
                success, result, new_message_id = self.send_discord_message(token, channel_id, message, last_message_id if auto_delete else None, is_dm)

                # Update channel status
                with self.channel_status_lock:
                    if thread_key in self.channel_status:
                        self.channel_status[thread_key]['last_attempt_time'] = time.time()

                        if success:
                            self.channel_status[thread_key]['message_count'] += 1
                            self.channel_status[thread_key]['last_message_time'] = time.time()
                            self.channel_status[thread_key]['last_message_id'] = new_message_id
                            last_message_id = new_message_id
                            logging.info(f"Success {'DM' if is_dm else 'channel'} {channel_id} with token {token_name}")
                        else:
                            self.channel_status[thread_key]['last_error'] = result
                            logging.error(f"Failed to send message to {'DM' if is_dm else 'channel'} {channel_id} with token {token_name}: {result}")

                if success:
                    self.message_count += 1 

                logging.info(f"Spam attempt result for channel {channel_id} with token {token_name}: {result}")

                self.send_webhook(channel_id, message, success, time_config, ping_user, is_dm)

                if thread.stop_flag:
                    break
                
                delay = self.calculate_delay(time_config)

                start_time = time.time()
                while time.time() - start_time < delay:
                    if thread.stop_flag:
                        break
                    time.sleep(min(1, delay - (time.time() - start_time)))

            except Exception as e:
                error_message = f"Error in spam loop for channel {channel_id} with token {token_name}: {str(e)}"
                logging.error(error_message)

                with self.channel_status_lock:
                    if thread_key in self.channel_status:
                        self.channel_status[thread_key]['status'] = 'Error'

                # Wait a short time before retrying to avoid rapid-fire errors
                time.sleep(5)

        # Thread is stopping
        with self.channel_status_lock:
            if thread_key in self.channel_status:
                self.channel_status[thread_key]['status'] = 'Stopped'

        logging.info(f"Spam loop for {'DM' if is_dm else 'channel'} {channel_id} with token {token_name} stopped")

    
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
        if is_dm:
            api_url = f"https://discord.com/api/v9/users/@me/channels"
            dm_payload = {"recipient_id": channel_id}
            headers = {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
            try:
                dm_response = requests.post(api_url, headers=headers, json=dm_payload, timeout=10, verify=self.cert_path)
                dm_response.raise_for_status()
                dm_channel = dm_response.json()
                channel_id = dm_channel['id']
            except requests.exceptions.RequestException as e:
                error_message = f'Failed to create DM channel: {str(e)}'
                logging.error(error_message)
                return False, error_message, None

        api_url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }
        payload = {
            'content': message
        }
        try:
            if last_message_id and not is_dm:
                delete_url = f"{api_url}/{last_message_id}"
                delete_response = requests.delete(delete_url, headers=headers, timeout=10, verify=self.cert_path)
                delete_response.raise_for_status()
                logging.info(f"Successfully deleted previous message in {'DM' if is_dm else 'channel'} {channel_id}")

            response = requests.post(api_url, headers=headers, json=payload, timeout=10, verify=self.cert_path)
            response.raise_for_status()
            logging.info(f"Successfully sent message to {'DM' if is_dm else 'channel'} {channel_id}")
            return True, f'Message sent successfully to {"DM" if is_dm else "channel"} <#{channel_id}>!', response.json().get('id')
        except requests.exceptions.RequestException as e:
            error_message = f'Failed to send message to {"DM" if is_dm else "channel"} <#{channel_id}>: {str(e)}'
            logging.error(error_message)
            if hasattr(e, 'response'):
                logging.error(f"Response status code: {e.response.status_code}")
                logging.error(f"Response content: {e.response.text}")
            return False, error_message, None

    def update_channel(self, channel_id, new_config):
        for i, channel in enumerate(self.config["channels"]):
            if channel["channel_id"] == channel_id:
                self.config["channels"][i] = new_config
                self.save_config()
                return True
        return False

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

        if hasattr(self, 'overall_status_label'):
            self.overall_status_label.config(text="Overall Status: Stopped")

        if hasattr(self, 'status_tree'):
            for item in self.status_tree.get_children():
                channel_id = self.status_tree.item(item)['text']
                self.status_tree.item(item, values=(
                    self.status_tree.item(item)['values'][0], 
                    "Stopped",
                    "--",  
                    self.status_tree.item(item)['values'][3],  
                    self.status_tree.item(item)['values'][4],  
                    self.status_tree.item(item)['values'][5],  
                    "Start"  
                ))

        self.update_status_display()
        messagebox.showinfo("Stopped", "All spam threads have been stopped")
        logging.info("All spam threads stopped")


    def format_time_config(self, time_config):
        formatted = []
        for unit, value in time_config.items():
            if value > 0:
                formatted.append(f"{value} {unit}")
        return " ".join(formatted) if formatted else "Instant"

    def calculate_delay(self, time_config):
        total_seconds = 0
        for unit, value in time_config.items():
            if unit == 'weeks':
                total_seconds += value * 7 * 24 * 3600
            elif unit == 'days':
                total_seconds += value * 24 * 3600
            elif unit == 'hours':
                total_seconds += value * 3600
            elif unit == 'minutes':
                total_seconds += value * 60
            elif unit == 'seconds':
                total_seconds += value
        return max(total_seconds, 1)  # Ensure at least 1 second delay 

    def send_webhook(self, channel_id, message, success, time_config, ping_user=None, is_dm=False):
        webhook_url = self.config.get('webhook_url')

        if not webhook_url:
            logging.warning("Webhook URL is not set. Skipping webhook send.")
            return

        logging.info(f"Preparing to send webhook for {'DM' if is_dm else 'channel'} {channel_id}")

        current_time = time.strftime("%I:%M:%S %p")

        # Calculate running time based on channel status
        running_time_str = "00:00:00"
        with self.channel_status_lock:
            if channel_id in self.channel_status:
                start_time = self.channel_status[channel_id].get('start_time')
                if start_time:
                    running_time = datetime.now() - datetime.fromtimestamp(start_time)
                    hours, remainder = divmod(int(running_time.total_seconds()), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    running_time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        banner_url = "https://i.ibb.co.com/f1ZScNq/standard-2.gif"  # Replace with actual banner image URL

        embed = {
            "title": " Auto Message Log ",
            "color": 0x9B59B6,
            "fields": [
                {"name": "<a:seru:1204280141145186334> Status", "value": "<a:kk_gif_Online_Ping:1204283707251236904> Message sent successfully" if success else "<a:offline:1204283658895368264> Failed to send message", "inline": False},
                {"name": "<:messenger:1268148703252971584> Channel", "value": f"<#{channel_id}>" if not is_dm else f"DM to <#{channel_id}>", "inline": True},
                {"name": "<a:crap5:1268148019740540928> Time", "value": current_time, "inline": True},
                {"name": "<a:XYRASirine:1204282584503296040> Running Time", "value": running_time_str, "inline": True},
                {"name": "<a:pin:1204280241653284904> Messages Sent", "value": str(self.get_message_count(channel_id)), "inline": True},
                {"name": "<:clock:1268147985901158506> Interval", "value": self.format_time_config(time_config), "inline": True},
                {"name": "<:birth:1268147985901158506> Message", "value": f"```{message[:1000]}```", "inline": False},
            ],
            "image": {"url": banner_url},
            "footer": {
                "text": "Auto Post | Creator: Murad"
            }
        }

        payload = {
            "embeds": [embed],
            "username": "Auto Message Log",
            "avatar_url": "https://i.ibb.co.com/FwddMLs/image.png"
        }

        # Add ping to payload if message failed and ping_user is provided
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
        with self.channel_status_lock:
            if channel_id in self.channel_status:
                return self.channel_status[channel_id].get('message_count', 0)
        return 0
    # Jika ada setup tambahan yang diperlukan setelah inisialisasi AutoSpamGUI, tambahkan di sini

class AnimatedGIF:
    def __init__(self, master, gif_url):
        self.master = master
        self.gif_url = gif_url
        self.frames = []
        self.current_frame = 0

        self.load_gif()

        self.image_label = ttk.Label(master)
        self.image_label.pack(pady=5)

        self.animate(0)

    def load_gif(self):
        response = requests.get(self.gif_url)
        gif = Image.open(BytesIO(response.content))
        
        for frame in range(0, gif.n_frames):
            gif.seek(frame)
            frame_image = gif.copy().resize((480, 200))
            photo = ImageTk.PhotoImage(frame_image)
            self.frames.append(photo)

    def animate(self, counter):
        self.image_label.config(image=self.frames[self.current_frame])
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.master.after(100, self.animate, counter + 1)

def show_loading_window():
    loading_window = tk.Toplevel()
    loading_window.title("Loading")
    loading_window.geometry("500x300")
    loading_window.resizable(False, False)
    loading_window.attributes('-topmost', True)
    loading_window.overrideredirect(True)
    
    screen_width = loading_window.winfo_screenwidth()
    screen_height = loading_window.winfo_screenheight()
    x_coordinate = int((screen_width/2) - (250))
    y_coordinate = int((screen_height/2) - (150))
    
    loading_window.geometry(f"500x300+{x_coordinate}+{y_coordinate}")
    
    frame = ttk.Frame(loading_window, borderwidth=2, relief='raised')
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    # Load animated GIF
    gif_url = "https://i.ibb.co.com/f1ZScNq/standard-2.gif"  # Replace with your GIF URL
    try:
        animated_gif = AnimatedGIF(frame, gif_url)
    except Exception as e:
        print(f"Error loading GIF: {e}")
        error_label = ttk.Label(frame, text="GIF could not be loaded", font=("Arial", 16))
        error_label.pack(pady=20)
    
    progress = ttk.Progressbar(frame, mode="indeterminate", length=450)
    progress.pack(pady=10)
    progress.start()
    
    label = ttk.Label(frame, text="Checking Your Keys")
    label.pack()
    
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
    root = create_themed_tk()
    root.withdraw()  # Hide the main window initially

    loading_window = show_loading_window()
    
    def after_loading():
        loading_window.destroy()
        if check_and_activate_key(root):
            start_main_application(root)
        else:
            root.destroy()

    root.after(2000, after_loading)

    root.mainloop()

# Panggil fungsi main() untuk memulai aplikasi
if __name__ == "__main__":
    main()
