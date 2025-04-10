#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MunchinProject - Gelişmiş Dosya Şifreleme Aracı

import os
import base64
import pickle
import hashlib
import random
import string
import subprocess
import threading
import time
import sys
import winreg
import concurrent.futures
import multiprocessing
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Özel modülleri içe aktar
try:
    from file_analyzer import FileAnalyzer
    from tray_manager import TrayManager
    from steganography import Steganography
    from scheduler import TaskScheduler
except ImportError as e:
    print(f"Modül içe aktarma hatası: {e}")

def generate_key(password):
    """Şifre tabanlı anahtar üretme"""
    password = password.encode()
    salt = b'salt_'  # Sabit salt kullanıyoruz - gerçek uygulamalarda değişken olmalı
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(file_path, key):
    """Dosyayı şifrele"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        return True
    except:
        return False

def decrypt_file(file_path, key):
    """Dosyayı çöz"""
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    except:
        return False

def secure_delete(file_path, passes=3):
    """
    Dosyayı geri dönülmez şekilde sil (srm benzeri)
    passes: Üzerine yazma geçiş sayısı
    """
    if not os.path.isfile(file_path):
        return False
    
    try:
        # Dosya boyutunu al
        file_size = os.path.getsize(file_path)
        
        # Dosyayı birkaç kez üzerine yazarak sil
        for _ in range(passes):
            with open(file_path, "wb") as f:
                # 1. Geçiş: Rastgele verilerle doldur
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            with open(file_path, "wb") as f:
                # 2. Geçiş: Sıfırlarla doldur
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
        
        # Dosyayı sil
        os.remove(file_path)
        return True
    except:
        # Herhangi bir hata durumunda normal silme dene
        try:
            os.remove(file_path)
            return True
        except:
            return False

def generate_strong_password(length=16):
    """Güçlü rastgele şifre üret"""
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Her kategoriden en az bir karakter kullan
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]
    
    # Geri kalan karakterleri rastgele seç
    all_chars = lowercase + uppercase + digits + symbols
    password.extend(random.choice(all_chars) for _ in range(length - 4))
    
    # Karakterleri karıştır
    random.shuffle(password)
    return ''.join(password)

def obfuscate_data(data, key):
    """Veriyi basit bir algoritma ile karıştır"""
    seed = int(hashlib.sha256((key + "munching_salt").encode()).hexdigest(), 16) % 10000
    random.seed(seed)
    char_mapping = list(range(256))
    random.shuffle(char_mapping)
    if isinstance(data, str):
        data = data.encode()
    return bytes([char_mapping[b] for b in data])

def wipe_free_space(drive_letter, passes=1):
    """Boş disk alanını güvenli bir şekilde sil (Windows için)"""
    import tempfile
    
    try:
        # Geçici dosya oluştur
        temp_dir = os.path.join(drive_letter, 'temp_wipe_dir')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        temp_file = os.path.join(temp_dir, "wipe_file")
        
        # Dosyaya sürekli veri yazarak boş alanı doldur
        with open(temp_file, 'wb') as f:
            try:
                # 10MB'lık bloklar halinde yaz
                block_size = 10 * 1024 * 1024  # 10MB
                for _ in range(passes):
                    while True:
                        try:
                            f.write(os.urandom(block_size))
                            f.flush()
                        except:
                            # Disk dolduğunda dur
                            break
            except:
                pass
        
        # Temizleme
        os.remove(temp_file)
        os.rmdir(temp_dir)
        return True
        
    except:
        return False

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MunchinProject")
        self.root.geometry("750x900")
        self.root.minsize(750, 700)
        self.root.resizable(True, True)
        
        # Script bilgileri
        self.script_path = os.path.abspath(__file__)
        self.script_dir = os.path.dirname(self.script_path)
        self.status_file = os.path.join(self.script_dir, '.encrypt_status')
        self.attempt_file = os.path.join(self.script_dir, '.password_attempts')
        self.dark_mode = False
        self.icon_path = os.path.join(self.script_dir, "icon.png")
        
        # Şifre deneme sayısını kontrol et - daha güvenli yöntemle
        self.password_attempts = self.load_password_attempts()
        
        # Eğer şifre deneme hakkı kalmadıysa, hemen dosyaları silme işlemine başla
        if self.password_attempts >= 3:
            self.root.after(500, lambda: self.show_delete_warning_and_delete())
        
        # Tema ayarları
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Helvetica', 12))
        self.style.configure('TLabel', font=('Helvetica', 12))
        self.style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        self.style.configure('Status.TLabel', font=('Helvetica', 10))
        
        # Ek modüller
        try:
            # Modülleri başlat
            self.file_analyzer = FileAnalyzer(self, self.root)
            self.tray_manager = TrayManager(self, self.root)
            self.steganography = Steganography(self, self.root)
            self.task_scheduler = TaskScheduler(self, self.root)
        except Exception as e:
            print(f"Modül başlatma hatası: {e}")
        
        # Ana çerçeve
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        header = ttk.Label(main_frame, text="MunchinProject - Dosya Şifreleme Sistemi", style='Header.TLabel')
        header.pack(pady=10)
        
        # Tema değiştirme butonu
        theme_frame = ttk.Frame(main_frame)
        theme_frame.pack(fill=tk.X)
        
        self.theme_button = ttk.Button(theme_frame, text="Karanlık Mod", command=self.toggle_theme)
        self.theme_button.pack(side=tk.RIGHT)
        
        # Sekme sistemi
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Ana şifreleme sekmesi
        encrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_tab, text="Şifreleme")
        
        # Mod seçimi
        self.mode_frame = ttk.LabelFrame(encrypt_tab, text="İşlem Modu")
        self.mode_frame.pack(fill=tk.X, pady=10)
        
        self.mode_var = tk.StringVar(value="auto")
        auto_mode = ttk.Radiobutton(self.mode_frame, text="Otomatik Algıla", variable=self.mode_var, value="auto")
        encrypt_mode = ttk.Radiobutton(self.mode_frame, text="Şifrele", variable=self.mode_var, value="encrypt")
        decrypt_mode = ttk.Radiobutton(self.mode_frame, text="Şifre Çöz", variable=self.mode_var, value="decrypt")
        
        auto_mode.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        encrypt_mode.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        decrypt_mode.grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)
        
        # Şifre giriş alanı
        password_frame = ttk.Frame(encrypt_tab)
        password_frame.pack(fill=tk.X, pady=10)
        
        password_label = ttk.Label(password_frame, text="Şifre:")
        password_label.pack(anchor=tk.W)
        
        password_entry_frame = ttk.Frame(password_frame)
        password_entry_frame.pack(fill=tk.X, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_entry_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Şifre gösterme/gizleme butonu
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_button = ttk.Button(password_entry_frame, text="👁️", width=3, 
                                             command=self.toggle_password_visibility)
        self.show_password_button.pack(side=tk.LEFT, padx=5)
        
        # Güçlü şifre üretme butonu
        self.gen_password_button = ttk.Button(password_entry_frame, text="🔑", width=3, 
                                            command=self.generate_password)
        self.gen_password_button.pack(side=tk.LEFT)
        
        # Dosya uzantı filtreleme
        filter_frame = ttk.Frame(encrypt_tab)
        filter_frame.pack(fill=tk.X, pady=5)
        
        filter_label = ttk.Label(filter_frame, text="Uzantı Filtresi (ör: .jpg,.png,.txt - boş bırakılırsa tümü):")
        filter_label.pack(anchor=tk.W)
        
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var)
        filter_entry.pack(fill=tk.X, pady=5)
        
        # Dizin seçimi
        dir_frame = ttk.Frame(encrypt_tab)
        dir_frame.pack(fill=tk.X, pady=10)
        
        dir_label = ttk.Label(dir_frame, text="Dizin:")
        dir_label.pack(anchor=tk.W)
        
        dir_select_frame = ttk.Frame(dir_frame)
        dir_select_frame.pack(fill=tk.X, pady=5)
        
        self.dir_var = tk.StringVar(value=self.script_dir)
        dir_entry = ttk.Entry(dir_select_frame, textvariable=self.dir_var, width=30)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(dir_select_frame, text="Gözat", command=self.browse_directory)
        browse_button.pack(side=tk.RIGHT, padx=5)
        
        # Çoklu işlem desteği
        multi_frame = ttk.Frame(encrypt_tab)
        multi_frame.pack(fill=tk.X, pady=5)
        
        self.multiprocessing_var = tk.BooleanVar(value=True)
        multiprocessing_check = ttk.Checkbutton(
            multi_frame, 
            text="Çoklu İşlem Kullan (Daha hızlı işlem)", 
            variable=self.multiprocessing_var
        )
        multiprocessing_check.pack(anchor=tk.W)
        
        # Güvenlik seçenekleri
        security_frame = ttk.LabelFrame(encrypt_tab, text="Güvenlik Seçenekleri")
        security_frame.pack(fill=tk.X, pady=5)
        
        self.secure_delete_var = tk.BooleanVar(value=True)
        secure_delete_check = ttk.Checkbutton(
            security_frame, 
            text="Güvenli Silme (Yavaş ama geri dönüşümsüz)", 
            variable=self.secure_delete_var
        )
        secure_delete_check.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        self.wipe_free_space_var = tk.BooleanVar(value=False)
        wipe_space_check = ttk.Checkbutton(
            security_frame, 
            text="Boş Alanları Temizle (Silme sonrası)", 
            variable=self.wipe_free_space_var
        )
        wipe_space_check.grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        # İşlem butonu
        buttons_frame = ttk.Frame(encrypt_tab)
        buttons_frame.pack(fill=tk.X, pady=15)
        
        self.process_button = ttk.Button(buttons_frame, text="İşlemi Başlat", command=self.start_process)
        self.process_button.pack(side=tk.LEFT, padx=5)
        
        self.backup_button = ttk.Button(buttons_frame, text="Ayarları Yedekle", command=self.backup_security_data)
        self.backup_button.pack(side=tk.LEFT, padx=5)
        
        # İlerleme çubuğu
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(encrypt_tab, orient=tk.HORIZONTAL, length=510, mode='determinate', variable=self.progress_var)
        self.progress.pack(fill=tk.X, pady=10)
        
        # Durum bilgisi
        status_frame = ttk.Frame(encrypt_tab)
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="Hazır")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, style='Status.TLabel')
        status_label.pack(anchor=tk.W, pady=5)
        
        # Sonuç alanı
        self.result_text = tk.Text(status_frame, height=5, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.result_text, command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        
        # Diğer sekmeleri ekle
        try:
            analyzer_tab = self.file_analyzer.create_analyzer_tab(self.notebook)
            steg_tab = self.steganography.create_steganography_tab(self.notebook)
            scheduler_tab = self.task_scheduler.create_scheduler_tab(self.notebook)
        except Exception as e:
            print(f"Sekme oluşturma hatası: {e}")
        
        # Sürüm bilgisi
        version_label = ttk.Label(main_frame, text="MunchinProject v3.0 - Gelişmiş Güvenlik Sistemi", font=('Helvetica', 8))
        version_label.pack(side=tk.BOTTOM, anchor=tk.SE, pady=2)
        
        # Verileri güvenli şekilde yedekle
        self.backup_security_data(silent=True)
        
        # Sistem tepsisi simgesini başlat
        try:
            self.tray_manager.start_tray()
        except Exception as e:
            print(f"Tepsi simgesi başlatma hatası: {e}")
    
    def toggle_theme(self):
        """Karanlık/açık tema geçişi"""
        if self.dark_mode:
            # Açık tema
            self.style.theme_use('clam')
            
            # Ana pencere ve çerçeveler
            self.root.configure(bg="#f0f0f0")
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame) or isinstance(widget, ttk.LabelFrame):
                    widget.configure(style='')
            
            # Metin widget'ı
            self.result_text.config(bg="white", fg="black", insertbackground="black")
            
            # ttk bileşenleri için stil ayarları
            self.style.configure('TFrame', background="#f0f0f0")
            self.style.configure('TLabelframe', background="#f0f0f0")
            self.style.configure('TLabelframe.Label', background="#f0f0f0", foreground="black")
            self.style.configure('TLabel', background="#f0f0f0", foreground="black")
            self.style.configure('TButton', background="#e0e0e0", foreground="black")
            self.style.configure('TCheckbutton', background="#f0f0f0", foreground="black")
            self.style.configure('TRadiobutton', background="#f0f0f0", foreground="black")
            self.style.configure('TEntry', fieldbackground="white", foreground="black")
            self.style.configure('TProgressbar', background='#4CAF50', troughcolor='#e0e0e0')
            self.style.configure('Header.TLabel', background="#f0f0f0", foreground="black", font=('Helvetica', 16, 'bold'))
            self.style.configure('Status.TLabel', background="#f0f0f0", foreground="black", font=('Helvetica', 10))
            
            # Stil haritalaması (hover, active, vb. durumlar)
            self.style.map('TButton', 
                         background=[('active', '#d0d0d0')],
                         foreground=[('active', 'black')])
            self.style.map('TCheckbutton', 
                         background=[('active', '#f0f0f0')],
                         foreground=[('active', 'black')])
            self.style.map('TRadiobutton', 
                         background=[('active', '#f0f0f0')],
                         foreground=[('active', 'black')])
            
            self.theme_button.config(text="Karanlık Mod")
            self.dark_mode = False
            
            # Tüm çerçeveleri güncelle
            self.update_all_frames()
            
        else:
            # Karanlık tema
            self.style.theme_use('clam')
            
            # Ana pencere ve çerçeveler
            self.root.configure(bg="#333333")
            
            # Metin widget'ı
            self.result_text.config(bg="#222222", fg="white", insertbackground="white")
            
            # ttk bileşenleri için stil ayarları
            self.style.configure('TFrame', background="#333333")
            self.style.configure('TLabelframe', background="#333333", foreground="white")
            self.style.configure('TLabelframe.Label', background="#333333", foreground="white")
            self.style.configure('TLabel', background="#333333", foreground="white")
            self.style.configure('TButton', background="#444444", foreground="white")
            self.style.configure('TCheckbutton', background="#333333", foreground="white")
            self.style.configure('TRadiobutton', background="#333333", foreground="white")
            self.style.configure('TEntry', fieldbackground="#222222", foreground="white")
            self.style.configure('TProgressbar', background='#4CAF50', troughcolor='#555555')
            self.style.configure('Header.TLabel', background="#333333", foreground="white", font=('Helvetica', 16, 'bold'))
            self.style.configure('Status.TLabel', background="#333333", foreground="white", font=('Helvetica', 10))
            
            # Stil haritalaması (hover, active, vb. durumlar)
            self.style.map('TButton', 
                         background=[('active', '#555555')],
                         foreground=[('active', 'white')])
            self.style.map('TCheckbutton', 
                         background=[('active', '#333333')],
                         foreground=[('active', 'white')])
            self.style.map('TRadiobutton', 
                         background=[('active', '#333333')],
                         foreground=[('active', 'white')])
            
            self.theme_button.config(text="Açık Mod")
            self.dark_mode = True
            
            # Tüm çerçeveleri güncelle
            self.update_all_frames()
    
    def update_all_frames(self):
        """Tüm çerçeveleri ve alt bileşenleri güncelle"""
        bg_color = "#333333" if self.dark_mode else "#f0f0f0"
        fg_color = "white" if self.dark_mode else "black"
        
        # Tüm çerçeveleri özyinelemeli olarak güncelle
        def update_widgets(parent):
            for widget in parent.winfo_children():
                try:
                    # ttk bileşenler için stil güncelleme
                    if isinstance(widget, (ttk.Frame, ttk.LabelFrame)):
                        if self.dark_mode:
                            widget.configure(style='dark.TFrame' if isinstance(widget, ttk.Frame) else 'dark.TLabelframe')
                        else:
                            widget.configure(style='TFrame' if isinstance(widget, ttk.Frame) else 'TLabelframe')
                        
                        # Alt bileşenleri güncelle
                        update_widgets(widget)
                    # Normal Tkinter widget'ları için doğrudan güncelleme
                    elif isinstance(widget, tk.Frame):
                        widget.configure(bg=bg_color)
                        update_widgets(widget)
                    elif isinstance(widget, tk.Text):
                        bg = "#222222" if self.dark_mode else "white"
                        widget.configure(bg=bg, fg=fg_color, insertbackground=fg_color)
                except:
                    pass
        
        # Ana pencereden başla
        update_widgets(self.root)
        
        # Diğer widget'ların durumlarını güncelle
        if self.dark_mode:
            self.style.configure('TCheckbutton', indicatorbackground="#222222")
            self.style.configure('TRadiobutton', indicatorbackground="#222222")
        else:
            self.style.configure('TCheckbutton', indicatorbackground="white")
            self.style.configure('TRadiobutton', indicatorbackground="white")
        
        # Zorla yeniden çizme
        self.root.update_idletasks()
    
    def toggle_password_visibility(self):
        """Şifre görünürlüğünü aç/kapa"""
        current_show = self.password_entry.cget('show')
        if current_show == '*':
            self.password_entry.config(show='')
            self.show_password_button.config(text="🔒")
        else:
            self.password_entry.config(show='*')
            self.show_password_button.config(text="👁️")
    
    def generate_password(self):
        """Güçlü şifre üret ve şifre alanına yerleştir"""
        password = generate_strong_password(16)
        self.password_var.set(password)
        self.update_status("Güçlü rastgele şifre oluşturuldu!")
    
    def backup_security_data(self, silent=False):
        """Güvenlik yapılandırmasını ve durumunu yedekle"""
        try:
            backup_data = {
                "password_attempts": self.password_attempts,
                "installation_date": time.time(),
                "app_version": "3.0"
            }
            
            # Ana dizinin dışında gizli bir yere yedekle
            app_data_dir = os.path.join(os.environ['APPDATA'], '.munchin_backup')
            if not os.path.exists(app_data_dir):
                os.makedirs(app_data_dir)
                
            # Dosya adını gizle
            backup_file = os.path.join(app_data_dir, 'system_config.dat')
            with open(backup_file, 'wb') as f:
                pickled_data = pickle.dumps(backup_data)
                # Basit bir obfuscation
                f.write(bytes([b ^ 42 for b in pickled_data]))
            
            # Dosya özniteliklerini değiştir (gizli yap)
            subprocess.call(['attrib', '+h', '+s', backup_file])
            
            if not silent:
                self.update_status("Güvenlik verileri başarıyla yedeklendi.", True)
            return True
        except Exception as e:
            if not silent:
                self.update_status(f"Yedekleme hatası: {str(e)}", True)
            return False
    
    def filter_files(self, all_files):
        """Dosyaları uzantılarına göre filtrele"""
        filter_text = self.filter_var.get().strip()
        
        # Filtre boşsa tüm dosyaları döndür
        if not filter_text:
            return all_files
        
        # Filtreleri ayrıştır
        extensions = [ext.strip().lower() for ext in filter_text.split(',')]
        
        # Dosyaları filtrele
        return [file for file in all_files if os.path.splitext(file)[1].lower() in extensions]
    
    def load_password_attempts(self):
        """Şifre deneme sayısını dosyadan ve kayıt defterinden yükle"""
        attempts = 0
        
        # 1. Dosyadan kontrol et
        if os.path.exists(self.attempt_file):
            try:
                with open(self.attempt_file, 'r') as f:
                    attempts = max(attempts, int(f.read().strip()))
            except:
                pass
        
        # 2. Windows kayıt defterinden kontrol et
        try:
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\MunchinProject")
            reg_value, _ = winreg.QueryValueEx(reg_key, "PasswordAttempts")
            attempts = max(attempts, int(reg_value))
            winreg.CloseKey(reg_key)
        except:
            pass
        
        # İkinci gizli kayıt defteri konumu
        try:
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            reg_value, _ = winreg.QueryValueEx(reg_key, "AutoUpdater123")
            hidden_attempts = int(reg_value[::-1])  # Tersine çevrili değer
            attempts = max(attempts, hidden_attempts)
            winreg.CloseKey(reg_key)
        except:
            pass
        
        # 3. Ek gizli dosya kontrolü - farklı bir isimle
        hidden_file = os.path.join(self.script_dir, '.munchin_config')
        if os.path.exists(hidden_file):
            try:
                with open(hidden_file, 'r') as f:
                    content = f.read().strip()
                    # Basit bir obfuscation - son 1 karakter deneme sayısı
                    hidden_attempts = int(content[-1])
                    attempts = max(attempts, hidden_attempts)
            except:
                pass
        
        # 4. AppData klasöründeki yedekten kontrol et
        try:
            backup_file = os.path.join(os.environ['APPDATA'], '.munchin_backup', 'system_config.dat')
            if os.path.exists(backup_file):
                with open(backup_file, 'rb') as f:
                    obfuscated_data = f.read()
                    data = bytes([b ^ 42 for b in obfuscated_data])  # De-obfuscation
                    backup_data = pickle.loads(data)
                    attempts = max(attempts, backup_data.get('password_attempts', 0))
        except:
            pass
        
        return attempts
    
    def save_password_attempts(self):
        """Şifre deneme sayısını dosyaya ve kayıt defterine kaydet"""
        # 1. Normal dosyaya kaydet
        try:
            with open(self.attempt_file, 'w') as f:
                f.write(str(self.password_attempts))
        except:
            pass
        
        # 2. Windows kayıt defterine kaydet
        try:
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\MunchinProject")
            winreg.SetValueEx(reg_key, "PasswordAttempts", 0, winreg.REG_SZ, str(self.password_attempts))
            winreg.CloseKey(reg_key)
            
            # İkinci gizli kayıt defteri konumu (tersine çevrilmiş)
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            winreg.SetValueEx(reg_key, "AutoUpdater123", 0, winreg.REG_SZ, str(self.password_attempts)[::-1])
            winreg.CloseKey(reg_key)
        except:
            pass
        
        # 3. Gizli bir dosyaya daha kaydet
        try:
            hidden_file = os.path.join(self.script_dir, '.munchin_config')
            fake_content = f"config_version=1.0\ntheme=default\nsetting={self.password_attempts}"
            with open(hidden_file, 'w') as f:
                f.write(fake_content)
        except:
            pass
        
        # 4. AppData'ya yedekle
        self.backup_security_data(silent=True)
    
    def reset_password_attempts(self):
        """Şifre deneme sayısını sıfırla"""
        self.password_attempts = 0
        
        # 1. Dosyayı sil veya sıfırla
        if os.path.exists(self.attempt_file):
            try:
                os.remove(self.attempt_file)
            except:
                try:
                    with open(self.attempt_file, 'w') as f:
                        f.write("0")
                except:
                    pass
        
        # 2. Windows kayıt defterindeki değeri sıfırla
        try:
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\MunchinProject")
            winreg.SetValueEx(reg_key, "PasswordAttempts", 0, winreg.REG_SZ, "0")
            winreg.CloseKey(reg_key)
            
            # İkinci gizli kayıt defteri konumu
            reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            winreg.SetValueEx(reg_key, "AutoUpdater123", 0, winreg.REG_SZ, "0"[::-1])  # tersine çevrilmiş
            winreg.CloseKey(reg_key)
        except:
            pass
        
        # 3. Gizli dosyayı güncelle
        try:
            hidden_file = os.path.join(self.script_dir, '.munchin_config')
            fake_content = "config_version=1.0\ntheme=default\nsetting=0"
            with open(hidden_file, 'w') as f:
                f.write(fake_content)
        except:
            pass
        
        # 4. AppData'daki yedeği güncelle
        self.backup_security_data(silent=True)
    
    def show_delete_warning_and_delete(self):
        """Silme uyarısı göster ve sil"""
        messagebox.showerror("Güvenlik İhlali", 
            "Çok fazla yanlış şifre denemesi tespit edildi! Tüm dosyalar kalıcı olarak siliniyor!")
        threading.Thread(target=self.delete_all_files, daemon=True).start()
        
    def browse_directory(self):
        """Dizin seçme diyaloğunu aç"""
        directory = filedialog.askdirectory(initialdir=self.dir_var.get())
        if directory:
            self.dir_var.set(directory)
    
    def update_status(self, message, add_to_result=False):
        """Durum mesajını güncelle"""
        self.status_var.set(message)
        if add_to_result:
            self.result_text.insert(tk.END, message + "\n")
            self.result_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_process(self):
        """İşlemi başlat"""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Uyarı", "Lütfen bir şifre girin.")
            return
        
        # İşlem butonunu devre dışı bırak
        self.process_button.config(state=tk.DISABLED)
        self.backup_button.config(state=tk.DISABLED)
        self.result_text.delete(1.0, tk.END)
        
        # Şifreleme işlemini arka planda başlat
        threading.Thread(target=self.process_files, daemon=True).start()
    
    def process_files(self):
        """Dosya işleme"""
        try:
            # İlerlemeyi sıfırla
            self.progress_var.set(0)
            
            # Kullanıcının seçtiği dizin
            selected_dir = self.dir_var.get()
            
            # Şifreden anahtar üret
            key = generate_key(self.password_var.get())
            
            # İşlem modunu belirle
            mode = self.mode_var.get()
            if mode == "auto":
                # Otomatik algıla
                if os.path.exists(self.status_file):
                    success = self.decrypt_files(key, selected_dir)
                    if not success:
                        self.password_attempt_failed()
                    else:
                        self.reset_password_attempts()  # Başarılı olursa sıfırla
                else:
                    self.encrypt_files(key, selected_dir)
                    self.reset_password_attempts()  # Şifreleme başarılı olursa sıfırla
            elif mode == "encrypt":
                self.encrypt_files(key, selected_dir)
                self.reset_password_attempts()  # Şifreleme başarılı olursa sıfırla
            else:
                success = self.decrypt_files(key, selected_dir)
                if not success:
                    self.password_attempt_failed()
                else:
                    self.reset_password_attempts()  # Başarılı olursa sıfırla
            
        except Exception as e:
            self.update_status(f"Hata: {str(e)}", True)
        finally:
            # İşlem butonunu tekrar aktif et
            self.process_button.config(state=tk.NORMAL)
            self.backup_button.config(state=tk.NORMAL)
    
    def password_attempt_failed(self):
        """Şifre denemesi başarısız olduğunda"""
        self.password_attempts += 1
        self.save_password_attempts()  # Her başarısız denemeden sonra kaydet
        
        remaining = 3 - self.password_attempts
        
        if remaining > 0:
            messagebox.showwarning("Yanlış Şifre", 
                f"Girdiğiniz şifre yanlış! Kalan deneme hakkınız: {remaining}")
        else:
            messagebox.showerror("Güvenlik Uyarısı", 
                "Art arda 3 kez yanlış şifre girdiniz! Tüm dosyalar kalıcı olarak siliniyor!")
            
            # Dosyaları sil
            threading.Thread(target=self.delete_all_files, daemon=True).start()
    
    def delete_all_files(self):
        """Tüm dosyaları geri dönüşümsüz olarak sil - 3 kez yanlış şifre girildiğinde çağrılır"""
        directory = self.dir_var.get()
        
        try:
            self.update_status("Dosyalar kalıcı olarak siliniyor...", True)
            
            # Silinecek dosyaları al
            to_delete = []
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Script dosyasını ve deneme sayısı dosyalarını silme
                    if (file_path != self.script_path and 
                        file_path != self.attempt_file and 
                        not os.path.basename(file_path).startswith('.munchin_config')):
                        to_delete.append(file_path)
            
            total_files = len(to_delete)
            deleted = 0
            
            # Dosyaları güvenli şekilde sil
            for i, file_path in enumerate(to_delete):
                try:
                    # İlerleme çubuğunu güncelle
                    progress = (i / total_files) * 100
                    self.progress_var.set(progress)
                    
                    self.update_status(f"Güvenli olarak siliniyor: {file_path}")
                    
                    # Güvenli silme fonksiyonu veya normal silme
                    if self.secure_delete_var.get():
                        success = secure_delete(file_path)
                    else:
                        os.remove(file_path)
                        success = True
                        
                    if success:
                        deleted += 1
                        self.update_status(f"Kalıcı olarak silindi: {file_path}", True)
                    else:
                        self.update_status(f"Silinme başarısız: {file_path}", True)
                except:
                    self.update_status(f"Silinme başarısız: {file_path}", True)
            
            # İlerleme çubuğunu %100 yap
            self.progress_var.set(100)
            
            # Status file'ı da sil
            if os.path.exists(self.status_file):
                try:
                    secure_delete(self.status_file)
                except:
                    pass
            
            self.update_status(f"İşlem tamamlandı. {deleted}/{total_files} dosya kalıcı olarak silindi.", True)
            
            # Boş alanı temizle (eğer seçiliyse)
            if self.wipe_free_space_var.get():
                self.update_status("Boş disk alanı temizleniyor (bu işlem zaman alabilir)...", True)
                drive = os.path.splitdrive(directory)[0] or directory
                if wipe_free_space(drive):
                    self.update_status("Boş disk alanı temizlendi.", True)
                else:
                    self.update_status("Boş disk alanı temizleme başarısız.", True)
            
            messagebox.showinfo("İşlem Tamamlandı", f"{deleted} dosya güvenli şekilde kalıcı olarak silindi.")
            
            # İşlem tamamlandıktan sonra deneme sayısını sıfırla
            self.reset_password_attempts()
            
        except Exception as e:
            self.update_status(f"Dosya silme işlemi başarısız: {str(e)}", True)
    
    def encrypt_files(self, key, directory):
        """Dizindeki dosyaları şifrele"""
        self.update_status("Şifreleme işlemi başlatılıyor...", True)
        
        # Dosyaları topla
        all_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Script dosyasını, durum dosyasını ve deneme sayısı dosyasını şifreleme
                if (file_path != self.script_path and 
                    not os.path.basename(file_path).startswith('.encrypt_status') and
                    file_path != self.attempt_file and
                    not os.path.basename(file_path).startswith('.munchin_config')):
                    all_files.append(file_path)
        
        # Dosyaları filtrele
        all_files = self.filter_files(all_files)
        
        # İlerleme çubuğu için
        total_files = len(all_files)
        if total_files == 0:
            self.update_status("Şifrelenecek dosya bulunamadı.", True)
            return
        
        # Şifrelenen dosyaların listesi
        encrypted_files = []
        
        # Çoklu işlem kullan?
        if self.multiprocessing_var.get() and total_files > 10:
            self.update_status("Çoklu işlem kullanılarak şifreleniyor...", True)
            
            # İşlemci sayısını al
            num_workers = multiprocessing.cpu_count()
            
            # Dosyaları gruplara böl
            chunks = [all_files[i:i + len(all_files) // num_workers + 1] 
                    for i in range(0, len(all_files), len(all_files) // num_workers + 1)]
            
            progress_count = 0
            
            # Her grup için bir thread başlat
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                future_to_chunk = {executor.submit(self._encrypt_chunk, chunk, key): chunk for chunk in chunks}
                
                for future in concurrent.futures.as_completed(future_to_chunk):
                    chunk_results = future.result()
                    encrypted_files.extend(chunk_results)
                    
                    # İlerleme çubuğunu güncelle
                    progress_count += len(chunk_results)
                    progress = (progress_count / total_files) * 100
                    self.progress_var.set(progress)
                    self.update_status(f"Şifrelendi: {progress_count}/{total_files} dosya")
        else:
            # Normal sıralı işleme
            for i, file_path in enumerate(all_files):
                try:
                    # İlerleme çubuğunu güncelle
                    progress = (i / total_files) * 100
                    self.progress_var.set(progress)
                    
                    self.update_status(f"Şifreleniyor: {file_path}")
                    
                    if encrypt_file(file_path, key):
                        encrypted_files.append(file_path)
                        self.update_status(f"Şifrelendi: {file_path}", True)
                    else:
                        self.update_status(f"Şifreleme başarısız: {file_path}", True)
                except Exception as e:
                    self.update_status(f"Hata ({file_path}): {str(e)}", True)
        
        # İlerleme çubuğunu %100 yap
        self.progress_var.set(100)
        
        # Şifrelenen dosyaların listesini kaydet
        with open(self.status_file, 'wb') as f:
            pickle.dump(encrypted_files, f)
        
        self.update_status(f"İşlem tamamlandı. {len(encrypted_files)} dosya şifrelendi.", True)
    
    def _encrypt_chunk(self, file_list, key):
        """Bir grup dosyayı şifrele (çoklu işlem için)"""
        successful = []
        for file_path in file_list:
            try:
                if encrypt_file(file_path, key):
                    successful.append(file_path)
            except:
                pass
        return successful
    
    def decrypt_files(self, key, directory):
        """Şifreli dosyaların şifresini çöz"""
        self.update_status("Şifre çözme işlemi başlatılıyor...", True)
        
        # Şifreli dosyaların listesini kontrol et
        if not os.path.exists(self.status_file):
            self.update_status("Şifreli dosya bulunamadı. Önce dosyaları şifreleyin.", True)
            return True  # Başarısız giriş sayılmaması için
        
        try:
            # Şifreli dosyaları yükle
            with open(self.status_file, 'rb') as f:
                encrypted_files = pickle.load(f)
            
            # Dosyaları filtrele
            encrypted_files = self.filter_files(encrypted_files)
            
            # İlerleme çubuğu için
            total_files = len(encrypted_files)
            if total_files == 0:
                self.update_status("Çözülecek dosya bulunamadı.", True)
                return True
            
            # İlk dosyayı test et - şifre doğru mu?
            test_file = next((f for f in encrypted_files if os.path.exists(f)), None)
            if test_file:
                try:
                    # Şifreyi test et
                    with open(test_file, 'rb') as f:
                        test_data = f.read()
                    
                    fernet = Fernet(key)
                    fernet.decrypt(test_data)  # Şifre yanlışsa bir hata fırlatır
                except:
                    # Şifre yanlış
                    self.update_status("Şifre çözme başarısız. Yanlış şifre girdiniz.", True)
                    return False
            
            # Çoklu işlem kullan?
            if self.multiprocessing_var.get() and total_files > 10:
                self.update_status("Çoklu işlem kullanılarak çözülüyor...", True)
                
                # İşlemci sayısını al
                num_workers = multiprocessing.cpu_count()
                
                # Dosyaları gruplara böl
                chunks = [encrypted_files[i:i + len(encrypted_files) // num_workers + 1] 
                        for i in range(0, len(encrypted_files), len(encrypted_files) // num_workers + 1)]
                
                successful = 0
                
                # Her grup için bir thread başlat
                with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                    future_to_chunk = {executor.submit(self._decrypt_chunk, chunk, key): chunk for chunk in chunks}
                    
                    for future in concurrent.futures.as_completed(future_to_chunk):
                        chunk_results = future.result()
                        successful += len(chunk_results)
                        
                        # İlerleme çubuğunu güncelle
                        progress = (successful / total_files) * 100
                        self.progress_var.set(progress)
                        self.update_status(f"Çözüldü: {successful}/{total_files} dosya")
            else:
                # Normal sıralı işleme
                successful = 0
                for i, file_path in enumerate(encrypted_files):
                    # İlerleme çubuğunu güncelle
                    progress = (i / total_files) * 100
                    self.progress_var.set(progress)
                    
                    if os.path.exists(file_path) and file_path != self.script_path:
                        self.update_status(f"Şifre çözülüyor: {file_path}")
                        
                        if decrypt_file(file_path, key):
                            successful += 1
                            self.update_status(f"Çözüldü: {file_path}", True)
                        else:
                            self.update_status(f"Çözülme başarısız: {file_path}", True)
            
            # İlerleme çubuğunu %100 yap
            self.progress_var.set(100)
            
            # Temizleme
            os.remove(self.status_file)
            
            self.update_status(f"İşlem tamamlandı. {successful}/{total_files} dosya çözüldü.", True)
            return True
            
        except Exception as e:
            self.update_status(f"Şifre çözme başarısız. Yanlış şifre veya hasar görmüş dosyalar: {str(e)}", True)
            return False
    
    def _decrypt_chunk(self, file_list, key):
        """Bir grup dosyanın şifresini çöz (çoklu işlem için)"""
        successful = []
        for file_path in file_list:
            try:
                if os.path.exists(file_path) and file_path != self.script_path:
                    if decrypt_file(file_path, key):
                        successful.append(file_path)
            except:
                pass
        return successful

if __name__ == "__main__":
    try:
        # Gerekli modülleri kontrol et ve yükle
        required_modules = {"pillow": "PIL", "pystray": "pystray", "matplotlib": "matplotlib", 
                           "cryptography": "cryptography", "numpy": "numpy"}
        
        missing_modules = []
        for pip_name, import_name in required_modules.items():
            try:
                __import__(import_name)
            except ImportError:
                missing_modules.append(pip_name)
        
        # Eksik modüller varsa yükleme öner
        if missing_modules:
            print(f"Uyarı: Bazı gerekli modüller eksik: {', '.join(missing_modules)}")
            print(f"Yüklemek için: pip install {' '.join(missing_modules)}")
            
            # Basit bir GUI ile bildir
            root = tk.Tk()
            root.withdraw()
            if messagebox.askyesno("Eksik Modüller", 
                                  f"Bazı gerekli modüller eksik: {', '.join(missing_modules)}\n\n" +
                                  f"Programın tam çalışması için bu modüllerin yüklenmesi gerekiyor.\n" +
                                  f"Şimdi yüklemek ister misiniz?"):
                try:
                    import subprocess
                    subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_modules)
                    messagebox.showinfo("Başarılı", "Modüller başarıyla yüklendi. Program yeniden başlatılıyor.")
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                except Exception as e:
                    messagebox.showerror("Hata", f"Modüller yüklenirken hata oluştu: {str(e)}")
            root.destroy()
        
        # Ana uygulamayı başlat
        root = tk.Tk()
        app = CryptoApp(root)
        root.mainloop()
        
    except Exception as e:
        print(f"Kritik hata: {str(e)}")
        # Basit bir hata mesajı göster
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Hata", f"Program başlatılırken bir hata oluştu:\n\n{str(e)}")
            root.destroy()
        except:
            pass