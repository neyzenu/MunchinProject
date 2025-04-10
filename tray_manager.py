import os
import threading
import tkinter as tk
from PIL import Image, ImageDraw

class TrayManager:
    """Sistem tepsisi entegrasyonu için sınıf"""
    
    def __init__(self, app, root):
        self.app = app
        self.root = root
        self.tray_icon = None
        self.icon_path = None
        self.minimized_to_tray = False
        
        # Gerekli kütüphaneyi import et
        try:
            import pystray
            self.pystray = pystray
            self.pystray_available = True
        except ImportError:
            self.pystray_available = False
        
        # Tepsi simgesi hazırla
        if self.pystray_available:
            self.setup_tray_icon()
            
        # Pencere kapatma olayını yakala
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def setup_tray_icon(self):
        """Tepsi simgesini hazırla"""
        # Geçici simge oluştur
        icon_image = self.create_icon_image()
        
        # Menü oluştur
        menu = self.pystray.Menu(
            self.pystray.MenuItem('Göster', self.show_window),
            self.pystray.MenuItem('Sistem Tepsisine Küçült', self.minimize_to_tray),
            self.pystray.MenuItem('Hızlı Şifreleme...', self.quick_encrypt),
            self.pystray.MenuItem('Hızlı Çözme...', self.quick_decrypt),
            self.pystray.MenuItem('Çıkış', self.exit_app)
        )
        
        # Tepsi simgesi oluştur
        self.tray_icon = self.pystray.Icon("MunchinProject", icon_image, "MunchinProject - Çalışıyor", menu)
    
    def create_icon_image(self, size=64):
        """Uygulama için bir simge oluştur"""
        # Geçici basit simge oluştur
        image = Image.new('RGB', (size, size), color=(53, 150, 255))
        dc = ImageDraw.Draw(image)
        dc.rectangle([size // 4, size // 4, size * 3 // 4, size * 3 // 4], fill=(255, 255, 255))
        dc.text((size//4, size//4), "MC", fill=(0, 0, 0))
        
        # Özel simge dosyası varsa kullan
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
        if os.path.exists(icon_path):
            try:
                image = Image.open(icon_path)
                image = image.resize((size, size))
                self.icon_path = icon_path
            except:
                pass
        
        return image
    
    def start_tray(self):
        """Tepsi simgesini başlat"""
        if self.pystray_available and self.tray_icon:
            try:
                threading.Thread(target=self.tray_icon.run, daemon=True).start()
                return True
            except Exception as e:
                print(f"Tepsi simgesi başlatılamadı: {str(e)}")
                return False
        return False
    
    def show_window(self, icon=None, item=None):
        """Pencereyi göster"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.minimized_to_tray = False
    
    def minimize_to_tray(self, icon=None, item=None):
        """Pencereyi sistem tepsisine küçült"""
        self.root.withdraw()
        self.minimized_to_tray = True
    
    def quick_encrypt(self, icon=None, item=None):
        """Sistem tepsisinden hızlı şifreleme"""
        self.show_window()
        # Şifreleme ekranını göster ve otomatik ayarla
        self.app.mode_var.set("encrypt")
        # Dosya seçme diyalogu göster
        self.app.browse_directory()
    
    def quick_decrypt(self, icon=None, item=None):
        """Sistem tepsisinden hızlı çözme"""
        self.show_window()
        # Çözme ekranını göster ve otomatik ayarla
        self.app.mode_var.set("decrypt")
        # Dosya seçme diyalogu göster
        self.app.browse_directory()
    
    def exit_app(self, icon=None, item=None):
        """Uygulamadan çık"""
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.destroy()
    
    def on_close(self):
        """Pencere kapatılırken tepsi simgesine küçültme veya çıkış"""
        if not self.pystray_available:
            self.root.destroy()
            return
            
        # Kullanıcı tercihini sor
        import tkinter.messagebox as messagebox
        answer = messagebox.askyesnocancel(
            "MunchinProject", 
            "Ne yapmak istersiniz?",
            detail="Evet: Sistem tepsisine küçült\nHayır: Uygulamadan çık\nİptal: İşlemi iptal et"
        )
        
        if answer is None:  # İptal
            return
        elif answer:  # Evet
            self.minimize_to_tray()
        else:  # Hayır
            self.exit_app()