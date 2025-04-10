import os
import numpy as np
from PIL import Image
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class Steganography:
    """Steganografi işlemleri için sınıf"""
    
    def __init__(self, app, root):
        self.app = app
        self.root = root
    
    def create_steganography_tab(self, notebook):
        """Steganografi sekmesi oluştur"""
        steg_frame = ttk.Frame(notebook)
        notebook.add(steg_frame, text="Steganografi")
        
        # Başlık
        header = ttk.Label(steg_frame, text="Görüntülerde Veri Gizleme", style='Header.TLabel')
        header.pack(pady=10)
        
        # İşlem tipi
        mode_frame = ttk.LabelFrame(steg_frame, text="İşlem Modu")
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        mode_var = tk.StringVar(value="hide")
        hide_radio = ttk.Radiobutton(mode_frame, text="Veri Gizle", variable=mode_var, value="hide")
        extract_radio = ttk.Radiobutton(mode_frame, text="Veri Çıkar", variable=mode_var, value="extract")
        
        hide_radio.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        extract_radio.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Görüntü seçimi
        image_frame = ttk.Frame(steg_frame)
        image_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(image_frame, text="Görüntü:").pack(anchor=tk.W)
        
        image_select_frame = ttk.Frame(image_frame)
        image_select_frame.pack(fill=tk.X, pady=5)
        
        image_var = tk.StringVar()
        image_entry = ttk.Entry(image_select_frame, textvariable=image_var, width=40)
        image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_img_button = ttk.Button(image_select_frame, text="Gözat", 
                                      command=lambda: self.browse_image(image_var))
        browse_img_button.pack(side=tk.RIGHT, padx=5)
        
        # Veri girişi (gizleme için)
        data_frame = ttk.LabelFrame(steg_frame, text="Gizlenecek/Çıkarılacak Veri")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Metin veya dosya seçimi için radyo butonlar
        data_type_var = tk.StringVar(value="text")
        text_radio = ttk.Radiobutton(data_frame, text="Metin Gizle", variable=data_type_var, value="text",
                                   command=lambda: self.toggle_data_input("text", text_area, file_frame))
        file_radio = ttk.Radiobutton(data_frame, text="Dosya Gizle", variable=data_type_var, value="file",
                                   command=lambda: self.toggle_data_input("file", text_area, file_frame))
        
        text_radio.pack(anchor=tk.W, padx=5, pady=2)
        file_radio.pack(anchor=tk.W, padx=5, pady=2)
        
        # Metin girişi
        text_area = tk.Text(data_frame, height=6, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Dosya seçimi
        file_frame = ttk.Frame(data_frame)
        
        file_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=file_var, width=40)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_file_button = ttk.Button(file_frame, text="Dosya Seç", 
                                      command=lambda: self.browse_file(file_var))
        browse_file_button.pack(side=tk.RIGHT, padx=5)
        
        # Başlangıçta dosya seçimi gizli
        file_frame.pack_forget()
        
        # Çıktı ayarları
        output_frame = ttk.LabelFrame(steg_frame, text="Çıktı Ayarları")
        output_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(output_frame, text="Çıktı Dosyası:").pack(anchor=tk.W)
        
        output_select_frame = ttk.Frame(output_frame)
        output_select_frame.pack(fill=tk.X, pady=5)
        
        output_var = tk.StringVar()
        output_entry = ttk.Entry(output_select_frame, textvariable=output_var, width=40)
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_output_button = ttk.Button(output_select_frame, text="Kaydet", 
                                        command=lambda: self.browse_output(output_var, mode_var.get()))
        browse_output_button.pack(side=tk.RIGHT, padx=5)
        
        # Şifreleme seçeneği
        encrypt_var = tk.BooleanVar(value=True)
        encrypt_check = ttk.Checkbutton(output_frame, text="Gizlenen veriyi şifrele", variable=encrypt_var)
        encrypt_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Şifre girişi
        password_frame = ttk.Frame(output_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Şifre:").pack(side=tk.LEFT, padx=5)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="*", width=20)
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # İşlem butonu
        button_frame = ttk.Frame(steg_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        process_button = ttk.Button(button_frame, text="İşlemi Başlat", 
                                   command=lambda: self.process_steganography(
                                       mode_var.get(),
                                       image_var.get(),
                                       text_area.get("1.0", tk.END),
                                       file_var.get(),
                                       output_var.get(),
                                       password_var.get(),
                                       encrypt_var.get(),
                                       data_type_var.get()
                                   ))
        process_button.pack(side=tk.LEFT, padx=10)
        
        # Durum çubuğu
        status_var = tk.StringVar(value="Hazır")
        status_label = ttk.Label(steg_frame, textvariable=status_var, style='Status.TLabel')
        status_label.pack(anchor=tk.W, pady=5, padx=10)
        
        # Durum değişkeni kaydet
        self.status_var = status_var
        
        return steg_frame
    
    def toggle_data_input(self, data_type, text_area, file_frame):
        """Veri giriş tipini değiştir"""
        if data_type == "text":
            file_frame.pack_forget()
            text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            text_area.pack_forget()
            file_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def browse_image(self, var):
        """Görüntü dosyası seç"""
        filetypes = [
            ("Görüntü Dosyaları", "*.png *.jpg *.jpeg *.bmp *.gif"),
            ("Tüm Dosyalar", "*.*")
        ]
        filename = filedialog.askopenfilename(title="Görüntü Seç", filetypes=filetypes)
        if filename:
            var.set(filename)
    
    def browse_file(self, var):
        """Gizlenecek dosya seç"""
        filename = filedialog.askopenfilename(title="Gizlenecek Dosya Seç")
        if filename:
            var.set(filename)
    
    def browse_output(self, var, mode):
        """Çıktı dosyası seç"""
        if mode == "hide":
            filetypes = [("PNG Dosyası", "*.png"), ("Tüm Dosyalar", "*.*")]
            filename = filedialog.asksaveasfilename(title="Çıktı Dosyasını Kaydet", 
                                                  defaultextension=".png", filetypes=filetypes)
            if filename:
                var.set(filename)
        else:
            # Çıkarma modunda, çıkarılacak verinin kaydedileceği dizin veya dosya
            filename = filedialog.asksaveasfilename(title="Çıkarılan Veriyi Kaydet")
            if filename:
                var.set(filename)
    
    def process_steganography(self, mode, image_path, text_data, file_path, 
                             output_path, password, encrypt, data_type):
        """Steganografi işlemini gerçekleştir"""
        # Gerekli girdi kontrolü
        if not image_path:
            messagebox.showerror("Hata", "Lütfen bir görüntü dosyası seçin!")
            return
        
        if not os.path.exists(image_path):
            messagebox.showerror("Hata", "Seçilen görüntü dosyası bulunamadı!")
            return
        
        if mode == "hide":
            # Gizleme modu
            if data_type == "text":
                if not text_data.strip():
                    messagebox.showerror("Hata", "Gizlenecek metin boş olamaz!")
                    return
                data = text_data.encode('utf-8')
            else:
                if not file_path or not os.path.exists(file_path):
                    messagebox.showerror("Hata", "Gizlenecek dosya bulunamadı!")
                    return
                with open(file_path, 'rb') as f:
                    data = f.read()
            
            if not output_path:
                messagebox.showerror("Hata", "Lütfen çıktı dosyası için bir konum belirleyin!")
                return
            
            # Veriyi şifrele (isteğe bağlı)
            if encrypt and password:
                from cryptography.fernet import Fernet
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                import base64
                
                # Şifre anahtarı oluştur
                salt = b'salt_'
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                
                # Veriyi şifrele
                data = fernet.encrypt(data)
            
            # Veri tipi bilgisini ekle (çıkartma için)
            header = b'txt:' if data_type == "text" else b'bin:'
            data = header + data
            
            # Steganografi işlemi
            try:
                result = self.hide_data_in_image(image_path, data, output_path)
                if result:
                    messagebox.showinfo("Başarılı", "Veri başarıyla görüntüye gizlendi!")
                    self.status_var.set(f"Veri başarıyla {output_path} dosyasına gizlendi.")
                else:
                    messagebox.showerror("Hata", "Veri gizleme işlemi başarısız oldu!")
            except Exception as e:
                messagebox.showerror("Hata", f"İşlem sırasında bir hata oluştu: {str(e)}")
        
        else:
            # Çıkarma modu
            if not output_path:
                messagebox.showerror("Hata", "Lütfen çıkarılan veri için bir kaydetme konumu belirleyin!")
                return
            
            try:
                # Steganografi ile veri çıkarma
                extracted_data = self.extract_data_from_image(image_path)
                
                if not extracted_data:
                    messagebox.showerror("Hata", "Görüntüden veri çıkarılamadı!")
                    return
                
                # Veri tipi kontrolü
                if extracted_data.startswith(b'txt:'):
                    data_type_extracted = "text"
                    extracted_data = extracted_data[4:]  # Başlık bilgisini kaldır
                elif extracted_data.startswith(b'bin:'):
                    data_type_extracted = "binary"
                    extracted_data = extracted_data[4:]  # Başlık bilgisini kaldır
                else:
                    data_type_extracted = "unknown"
                
                # Veri şifrelenmiş mi?
                if encrypt and password:
                    try:
                        from cryptography.fernet import Fernet
                        from cryptography.hazmat.primitives import hashes
                        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                        import base64
                        
                        # Şifre anahtarı oluştur
                        salt = b'salt_'
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                        fernet = Fernet(key)
                        
                        # Veriyi çöz
                        extracted_data = fernet.decrypt(extracted_data)
                    except Exception as e:
                        messagebox.showerror("Şifre Çözme Hatası", 
                                          "Veri şifreli ve şifre çözme başarısız oldu. Doğru şifreyi girdiğinizden emin olun.")
                        return
                
                # Veri kaydetme
                if data_type_extracted == "text":
                    try:
                        text_data = extracted_data.decode('utf-8')
                        with open(output_path, 'w', encoding='utf-8') as f:
                            f.write(text_data)
                    except UnicodeDecodeError:
                        # UTF-8 ile çözülemiyorsa binary olarak kaydet
                        with open(output_path, 'wb') as f:
                            f.write(extracted_data)
                else:
                    with open(output_path, 'wb') as f:
                        f.write(extracted_data)
                
                messagebox.showinfo("Başarılı", "Veri başarıyla çıkarıldı ve kaydedildi!")
                self.status_var.set(f"Veri başarıyla {output_path} dosyasına çıkarıldı.")
                
            except Exception as e:
                messagebox.showerror("Hata", f"İşlem sırasında bir hata oluştu: {str(e)}")
    
    def hide_data_in_image(self, image_path, data, output_path):
        """Veriyi bir görüntü dosyasında gizler"""
        # Görüntüyü aç
        img = Image.open(image_path)
        width, height = img.size
        
        # RGB moduna dönüştür (PNG dosyaları için gerekli olabilir)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Görüntüyü piksel dizisine dönüştür
        pixels = np.array(img)
        
        # Veriyi ikili biçime dönüştür
        binary_data = ''
        for byte in data:
            binary_data += format(byte, '08b')
        
        # Gizleme için alan kontrolü
        max_bytes = (width * height * 3) // 8
        data_size_bytes = len(data) + 4  # 4 ekstra byte uzunluk bilgisi için
        if data_size_bytes > max_bytes:
            messagebox.showerror("Hata", 
                              f"Veri boyutu çok büyük! En fazla {max_bytes} byte gizleyebilirsiniz.")
            return False
        
        # Veri uzunluğunu başa ekle (4 byte, 32 bit)
        data_len = len(data)
        binary_data_len = format(data_len, '032b')
        binary_data = binary_data_len + binary_data
        
        data_index = 0
        # Her pikselin en az önemli bitini değiştir
        for i in range(height):
            for j in range(width):
                for k in range(3):  # RGB
                    if data_index < len(binary_data):
                        # DÜZELTME: Güvenli piksel manipülasyonu
                        if int(binary_data[data_index]) == 0:
                            # LSB'yi 0 yapmak için çift sayıya çevir
                            pixels[i, j, k] = pixels[i, j, k] & 254  # 254 = 0b11111110
                        else:
                            # LSB'yi 1 yapmak için tek sayıya çevir
                            pixels[i, j, k] = pixels[i, j, k] | 1
                        data_index += 1
                    else:
                        break
                if data_index >= len(binary_data):
                    break
            if data_index >= len(binary_data):
                break
        
        # Değiştirilmiş görüntüyü kaydet
        output_img = Image.fromarray(pixels)
        output_img.save(output_path)
        return True
    
    def extract_data_from_image(self, image_path):
        """Bir görüntüden gizlenmiş veriyi çıkarır"""
        # Görüntüyü aç
        img = Image.open(image_path)
        width, height = img.size
        
        # RGB moduna dönüştür (PNG dosyaları için gerekli olabilir)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Görüntüyü piksel dizisine dönüştür
        pixels = np.array(img)
        
        # Önce veri uzunluğunu çıkar (ilk 32 bit)
        binary_data_len = ''
        data_index = 0
        
        for i in range(height):
            for j in range(width):
                for k in range(3):  # RGB
                    if data_index < 32:
                        # Pikselin LSB'sini oku
                        binary_data_len += str(pixels[i, j, k] & 1)
                        data_index += 1
                    else:
                        break
                if data_index >= 32:
                    break
            if data_index >= 32:
                break
        
        # Veri uzunluğunu hesapla
        data_len = int(binary_data_len, 2)
        
        # Şimdi veriyi çıkar
        binary_data = ''
        data_index = 0
        bits_read = 0
        total_bits = data_len * 8
        
        for i in range(height):
            for j in range(width):
                for k in range(3):  # RGB
                    if data_index < 32:
                        # Zaten okunan uzunluk biti, atla
                        data_index += 1
                        continue
                    elif bits_read < total_bits:
                        # Pikselin LSB'sini oku
                        binary_data += str(pixels[i, j, k] & 1)
                        bits_read += 1
                    else:
                        break
                if bits_read >= total_bits:
                    break
            if bits_read >= total_bits:
                break
        
        # Binary string'i byte dizisine dönüştür
        byte_data = bytearray()
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                byte_data.append(int(byte, 2))
        
        return bytes(byte_data)