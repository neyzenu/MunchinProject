import os
import time
import datetime
import threading
import pickle
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class TaskScheduler:
    """Planlı görevler ve otomatizasyon için sınıf"""
    
    def __init__(self, app, root):
        self.app = app
        self.root = root
        self.tasks = []
        self.task_threads = []
        self.task_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".scheduled_tasks")
        
        # Görevleri yükle
        self.load_tasks()
        
        # Kaydedilen görevleri başlat
        self.start_saved_tasks()
    
    def create_scheduler_tab(self, notebook):
        """Görev planlayıcı sekmesi oluştur"""
        scheduler_frame = ttk.Frame(notebook)
        notebook.add(scheduler_frame, text="Görev Planlayıcı")
        
        # Planlı görevler listesi
        task_list_frame = ttk.LabelFrame(scheduler_frame, text="Planlı Görevler")
        task_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tablo görünümü
        columns = ('id', 'task_type', 'directory', 'schedule', 'status')
        self.task_tree = ttk.Treeview(task_list_frame, columns=columns, show='headings')
        
        # Kolon başlıkları
        self.task_tree.heading('id', text='#')
        self.task_tree.heading('task_type', text='Görev Tipi')
        self.task_tree.heading('directory', text='Dizin')
        self.task_tree.heading('schedule', text='Zaman')
        self.task_tree.heading('status', text='Durum')
        
        # Kolon genişlikleri
        self.task_tree.column('id', width=30)
        self.task_tree.column('task_type', width=100)
        self.task_tree.column('directory', width=200)
        self.task_tree.column('schedule', width=150)
        self.task_tree.column('status', width=70)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(task_list_frame, orient=tk.VERTICAL, command=self.task_tree.yview)
        self.task_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.task_tree.pack(fill=tk.BOTH, expand=True)
        
        # Yeni görev ekleme formu
        new_task_frame = ttk.LabelFrame(scheduler_frame, text="Yeni Görev Ekle")
        new_task_frame.pack(fill=tk.X, expand=False, padx=10, pady=5)
        
        # Görev tipi seçimi
        task_type_frame = ttk.Frame(new_task_frame)
        task_type_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(task_type_frame, text="Görev Tipi:").pack(side=tk.LEFT, padx=5)
        task_type_var = tk.StringVar(value="encrypt")
        task_type_combo = ttk.Combobox(task_type_frame, textvariable=task_type_var, 
                                      values=("encrypt", "decrypt", "delete"), state="readonly", width=15)
        task_type_combo.pack(side=tk.LEFT, padx=5)
        
        # Dizin seçimi
        dir_frame = ttk.Frame(new_task_frame)
        dir_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dir_frame, text="Dizin:").pack(side=tk.LEFT, padx=5)
        dir_var = tk.StringVar()
        dir_entry = ttk.Entry(dir_frame, textvariable=dir_var, width=40)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Düzeltme: Browse button now uses filedialog directly
        browse_button = ttk.Button(dir_frame, text="Gözat", 
                                  command=lambda: dir_var.set(filedialog.askdirectory()))
        browse_button.pack(side=tk.RIGHT, padx=5)
        
        # Şifre ayarı
        password_frame = ttk.Frame(new_task_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Şifre:").pack(side=tk.LEFT, padx=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="*")
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Zaman seçimi
        time_frame = ttk.Frame(new_task_frame)
        time_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(time_frame, text="Zaman:").pack(side=tk.LEFT, padx=5)
        
        date_var = tk.StringVar(value=datetime.date.today().strftime("%Y-%m-%d"))
        date_entry = ttk.Entry(time_frame, textvariable=date_var, width=12)
        date_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(time_frame, text="Saat:").pack(side=tk.LEFT, padx=5)
        
        hour_var = tk.StringVar(value=datetime.datetime.now().strftime("%H"))
        hour_spin = ttk.Spinbox(time_frame, from_=0, to=23, width=3, textvariable=hour_var, format="%02.0f")
        hour_spin.pack(side=tk.LEFT)
        
        ttk.Label(time_frame, text=":").pack(side=tk.LEFT)
        
        minute_var = tk.StringVar(value=datetime.datetime.now().strftime("%M"))
        minute_spin = ttk.Spinbox(time_frame, from_=0, to=59, width=3, textvariable=minute_var, format="%02.0f")
        minute_spin.pack(side=tk.LEFT)
        
        # Butonlar
        button_frame = ttk.Frame(new_task_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        add_button = ttk.Button(button_frame, text="Görev Ekle", 
                               command=lambda: self.add_task(
                                   task_type_var.get(),
                                   dir_var.get(),
                                   password_var.get(),
                                   date_var.get(),
                                   hour_var.get(),
                                   minute_var.get()
                               ))
        add_button.pack(side=tk.LEFT, padx=5)
        
        remove_button = ttk.Button(button_frame, text="Seçilen Görevi Kaldır", 
                                  command=self.remove_selected_task)
        remove_button.pack(side=tk.LEFT, padx=5)
        
        # Var olan görevleri göster
        self.refresh_task_list()
        
        return scheduler_frame
    
    def refresh_task_list(self):
        """Görev listesini güncelle"""
        # Listeyi temizle
        for item in self.task_tree.get_children():
            self.task_tree.delete(item)
        
        # Görevleri ekle
        for i, task in enumerate(self.tasks):
            status = "Aktif" if task.get('active', True) else "Pasif"
            
            # Zamanı formatla
            schedule_time = time.localtime(task.get('schedule_time', 0))
            schedule_str = time.strftime("%Y-%m-%d %H:%M", schedule_time)
            
            self.task_tree.insert('', tk.END, values=(
                i+1,
                task.get('task_type', 'N/A'),
                task.get('directory', 'N/A'),
                schedule_str,
                status
            ))
    
    def add_task(self, task_type, directory, password, date_str, hour_str, minute_str):
        """Yeni görev ekle"""
        # Parametreleri kontrol et
        if not directory or not password:
            messagebox.showerror("Hata", "Dizin ve şifre boş olamaz!")
            return
        
        try:
            # Zamanı kontrol et ve dönüştür
            year, month, day = map(int, date_str.split('-'))
            hour = int(hour_str)
            minute = int(minute_str)
            
            task_time = datetime.datetime(year, month, day, hour, minute).timestamp()
            
            # Geçmiş zaman kontrolü
            if task_time <= time.time():
                messagebox.showerror("Hata", "Görev zamanı geçmiş veya şu anki zamandan önce olamaz!")
                return
            
            # Görev bilgilerini hazırla
            task = {
                'task_type': task_type,
                'directory': directory,
                'password': password,
                'schedule_time': task_time,
                'created_at': time.time(),
                'active': True
            }
            
            # Görevi ekle ve kaydet
            self.tasks.append(task)
            self.save_tasks()
            
            # Görevi başlat
            self.schedule_task(task)
            
            # Listeyi güncelle
            self.refresh_task_list()
            
            messagebox.showinfo("Başarılı", "Görev başarıyla planlandı.")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Görev eklenirken bir hata oluştu: {str(e)}")
    
    def remove_selected_task(self):
        """Seçilen görevi kaldır"""
        selected = self.task_tree.selection()
        if not selected:
            messagebox.showwarning("Uyarı", "Lütfen bir görev seçin.")
            return
        
        try:
            # Seçilen görevin indeksini al
            item = self.task_tree.item(selected[0])
            index = int(item['values'][0]) - 1
            
            # Görev var mı kontrol et
            if 0 <= index < len(self.tasks):
                # Görevi kaldır
                del self.tasks[index]
                self.save_tasks()
                
                # Listeyi güncelle
                self.refresh_task_list()
                
                messagebox.showinfo("Başarılı", "Görev başarıyla kaldırıldı.")
            else:
                messagebox.showerror("Hata", "Geçersiz görev indeksi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Görev kaldırılırken bir hata oluştu: {str(e)}")
    
    def save_tasks(self):
        """Görevleri dosyaya kaydet"""
        try:
            with open(self.task_file, 'wb') as f:
                pickle.dump(self.tasks, f)
        except Exception as e:
            print(f"Görevler kaydedilirken hata: {str(e)}")
    
    def load_tasks(self):
        """Görevleri dosyadan yükle"""
        try:
            if os.path.exists(self.task_file):
                with open(self.task_file, 'rb') as f:
                    self.tasks = pickle.load(f)
        except Exception as e:
            print(f"Görevler yüklenirken hata: {str(e)}")
            self.tasks = []
    
    def start_saved_tasks(self):
        """Kaydedilmiş görevleri başlat"""
        for task in self.tasks[:]:  # Kopyasını döngüye sok (silme olabilir)
            # Geçmiş görevleri kontrol et
            if task.get('schedule_time', 0) <= time.time():
                # Görev zamanı geçmişse ve tek seferlik ise kaldır
                self.tasks.remove(task)
            else:
                # Değilse görevi planla
                self.schedule_task(task)
        
        # Değişiklikler varsa kaydet
        self.save_tasks()
    
    def schedule_task(self, task):
        """Bir görevi planla"""
        task_type = task.get('task_type')
        directory = task.get('directory')
        password = task.get('password')
        schedule_time = task.get('schedule_time')
        
        # Zamanı hesapla
        now = time.time()
        delay = max(0, schedule_time - now)
        
        # İş parçacığı oluştur
        task_thread = threading.Timer(
            delay,
            self.execute_task,
            args=[task]
        )
        task_thread.daemon = True
        task_thread.start()
        
        # İş parçacığını kaydet
        self.task_threads.append(task_thread)
    
    def execute_task(self, task):
        """Planlı görevi yürüt"""
        task_type = task.get('task_type')
        directory = task.get('directory')
        password = task.get('password')
        
        try:
            # Dinamik import kullanarak dairesel bağımlılıktan kaçınma
            import importlib
            grant_module = importlib.import_module('grant')
            
            # Görev tipi ne?
            if task_type == "encrypt":
                # Şifreleme işlemi
                key = grant_module.generate_key(password)
                
                # Dizindeki tüm dosyaları bul
                all_files = []
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        all_files.append(file_path)
                
                # Şifreleme işlemini gerçekleştir
                for file_path in all_files:
                    try:
                        grant_module.encrypt_file(file_path, key)
                    except:
                        pass
                
            elif task_type == "decrypt":
                # Şifre çözme işlemi
                key = grant_module.generate_key(password)
                
                # Dizindeki tüm dosyaları bul
                all_files = []
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        all_files.append(file_path)
                
                # Şifre çözme işlemini gerçekleştir
                for file_path in all_files:
                    try:
                        grant_module.decrypt_file(file_path, key)
                    except:
                        pass
                
            elif task_type == "delete":
                # Silme işlemi
                # Dizindeki tüm dosyaları bul
                all_files = []
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        all_files.append(file_path)
                
                # Silme işlemini gerçekleştir
                for file_path in all_files:
                    try:
                        grant_module.secure_delete(file_path)
                    except:
                        pass
                        
            # Görev tamamlandı, güncel listeyi göster (UI thread'inde)
            if self.root:
                self.root.after(0, self.task_completed_notification, task)
        
        except Exception as e:
            print(f"Görev yürütülürken hata: {str(e)}")
    
    def task_completed_notification(self, task):
        """Görev tamamlandığında bildirim göster"""
        # Görevi listeden kaldır
        if task in self.tasks:
            self.tasks.remove(task)
            self.save_tasks()
            self.refresh_task_list()
        
        # Bildirim göster
        task_type = task.get('task_type', '')
        directory = task.get('directory', '')
        
        task_types = {
            'encrypt': 'Şifreleme',
            'decrypt': 'Şifre çözme',
            'delete': 'Silme'
        }
        
        message = f"{task_types.get(task_type, task_type)} görevi tamamlandı.\nDizin: {directory}"
        messagebox.showinfo("Görev Tamamlandı", message)