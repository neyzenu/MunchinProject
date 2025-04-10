import os
import datetime
import collections
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class FileAnalyzer:
    """Akıllı dosya analizi ve raporlama için sınıf"""
    
    def __init__(self, app, root):
        self.app = app
        self.root = root
        self.analysis_results = {}
        self.current_directory = ""
    
    def create_analyzer_tab(self, notebook):
        """Dosya analizi sekmesi oluştur"""
        analyzer_frame = ttk.Frame(notebook)
        notebook.add(analyzer_frame, text="Dosya Analizi")
        
        # Başlık
        header = ttk.Label(analyzer_frame, text="Dosya Analizi ve Raporlama", style='Header.TLabel')
        header.pack(pady=10)
        
        # Dizin seçimi
        dir_frame = ttk.Frame(analyzer_frame)
        dir_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dir_frame, text="Analiz Edilecek Dizin:").pack(side=tk.LEFT)
        
        dir_var = tk.StringVar()
        dir_entry = ttk.Entry(dir_frame, textvariable=dir_var, width=50)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        browse_button = ttk.Button(dir_frame, text="Gözat", 
                                  command=lambda: self.browse_directory(dir_var))
        browse_button.pack(side=tk.RIGHT)
        
        # Analiz seçenekleri
        options_frame = ttk.LabelFrame(analyzer_frame, text="Analiz Seçenekleri")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Dosya türleri
        file_type_var = tk.BooleanVar(value=True)
        file_type_check = ttk.Checkbutton(options_frame, text="Dosya Türü Dağılımı", variable=file_type_var)
        file_type_check.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        
        # Boyut analizi
        size_var = tk.BooleanVar(value=True)
        size_check = ttk.Checkbutton(options_frame, text="Boyut Analizi", variable=size_var)
        size_check.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Değişim tarihi analizi
        date_var = tk.BooleanVar(value=True)
        date_check = ttk.Checkbutton(options_frame, text="Tarih Analizi", variable=date_var)
        date_check.grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        
        # Derinlik analizi (alt klasörler)
        depth_var = tk.BooleanVar(value=True)
        depth_check = ttk.Checkbutton(options_frame, text="Dizin Derinliği Analizi", variable=depth_var)
        depth_check.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Analiz butonu
        analyze_button = ttk.Button(analyzer_frame, text="Analiz Et", 
                                   command=lambda: self.analyze_directory(dir_var.get(), 
                                                                        file_type_var.get(),
                                                                        size_var.get(),
                                                                        date_var.get(),
                                                                        depth_var.get()))
        analyze_button.pack(pady=10)
        
        # Sonuç alanı
        results_frame = ttk.LabelFrame(analyzer_frame, text="Analiz Sonuçları")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Sekme kontrolü
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Metin raporu sekmesi
        text_frame = ttk.Frame(results_notebook)
        results_notebook.add(text_frame, text="Metin Raporu")
        
        self.result_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.result_text, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        
        # Grafik sekmesi
        chart_frame = ttk.Frame(results_notebook)
        results_notebook.add(chart_frame, text="Grafikler")
        
        self.chart_area = ttk.Frame(chart_frame)
        self.chart_area.pack(fill=tk.BOTH, expand=True)
        
        # Eylem butonları
        actions_frame = ttk.Frame(analyzer_frame)
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        save_report_button = ttk.Button(actions_frame, text="Raporu Kaydet", 
                                      command=self.save_report)
        save_report_button.pack(side=tk.LEFT, padx=5)
        
        export_chart_button = ttk.Button(actions_frame, text="Grafikleri Dışa Aktar", 
                                      command=self.export_charts)
        export_chart_button.pack(side=tk.LEFT, padx=5)
        
        clean_button = ttk.Button(actions_frame, text="Önerilen Temizlik", 
                                command=self.suggest_cleanup)
        clean_button.pack(side=tk.LEFT, padx=5)
        
        # İlerleme çubuğu ve durum
        self.progress_var = tk.DoubleVar()
        progress = ttk.Progressbar(analyzer_frame, orient=tk.HORIZONTAL, length=100, 
                                 mode='determinate', variable=self.progress_var)
        progress.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Analiz bekleniyor...")
        status_label = ttk.Label(analyzer_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, padx=10)
        
        return analyzer_frame
    
    def browse_directory(self, dir_var):
        """Dizin seçme diyaloğu"""
        directory = filedialog.askdirectory()
        if directory:
            dir_var.set(directory)
    
    def analyze_directory(self, directory, analyze_types, analyze_sizes, analyze_dates, analyze_depth):
        """Dizin analizi yap"""
        if not directory:
            messagebox.showerror("Hata", "Lütfen analiz edilecek bir dizin seçin!")
            return
        
        if not os.path.exists(directory):
            messagebox.showerror("Hata", "Seçilen dizin bulunamadı!")
            return
        
        # Önceki grafikleri temizle
        for widget in self.chart_area.winfo_children():
            widget.destroy()
        
        # Sonuç alanını temizle
        self.result_text.delete(1.0, tk.END)
        
        # Analiz işlemi başlat
        self.progress_var.set(0)
        self.status_var.set("Analiz yapılıyor...")
        self.root.update_idletasks()
        
        # Analiz
        try:
            self.current_directory = directory
            self.analysis_results = self.analyze_files(directory)
            
            # İlerleme çubuğunu güncelle
            self.progress_var.set(50)
            self.status_var.set("Sonuçlar raporlanıyor...")
            self.root.update_idletasks()
            
            # Raporu oluştur
            self.generate_report(analyze_types, analyze_sizes, analyze_dates, analyze_depth)
            
            # İlerleme çubuğunu tamamla
            self.progress_var.set(100)
            self.status_var.set("Analiz tamamlandı.")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Analiz sırasında bir hata oluştu: {str(e)}")
            self.status_var.set("Analiz başarısız oldu.")
    
    def analyze_files(self, directory):
        """Dizindeki dosyaları analiz et"""
        results = {
            'total_size': 0,
            'count': 0,
            'extensions': collections.Counter(),
            'size_distribution': collections.defaultdict(int),
            'date_distribution': collections.defaultdict(int),
            'depth_distribution': collections.defaultdict(int),
            'largest_files': [],
            'oldest_files': [],
            'newest_files': [],
            'duplicate_sizes': collections.defaultdict(list),
            'empty_dirs': [],
            'stats_by_extension': {}
        }
        
        # Tüm dizini tara
        for root, dirs, files in os.walk(directory):
            # Dizin derinliği hesapla
            depth = root[len(directory):].count(os.sep)
            results['depth_distribution'][depth] += 1
            
            # Boş dizin kontrolü
            if not dirs and not files:
                results['empty_dirs'].append(root)
            
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Dosya boyutu
                    size = os.path.getsize(file_path)
                    results['total_size'] += size
                    results['count'] += 1
                    
                    # Uzantı istatistikleri
                    ext = os.path.splitext(file)[1].lower()
                    results['extensions'][ext] += 1
                    
                    # Uzantıya göre toplam boyut
                    if ext not in results['stats_by_extension']:
                        results['stats_by_extension'][ext] = {
                            'count': 0,
                            'total_size': 0
                        }
                    results['stats_by_extension'][ext]['count'] += 1
                    results['stats_by_extension'][ext]['total_size'] += size
                    
                    # Boyut dağılımı
                    if size < 1024:  # <1KB
                        results['size_distribution']['<1KB'] += 1
                    elif size < 1024 * 10:  # <10KB
                        results['size_distribution']['<10KB'] += 1
                    elif size < 1024 * 100:  # <100KB
                        results['size_distribution']['<100KB'] += 1
                    elif size < 1024 * 1024:  # <1MB
                        results['size_distribution']['<1MB'] += 1
                    elif size < 1024 * 1024 * 10:  # <10MB
                        results['size_distribution']['<10MB'] += 1
                    elif size < 1024 * 1024 * 100:  # <100MB
                        results['size_distribution']['<100MB'] += 1
                    else:  # >100MB
                        results['size_distribution']['>100MB'] += 1
                    
                    # Tarih dağılımı
                    mod_time = os.path.getmtime(file_path)
                    mod_date = datetime.datetime.fromtimestamp(mod_time)
                    date_key = mod_date.strftime('%Y-%m')
                    results['date_distribution'][date_key] += 1
                    
                    # En büyük dosyalar
                    results['largest_files'].append((file_path, size))
                    
                    # En eski/yeni dosyalar
                    results['oldest_files'].append((file_path, mod_time))
                    results['newest_files'].append((file_path, mod_time))
                    
                    # Muhtemel kopya dosyalar (aynı boyutta olanlar)
                    results['duplicate_sizes'][size].append(file_path)
                    
                except:
                    # Dosya okunamadığında veya başka bir hata olduğunda atla
                    pass
        
        # Sonuçları sırala
        results['largest_files'].sort(key=lambda x: x[1], reverse=True)
        results['largest_files'] = results['largest_files'][:10]  # İlk 10
        
        results['oldest_files'].sort(key=lambda x: x[1])
        results['oldest_files'] = results['oldest_files'][:10]  # İlk 10
        
        results['newest_files'].sort(key=lambda x: x[1], reverse=True)
        results['newest_files'] = results['newest_files'][:10]  # İlk 10
        
        # Aynı boyutta birden fazla dosya olanlar (muhtemel kopyalar)
        duplicate_candidates = {size: files for size, files in results['duplicate_sizes'].items() if len(files) > 1}
        results['duplicate_sizes'] = duplicate_candidates
        
        return results
    
    def generate_report(self, analyze_types, analyze_sizes, analyze_dates, analyze_depth):
        """Analiz sonuçlarını raporla"""
        results = self.analysis_results
        
        # Metin raporu
        report = "DOSYA ANALİZ RAPORU\n"
        report += "=" * 40 + "\n\n"
        
        report += f"Analiz Edilen Dizin: {self.current_directory}\n"
        report += f"Toplam Dosya Sayısı: {results['count']}\n"
        
        # Toplam boyutu formatla
        total_size = results['total_size']
        if total_size < 1024:
            size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size / 1024:.2f} KB"
        elif total_size < 1024 * 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.2f} MB"
        else:
            size_str = f"{total_size / (1024 * 1024 * 1024):.2f} GB"
        
        report += f"Toplam Dosya Boyutu: {size_str}\n\n"
        
        # Dosya türü analizi
        if analyze_types and results['extensions']:
            report += "DOSYA TÜRLERİ DAĞILIMI\n"
            report += "-" * 30 + "\n"
            
            # Uzantıları sayılarına göre sırala
            sorted_extensions = sorted(results['extensions'].items(), key=lambda x: x[1], reverse=True)
            
            for ext, count in sorted_extensions:
                ext_name = ext if ext else '(uzantısız)'
                percentage = (count / results['count']) * 100
                report += f"{ext_name}: {count} dosya ({percentage:.1f}%)\n"
            
            # Grafik oluştur
            if len(results['extensions']) > 0:
                self.create_pie_chart('Dosya Türleri Dağılımı', 
                                      {k if k else '(uzantısız)': v for k, v in results['extensions'].items()})
        
        # Boyut dağılımı
        if analyze_sizes and results['size_distribution']:
            report += "\nBOYUT DAĞILIMI\n"
            report += "-" * 20 + "\n"
            
            # Boyut kategorilerini sırala
            size_categories = ['<1KB', '<10KB', '<100KB', '<1MB', '<10MB', '<100MB', '>100MB']
            for category in size_categories:
                if category in results['size_distribution']:
                    count = results['size_distribution'][category]
                    percentage = (count / results['count']) * 100
                    report += f"{category}: {count} dosya ({percentage:.1f}%)\n"
            
            # Grafik oluştur
            size_data = {cat: results['size_distribution'][cat] for cat in size_categories if cat in results['size_distribution']}
            if size_data:
                self.create_bar_chart('Dosya Boyut Dağılımı', size_data)
        
        # Tarih dağılımı
        if analyze_dates and results['date_distribution']:
            report += "\nTARİH DAĞILIMI (Aylara göre)\n"
            report += "-" * 30 + "\n"
            
            # Tarihleri sırala
            sorted_dates = sorted(results['date_distribution'].items())
            
            for date_key, count in sorted_dates:
                percentage = (count / results['count']) * 100
                report += f"{date_key}: {count} dosya ({percentage:.1f}%)\n"
            
            # Grafik oluştur
            if len(results['date_distribution']) > 0:
                self.create_line_chart('Dosya Değişim Tarihi Dağılımı', 
                                       {k: v for k, v in sorted_dates})
        
        # Derinlik analizi
        if analyze_depth and results['depth_distribution']:
            report += "\nDİZİN DERİNLİK DAĞILIMI\n"
            report += "-" * 30 + "\n"
            
            # Derinlikleri sırala
            sorted_depths = sorted(results['depth_distribution'].items())
            
            for depth, count in sorted_depths:
                report += f"Seviye {depth}: {count} dizin\n"
            
            # Grafik oluştur
            if len(results['depth_distribution']) > 0:
                self.create_bar_chart('Dizin Derinlik Dağılımı', 
                                     {f"Seviye {k}": v for k, v in sorted_depths})
        
        # En büyük dosyalar
        if results['largest_files']:
            report += "\nEN BÜYÜK DOSYALAR\n"
            report += "-" * 20 + "\n"
            
            for i, (file_path, size) in enumerate(results['largest_files'][:10], 1):
                # Boyutu formatla
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size / 1024:.2f} KB"
                elif size < 1024 * 1024 * 1024:
                    size_str = f"{size / (1024 * 1024):.2f} MB"
                else:
                    size_str = f"{size / (1024 * 1024 * 1024):.2f} GB"
                
                report += f"{i}. {os.path.basename(file_path)} ({size_str})\n   {file_path}\n"
        
        # Boş dizinler
        if results['empty_dirs']:
            report += "\nBOŞ DİZİNLER\n"
            report += "-" * 15 + "\n"
            
            for i, dir_path in enumerate(results['empty_dirs'][:10], 1):
                report += f"{i}. {dir_path}\n"
            
            if len(results['empty_dirs']) > 10:
                report += f"...ve {len(results['empty_dirs']) - 10} boş dizin daha\n"
        
        # Muhtemel kopya dosyalar
        if results['duplicate_sizes']:
            report += "\nMUHTEMEL KOPYALAR (Aynı boyutta dosyalar)\n"
            report += "-" * 40 + "\n"
            
            count = 0
            for size, files in sorted(results['duplicate_sizes'].items(), key=lambda x: len(x[1]), reverse=True):
                if len(files) > 1 and count < 5:  # En fazla 5 grup göster
                    # Boyutu formatla
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.2f} KB"
                    elif size < 1024 * 1024 * 1024:
                        size_str = f"{size / (1024 * 1024):.2f} MB"
                    else:
                        size_str = f"{size / (1024 * 1024 * 1024):.2f} GB"
                    
                    report += f"\nGrup {count+1} - Boyut: {size_str}, {len(files)} dosya:\n"
                    for file in files[:5]:  # Her gruptan en fazla 5 dosya göster
                        report += f"  - {file}\n"
                    
                    if len(files) > 5:
                        report += f"  ...ve {len(files) - 5} dosya daha\n"
                    
                    count += 1
        
        # Rapora ekle
        self.result_text.insert(tk.END, report)
        self.result_text.see(tk.END)
    
    def create_pie_chart(self, title, data):
        """Pasta grafik oluştur"""
        # En çok kullanılan 8 kategoriyi göster, geri kalanları 'Diğer' olarak grupla
        if len(data) > 8:
            sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)
            top_data = dict(sorted_data[:8])
            other_sum = sum(v for _, v in sorted_data[8:])
            if other_sum > 0:
                top_data["Diğer"] = other_sum
            data = top_data
        
        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, texts, autotexts = ax.pie(
            data.values(), 
            labels=data.keys(), 
            autopct='%1.1f%%', 
            startangle=90,
            textprops={'fontsize': 8}
        )
        
        # Etiketleri daha okunaklı hale getir
        for text in texts:
            text.set_fontsize(8)
        
        for autotext in autotexts:
            autotext.set_fontsize(8)
        
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        ax.set_title(title)
        
        # Canvas oluştur ve çizdir
        canvas = FigureCanvasTkAgg(fig, master=self.chart_area)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def create_bar_chart(self, title, data):
        """Çubuk grafik oluştur"""
        fig, ax = plt.subplots(figsize=(5, 4))
        
        # Çubukları çiz
        bars = ax.bar(data.keys(), data.values())
        
        # X ekseni etiketlerini döndür
        plt.xticks(rotation=45, ha='right')
        
        # Başlık ve eksen etiketleri
        ax.set_title(title)
        ax.set_ylabel('Dosya Sayısı')
        
        # X ekseni etiketlerinin daha okunaklı olması için düzenle
        fig.tight_layout()
        
        # Canvas oluştur ve çizdir
        canvas = FigureCanvasTkAgg(fig, master=self.chart_area)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def create_line_chart(self, title, data):
        """Çizgi grafik oluştur"""
        fig, ax = plt.subplots(figsize=(5, 4))
        
        # X ve Y eksenlerini ayır
        x = list(data.keys())
        y = list(data.values())
        
        # Çizgi çiz
        ax.plot(x, y, marker='o')
        
        # X ekseni etiketlerini döndür
        plt.xticks(rotation=45, ha='right')
        
        # Başlık ve eksen etiketleri
        ax.set_title(title)
        ax.set_xlabel('Tarih')
        ax.set_ylabel('Dosya Sayısı')
        
        # X ekseni etiketlerinin daha okunaklı olması için düzenle
        fig.tight_layout()
        
        # Canvas oluştur ve çizdir
        canvas = FigureCanvasTkAgg(fig, master=self.chart_area)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def save_report(self):
        """Raporu dosyaya kaydet"""
        if not self.result_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Uyarı", "Kaydedilecek bir rapor bulunamadı!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Metin Dosyaları", "*.txt"), ("Tüm Dosyalar", "*.*")],
            title="Raporu Kaydet"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.result_text.get(1.0, tk.END))
                messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Hata", f"Rapor kaydedilirken bir hata oluştu: {str(e)}")
    
    def export_charts(self):
        """Grafikleri dışa aktar"""
        if not self.chart_area.winfo_children():
            messagebox.showwarning("Uyarı", "Dışa aktarılacak bir grafik bulunamadı!")
            return
        
        directory = filedialog.askdirectory(title="Grafikleri Kaydet")
        
        if not directory:
            return
        
        try:
            # Tüm grafikleri kaydet (matplotlib figürleri)
            chart_count = 0
            for widget in self.chart_area.winfo_children():
                try:
                    # FigureCanvasTkAgg bileşeninden figürü al
                    fig = widget.figure
                    if fig:
                        filename = os.path.join(directory, f"chart_{chart_count + 1}.png")
                        fig.savefig(filename, format='png', dpi=300, bbox_inches='tight')
                        chart_count += 1
                except:
                    pass
            
            if chart_count > 0:
                messagebox.showinfo("Başarılı", f"{chart_count} grafik başarıyla kaydedildi.")
            else:
                messagebox.showwarning("Uyarı", "Hiçbir grafik kaydedilemedi.")
                
        except Exception as e:
            messagebox.showerror("Hata", f"Grafikler dışa aktarılırken bir hata oluştu: {str(e)}")
    
    def suggest_cleanup(self):
        """Temizlik önerileri"""
        if not self.analysis_results:
            messagebox.showwarning("Uyarı", "Öneri sunulacak analiz sonucu bulunamadı!")
            return
        
        results = self.analysis_results
        suggestions = []
        
        # Boş dizinler
        if results['empty_dirs']:
            suggestions.append(f"Boş Dizinler: {len(results['empty_dirs'])} boş dizin bulundu. Bunları silmek disk alanından tasarruf etmenize yardımcı olabilir.")
        
        # Muhtemel kopya dosyalar
        duplicate_count = sum(1 for files in results['duplicate_sizes'].values() if len(files) > 1)
        if duplicate_count > 0:
            suggestions.append(f"Muhtemel Kopyalar: {duplicate_count} grup dosya aynı boyuta sahip ve muhtemelen kopya olabilir. Bunları kontrol edip gereksizleri silmek disk alanından tasarruf etmenize yardımcı olabilir.")
        
        # Büyük dosyalar
        if results['largest_files']:
            large_files_total = sum(size for _, size in results['largest_files'])
            percentage = (large_files_total / results['total_size']) * 100 if results['total_size'] > 0 else 0
            
            if percentage > 50:  # En büyük 10 dosya toplam boyutun %50'sinden fazlaysa
                suggestions.append(f"Büyük Dosyalar: En büyük 10 dosya toplam disk alanının %{percentage:.1f}'ini kaplıyor. Bu dosyaları gözden geçirip gereksizleri silmek disk alanından önemli tasarruf sağlayabilir.")
        
        # Öneriler penceresi
        if suggestions:
            suggest_window = tk.Toplevel(self.root)
            suggest_window.title("Temizlik Önerileri")
            suggest_window.geometry("500x400")
            suggest_window.resizable(False, False)
            
            # Icon
            try:
                suggest_window.iconbitmap(self.app.icon_path)
            except:
                pass
            
            # Başlık
            header = ttk.Label(suggest_window, text="Önerilen Temizlik İşlemleri", style='Header.TLabel')
            header.pack(pady=10)
            
            # Öneriler listesi
            suggestions_frame = ttk.Frame(suggest_window)
            suggestions_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            suggestion_text = tk.Text(suggestions_frame, wrap=tk.WORD, height=15)
            suggestion_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Scrollbar
            scrollbar = ttk.Scrollbar(suggestion_text, orient="vertical", command=suggestion_text.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            suggestion_text.config(yscrollcommand=scrollbar.set)
            
            # Önerileri ekle
            for i, suggestion in enumerate(suggestions, 1):
                suggestion_text.insert(tk.END, f"{i}. {suggestion}\n\n")
            
            # Eylem butonları
            actions_frame = ttk.Frame(suggest_window)
            actions_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Boş dizinleri temizle butonu
            if results['empty_dirs']:
                clean_empty_dirs_button = ttk.Button(
                    actions_frame, 
                    text="Boş Dizinleri Temizle", 
                    command=lambda: self.clean_empty_directories(suggest_window)
                )
                clean_empty_dirs_button.pack(side=tk.LEFT, padx=5)
            
            # Kapat butonu
            close_button = ttk.Button(actions_frame, text="Kapat", command=suggest_window.destroy)
            close_button.pack(side=tk.RIGHT, padx=5)
            
        else:
            messagebox.showinfo("Temizlik Önerileri", "Herhangi bir temizlik önerisi bulunamadı.")
    
    def clean_empty_directories(self, parent_window):
        """Boş dizinleri temizle"""
        if not self.analysis_results or not self.analysis_results['empty_dirs']:
            messagebox.showinfo("Bilgi", "Temizlenecek boş dizin bulunamadı!")
            return
        
        result = messagebox.askyesno(
            "Onay", 
            f"{len(self.analysis_results['empty_dirs'])} boş dizin silinecek. Devam etmek istiyor musunuz?"
        )
        
        if result:
            deleted_count = 0
            failed_count = 0
            
            for dir_path in self.analysis_results['empty_dirs']:
                try:
                    os.rmdir(dir_path)
                    deleted_count += 1
                except:
                    failed_count += 1
            
            messagebox.showinfo(
                "Temizlik Sonucu", 
                f"{deleted_count} boş dizin başarıyla silindi.\n"
                f"{failed_count} dizin silinemedi."
            )
            
            # Sonuçtan boş dizinleri kaldır
            self.analysis_results['empty_dirs'] = []
            
            # Ebeveyn pencereyi kapat
            if parent_window and parent_window.winfo_exists():
                parent_window.destroy()