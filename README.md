# MunchinProject
MunchinProject-Gelişmiş Dosya Şifreleme Sistemi
# MunchinProject - Gelişmiş Dosya Şifreleme Sistemi

MunchinProject, güçlü şifreleme algoritmaları kullanarak dosyalarınızı güvenle şifrelemenizi sağlayan, çok yönlü bir güvenlik uygulamasıdır. Sade ve kullanıcı dostu arayüzünün arkasında, gelişmiş güvenlik özellikleri ve veri koruma mekanizmaları barındırır.



## 🔑 Özellikler

- **Güçlü Şifreleme**: Endüstri standardı Fernet şifreleme ile dosyalarınızı koruyun
- **Çoklu İşlem Desteği**: Yüksek performanslı paralel şifreleme/çözme
- **Steganografi**: Görüntülerde gizli veri saklama ve çıkarma
- **Dosya Analizi**: Ayrıntılı dosya istatistikleri ve grafiklerle dizin analizi
- **Görev Planlayıcı**: Şifreleme ve güvenlik işlemlerini otomatikleştirin
- **Sistem Tepsisi Entegrasyonu**: Arka planda çalışma ve hızlı erişim
- **Güvenli Silme**: Dosyaları kurtarılamaz şekilde silme
- **Kapsamlı Güvenlik**: Yanlış şifre koruma mekanizmaları ve şifre denemeleri izleme
- **İki Tema**: Açık ve karanlık tema seçenekleri

## 📋 Gereksinimler

Uygulama Python 3.6 veya daha yüksek sürümünde çalışır ve aşağıdaki kütüphanelere ihtiyaç duyar:

- cryptography
- pillow (PIL)
- pystray
- matplotlib
- numpy
- tkinter (genellikle Python ile gelir)

## 🛠️ Kurulum
git clone https://github.com/KullaniciAdi/munchinproject.git
cd munchinproject
pip install -r requirements.txt

veya manuel olarak:
pip install cryptography pillow pystray matplotlib numpy
python grant.py

### 1. Kaynak Kodunu İndirin
```bash
git clone https://github.com/KullaniciAdi/munchinproject.git
cd munchinproject
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

veya manuel olarak:

```bash
pip install cryptography pillow pystray matplotlib numpy
```

### 3. Uygulamayı Başlatın
```bash
python grant.py
```

## 💻 Kullanım

1. **Şifreleme İşlemi**:
   - İşlem modunu seçin (Otomatik Algıla / Şifrele / Şifre Çöz)
   - Güçlü bir şifre girin veya otomatik oluşturun
   - İsterseniz uzantı filtresi ekleyin (ör: .jpg,.docx)
   - Şifrelemek istediğiniz dizini seçin
   - "İşlemi Başlat" düğmesine tıklayın

2. **Steganografi**:
   - "Steganografi" sekmesine geçin
   - Bir görüntü dosyası seçin
   - Gizlemek istediğiniz metni veya dosyayı belirtin
   - Şifreleme için bir parola girin
   - İşlemi başlatın

3. **Dosya Analizi**:
   - "Dosya Analizi" sekmesinde bir dizin seçin
   - Analiz seçeneklerini belirleyin
   - "Analiz Et" düğmesine tıklayarak sonuçları görüntüleyin

4. **Görev Planlama**:
   - "Görev Planlayıcı" sekmesinden yeni görev ekleyin
   - Görev türünü, dizini, şifreyi ve zamanı ayarlayın
   - Planlanan görevler otomatik olarak yürütülecektir

## ⚠️ Güvenlik Notları

- **Şifreyi Unutmayın**: Şifrenizi kaybederseniz, dosyalarınıza erişmek mümkün olmayabilir.
- **Yanlış Şifre Koruma**: Üç kere yanlış şifre girilmesi durumunda, dosyalar güvenli bir şekilde silinebilir.
- **İlk Kullanım**: İlk kullanımdan önce önemli dosyalarınızı yedeklemeniz tavsiye edilir.

## requirements.txt Dosyası

Projenin ana dizinine aşağıdaki içerikle bir `requirements.txt` dosyası oluşturun:

```
cryptography>=3.4.0
pillow>=8.2.0
pystray>=0.17.3
matplotlib>=3.4.2
numpy>=1.20.0
```

## 🤝 Katkıda Bulunma

Hata raporları, özellik önerileri ve pull request'ler için GitHub Issues kullanabilirsiniz. Her türlü katkıya açığım!

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakın.

## 📞 İletişim

Sorularınız veya önerileriniz için GitHub üzerinden iletişime geçebilirsiniz.

---

**Not**: Bu uygulama eğitim ve kişisel kullanım amacıyla geliştirilmiştir. Yasadışı faaliyetlerde kullanılması kesinlikle yasaktır.
