# 🚗 License Plate Recognition System
This project is a Python-based License Plate Recognition System. It combines OpenCV for image 
processing and Pytesseract for optical character recognition (OCR) to automatically detect and 
read vehicle license plates. Tesseract OCR is integrated into the project, requiring no additional installation.

## ✨ Features

- Automatic Plate Detection: Quickly and accurately identifies vehicle license plates.
- OCR Text Recognition: Reads letters and numbers on plates using Pytesseract.
- Live Camera Support: Works with real-time camera feeds.
- Advanced Image Processing: Utilizes robust OpenCV-based algorithms.
- User-Friendly Interface: Provides an intuitive and easy-to-use interface.


## 📋 System Requirements

- Operating System: Windows, macOS, or Linux
- Python: 3.8 or higher
- Dependencies: Libraries listed in the requirements.txt file
- Hardware: Camera (IP or local) and optional relay device
- Storage: Minimum 500 MB free space (for database and logs)


## 🛠 Installation
1. Download the Project
Run the following command in your terminal to clone the project:
```bash
git clone https://github.com/hasanefeavc/License-Plate-Recognition.git
cd License-Plate-Recognition
```

2. Install Dependencies
To install the required libraries:
```bash
pip install -r requirements.txt
```

3. Launch the Application
To start the application:
```bash
python main.py
```


# 🖥 Interface and Usage

![anasayfa](https://github.com/user-attachments/assets/b12aead9-b969-42e6-9a2d-8fc8f7295d3b)

### Initial Setup and User Management

- On first launch, the application creates a database file named plates and prompts you to create a user account.

- Registered user information is stored; subsequent logins require only your username and password.

![kayıt1](https://github.com/user-attachments/assets/4851a095-aabe-4c99-a20d-c36bc8a3ae39)
![giriş2](https://github.com/user-attachments/assets/26ebc3cc-9e78-4220-8b09-6246de429378)


## Interface Features

### Plate Registration

- Add or remove plates via the "Registered Plates" tab.

![plakakayıt1](https://github.com/user-attachments/assets/84ffeb08-3f87-4705-af6f-c45a7b567737)


### History Logs

- Recognition records are stored in the database for 10 days and can be viewed from the interface. On the 11th day,
the oldest logs are automatically deleted and new entries are added.




### Camera Settings

- Configure the IP addresses for entry and exit cameras through the interface.

![kamerakaynakları](https://github.com/user-attachments/assets/5104c0a5-8c8c-4660-a8af-fbcdfc4bbecd)


### Uptime

- The top-right corner of the interface displays the application's uptime, which resets when the application is restarted.

![çalışmasüresi](https://github.com/user-attachments/assets/0224591a-d81b-45bb-b1bc-365be612b6c3)




## ⚙️ Code Customization
### Relay Connection

- Modify the code based on the signal type of the relay device used. Relay signals may vary depending on the device.

![role1](https://github.com/user-attachments/assets/07add916-1d91-429d-a770-f2e4c4d9eb78)


### 💡 Usage Tips

- Camera Configuration: Ensure IP addresses are correctly set.
- Relay Integration: Adjust settings according to the relay device's specifications.
- Performance: Use high-resolution cameras for better results.
- Troubleshooting: Refer to OpenCV and Pytesseract documentation for debugging assistance.


### 📜 License
This project is distributed under the MIT License. See the LICENSE file for details.

### 🤝 Contributing
To contribute to the project:

### Fork the repository.
Create a new feature branch (git checkout -b feature/new-feature).
Make your changes and commit them (git commit -m 'Added new feature').
Push your branch (git push origin feature/new-feature).
Open a Pull Request.


### 📞 Contact
### For questions or suggestions:

### GitHub: hasanefeavc
### Email: hasanefeavc@gmail.com



---------------------------------------------------------------------------------------------------------



# 🚗 Araç Plaka Tanıma Sistemi
Bu proje, Python tabanlı bir Araç Plaka Tanıma Sistemidir. OpenCV ile görüntü işleme ve Pytesseract ile optik karakter tanıma (OCR) teknolojilerini birleştirerek araç plakalarını otomatik olarak tespit eder ve okur. Tesseract OCR, proje içine entegre edilmiştir; ek kurulum gerektirmez.

## ✨ Özellikler

- Otomatik Plaka Tespiti: Araç plakalarını hızlı ve doğru bir şekilde algılar.
- OCR ile Metin Okuma: Plakalardaki harf ve rakamları Pytesseract ile tanır.
- Canlı Kamera Desteği: Gerçek zamanlı kamera akışıyla çalışır.
- Güçlü Görüntü İşleme: OpenCV tabanlı gelişmiş algoritmalar kullanır.
- Kullanıcı Dostu Arayüz: Sezgisel ve kolay kullanımlı bir arayüz sunar.


## 📋 Sistem Gereksinimleri

- İşletim Sistemi: Windows, macOS veya Linux
- Python: 3.8 veya üzeri
- Bağımlılıklar: requirements.txt dosyasında listelenen kütüphaneler
- Donanım: Kamera (IP veya yerel) ve opsiyonel röle cihazı
- Depolama: Minimum 500 MB boş alan (veritabanı ve loglar için)


## 🛠 Kurulum
1. Projeyi İndirin
Terminalde aşağıdaki komutu çalıştırarak projeyi klonlayın:
```bash
git clone https://github.com/hasanefeavc/License-Plate-Recognition.git
cd License-Plate-Recognition
```

2. Bağımlılıkları Yükleyin
```bash
Gerekli kütüphaneleri kurmak için:
pip install -r requirements.txt
```

3. Uygulamayı Başlatın
```bash
Uygulamayı çalıştırmak için:
python main.py
```


# 🖥 Arayüz ve Kullanım

![anasayfa](https://github.com/user-attachments/assets/b12aead9-b969-42e6-9a2d-8fc8f7295d3b)

### İlk Kurulum ve Kullanıcı Yönetimi

- Uygulama ilk açıldığında plates adında bir veritabanı dosyası oluşturur ve bir kullanıcı hesabı oluşturmanızı ister.

- Kayıtlı kullanıcı bilgileri saklanır; sonraki girişlerde kullanıcı adı ve şifrenizle oturum açabilirsiniz.

![kayıt1](https://github.com/user-attachments/assets/4851a095-aabe-4c99-a20d-c36bc8a3ae39)
![giriş2](https://github.com/user-attachments/assets/26ebc3cc-9e78-4220-8b09-6246de429378)


## Arayüz Özellikleri

### Plaka Kayıt

- "Kayıtlı Plakalar" sekmesinden plakaları ekleyebilir veya silebilirsiniz.

![plakakayıt1](https://github.com/user-attachments/assets/84ffeb08-3f87-4705-af6f-c45a7b567737)




### Geçmiş Loglar

- Tanıma işlemleri 10 gün boyunca veritabanında saklanır ve arayüzden görüntülenebilir.11. günde,
en eski loglar otomatik olarak silinir ve yeni kayıtlar eklenir.

![geçmişloglar](https://github.com/user-attachments/assets/5e04a53b-cf0f-4fbf-9f32-e6aa3445a974)




### Kamera Ayarları

- Giriş ve çıkış kameralarının IP adresleri arayüzden yapılandırılabilir.

![kamerakaynakları](https://github.com/user-attachments/assets/5104c0a5-8c8c-4660-a8af-fbcdfc4bbecd)



### Çalışma Süresi

- Arayüzün sağ üst köşesinde uygulamanın çalışma süresi gösterilir. Uygulama yeniden başlatıldığında sıfırlanır.

![çalışmasüresi](https://github.com/user-attachments/assets/0224591a-d81b-45bb-b1bc-365be612b6c3)




## ⚙ ️ Kod Özelleştirme
### Röle Bağlantısı

- Kullandığınız rölenin sinyal türüne göre kodda gerekli düzenlemeleri yapın. Röle sinyalleri cihaza bağlı olarak farklılık gösterebilir.

![role1](https://github.com/user-attachments/assets/07add916-1d91-429d-a770-f2e4c4d9eb78)



## 💡 Kullanım İpuçları

- Kamera Yapılandırması: IP adreslerinin doğru olduğundan emin olun.
- Röle Entegrasyonu: Röle cihazının teknik özelliklerine uygun ayarlamalar yapın.
- Performans: Daha iyi sonuçlar için yüksek çözünürlüklü kameralar kullanın.
- Hata Ayıklama: OpenCV ve Pytesseract dökümanlarını inceleyerek sorun giderme yapabilirsiniz.


### 📜 Lisans
Bu proje MIT Lisansı altında dağıtılmaktadır. Detaylar için LICENSE dosyasını inceleyin.

### 🤝 Katkıda Bulunma
Katkıda bulunmak isterseniz:

Depoyu fork edin.
Yeni bir özellik dalı oluşturun (git checkout -b feature/yeni-ozellik).
Değişikliklerinizi yapın ve commit edin (git commit -m 'Yeni özellik eklendi').
Dalınızı push edin (git push origin feature/yeni-ozellik).
Bir Pull Request açın.


### 📞 İletişim
### Sorularınız veya önerileriniz için:

### GitHub: hasanefeavc
### E-posta: [hasanefeavc@gmail.com]
