# M-MAP 🔍

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

M-MAP, hızlı ve kullanımı kolay bir port tarama aracıdır. Ağ güvenliği testleri ve sistem yönetimi için tasarlanmıştır.

## 🚀 Özellikler

- 🔍 Tek port tarama
- 🔎 Çoklu port tarama
- ⚡ Hızlı tarama (En yaygın 20 port)
- 🔥 Agresif tarama (Servis sürüm tespiti)
- 🌐 IP aralığı tarama
- 💾 Sonuçları TXT/JSON formatında dışa aktarma
- ⚙️ Özelleştirilebilir tarama ayarları
- 📊 Gerçek zamanlı ilerleme göstergesi

## 📋 Gereksinimler

```bash
pip install -r requirements.txt
```

## 🛠️ Kurulum

```bash
# Repoyu klonlayın
git clone https://github.com/melihcan1376/m-map.git

# Dizine gidin
cd m-map

# Gereksinimleri yükleyin
pip install -r requirements.txt

# Programı çalıştırın
python m-map.py
```

## 💻 Kullanım

1. **Tek Port Tarama:**
   - Belirli bir IP adresinde tek bir portu tarar

2. **Çoklu Port Tarama:**
   - Belirtilen port aralığını tarar
   - Threading ile hızlı tarama

3. **Hızlı Tarama:**
   - En yaygın 20 portu otomatik tarar
   - Hızlı sonuç için optimize edilmiş

4. **Agresif Tarama:**
   - Detaylı servis tespiti
   - Banner bilgisi toplama

5. **IP Aralığı Tarama:**
   - Birden fazla IP adresini tarar
   - CIDR desteği

## 📸 Ekran Görüntüsü

![M-MAP Screenshot](https://github.com/melihcan1376/m-map/blob/main/screen.png?raw=true)

## 🤝 Katkıda Bulunma

1. Bu repoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/yeniOzellik`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 👤 İletişim

Melih Can - [@melihcanndemir](https://github.com/melihcanndemir)

E-mail: melihcandemir@protonmail.com

## ⭐ Proje Durumu

![GitHub stars](https://img.shields.io/github/stars/melihcan1376/m-map?style=social)
![GitHub forks](https://img.shields.io/github/forks/melihcan1376/m-map?style=social)