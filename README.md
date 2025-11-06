# Windows Server Update Services (WSUS) Kurulum Rehberi
## Windows Server 2025 Üzerinde WSUS Kurulumu ve Yapılandırması

Bu rehber, **Windows Server 2025 Standard Evaluation** sistemine **Windows Server Update Services (WSUS)** rolünün nasıl kurulacağını ve yapılandırılacağını adım adım açıklar. Kurulum, `Server Manager` aracılığıyla gerçekleştirilir.

---

## 📑 İçindekiler

- [Ön Gereksinimler ve Hazırlık](#ön-gereksinimler-ve-hazırlık)
- [WSUS Kurulum Adımları](#-wsus-kurulum-adımları)
  - [Adım 1: Add Roles and Features - Gerekli Bağımlılıklar](#adım-1-add-roles-and-features---gerekli-bağımlılıklar)
  - [Adım 2: WSUS Role Services Seçimi](#adım-2-wsus-role-services-seçimi)
  - [Adım 3: Content Location Selection](#adım-3-content-location-selection)
  - [Adım 4: Kurulum Onayı](#adım-4-kurulum-onayı)
  - [Adım 5: Post-Installation Tasks](#adım-5-post-installation-tasks)
  - [Adım 6: WSUS Configuration Wizard - Before You Begin](#adım-6-wsus-configuration-wizard---before-you-begin)
  - [Adım 7: Connect to Upstream Server](#adım-7-connect-to-upstream-server)
  - [Adım 8: Choose Languages](#adım-8-choose-languages)
  - [Adım 9: Choose Products - All Products](#adım-9-choose-products---all-products)
  - [Adım 10: Choose Products - Operating Systems](#adım-10-choose-products---operating-systems)
  - [Adım 11: Choose Classifications](#adım-11-choose-classifications)
  - [Adım 12: Configure Sync Schedule](#adım-12-configure-sync-schedule)
  - [Adım 13: Update Services Management Console](#adım-13-update-services-management-console)
- [Kurulum Sonrası Ekstra Özellikler](#-kurulum-sonrası-ekstra-özellikler)
- [Sık Karşılaşılan Sorunlar ve Çözümler](#-sık-karşılaşılan-sorunlar-ve-çözümler)
- [Doküman Bilgileri](#-doküman-bilgileri)

---

## 🔰 Ön Gereksinimler ve Hazırlık

### Sistem Gereksinimleri
- **İşletim Sistemi:** Windows Server 2025 Standard/Datacenter
- **Bellek:** Minimum 4 GB (Önerilen 8+ GB)
- **Depolama:** Minimum 100 GB boş alan (Update içeriği için)
- **Ağ:** Statik IP adresi ve DNS yapılandırması

### Ağ ve Güvenlik Hazırlıkları
```powershell
# Statik IP ayarlama
New-NetIPAddress -IPAddress "192.168.31.100" -PrefixLength 24 -DefaultGateway "192.168.31.1" -InterfaceAlias "Ethernet"

# DNS sunucusu ayarlama
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "127.0.0.1"

# Sunucu ismini ayarlama
Rename-Computer -NewName "WSUS-SERVER" -Restart
```

### Kritik Ön Kontroller
- ✅ Windows Update yamaları tamamlanmış olmalı
- ✅ Güvenlik duvarı 8530/8531 portları (HTTP/HTTPS) açılmış olmalı
- ✅ SQL Server veya Windows Internal Database (WID) desteği
- ✅ Yönetici (Administrator) yetkisi

---

## 🖥️ WSUS Kurulum Adımları

### Adım 1: Add Roles and Features - Gerekli Bağımlılıklar

![Adım 1: WSUS Bağımlılıkları](Images/1.png)

**Teknik Detaylar:**

WSUS kurulumu için aşağıdaki bağımlılıklar otomatik olarak eklenir:

**Ana Bileşenler:**
- **.NET Framework 4.8 Features**
  - ASP.NET 4.8
- **WCF Services**
  - HTTP Activation
- **Remote Server Administration Tools**
  - Role Administration Tools
  - Windows Server Update Services Tools
    - API and PowerShell cmdlets
    - [Tools] User Interface Management Console
- **Web Server (IIS)**
  - Management Tools
  - IIS 6 Management Compatibility

**Teknik Açıklama:**
- WSUS, IIS (Internet Information Services) üzerinde çalışan bir web uygulamasıdır
- .NET Framework 4.8 ve ASP.NET desteği zorunludur
- WCF servisleri HTTP aktivasyonu ile güncellemeleri istemcilere sunar
- IIS 6 Management Compatibility eski istemcilerle uyumluluk sağlar

**PowerShell Alternatifi:**
```powershell
# WSUS rolünü tüm bağımlılıklarıyla kurma
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
```

✅ **"Include management tools (if applicable)"** seçeneği işaretli olmalıdır.  
**"Add Features"** butonuna tıklayarak devam edin.

---

### Adım 2: WSUS Role Services Seçimi

![Adım 2: WSUS Role Services](Images/2.png)

**Role Services Seçimi:**

**Seçilen Servisler:**
- ✅ **WID Connectivity** (Windows Internal Database)
  - WSUS veritabanını WID üzerinde saklar
  - Küçük ve orta ölçekli ortamlar için yeterlidir
  - Maksimum 30.000 istemciyi destekler
- ✅ **WSUS Services**
  - Temel WSUS hizmetleri ve güncelleme sunumu

**Alternatif Seçenekler:**
- ❌ **SQL Server Connectivity** (Bu senaryoda kullanılmıyor)
  - Harici SQL Server kullanımı için
  - 10.000+ istemci için önerilir
  - Yüksek performans ve ölçeklenebilirlik sağlar

**Teknik Karşılaştırma:**
| Özellik | WID | SQL Server |
|---------|-----|------------|
| Maksimum İstemci | 30.000 | Sınırsız |
| Kurulum Kolaylığı | Kolay | Orta |
| Bakım Gereksinimi | Düşük | Yüksek |
| Performans | Orta | Yüksek |
| Lisans Maliyeti | Ücretsiz | Ücretli |

**PowerShell ile Kurulum:**
```powershell
# WID ile WSUS kurulumu
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
```

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 3: Content Location Selection

![Adım 3: Content Location](Images/3.png)

**Content Location (İçerik Konumu) Ayarları:**

**Yapılandırma:**
- **Store updates in the following location:** `C:\WSUS`
- **Dosya Sistemi:** NTFS (Zorunlu)
- **Önerilen Boş Alan:** 100+ GB

**Teknik Öneriler:**

**Disk Gereksinimleri:**
- **Minimum:** 40 GB (Temel güncellemeler için)
- **Önerilen:** 100-200 GB (Çoklu ürün desteği için)
- **Enterprise:** 500+ GB (Tüm ürünler ve diller için)

**Performans İyileştirmeleri:**
- SSD disk kullanımı önerilir (I/O performansı için)
- RAID 10 yapılandırması (Hız + Yedeklilik)
- Düzenli disk temizliği (Server Cleanup Wizard)

**Klasör İzinleri:**
- `NT AUTHORITY\NETWORK SERVICE` - Full Control
- `BUILTIN\Administrators` - Full Control

**PowerShell ile Content Klasörü Oluşturma:**
```powershell
# WSUS content klasörü oluşturma
New-Item -Path "C:\WSUS" -ItemType Directory -Force

# NTFS izinleri ayarlama
$acl = Get-Acl "C:\WSUS"
$permission = "NT AUTHORITY\NETWORK SERVICE","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl "C:\WSUS" $acl
```

**Disk Alanı Tasarrufu İpuçları:**
- Güncellemeleri yerel olarak saklamayıp Microsoft Update'ten direkt indirme
- Express installation files devre dışı bırakma (%30-40 alan tasarrufu)
- Eski güncellemeleri decline etme

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 4: Kurulum Onayı

![Adım 4: Confirm Installation](Images/4.png)

**Kurulum Özeti:**

**Yüklenecek Bileşenler:**
```
Windows Server Update Services
├── .NET Framework 4.8 Features
│   ├── ASP.NET 4.8
│   └── WCF Services
│       └── HTTP Activation
├── Remote Server Administration Tools
│   ├── Role Administration Tools
│   │   └── Windows Server Update Services Tools
│   │       ├── API and PowerShell cmdlets
│   │       └── User Interface Management Console
└── Web Server (IIS)
    ├── Management Tools
    └── IIS 6 Management Compatibility
```

**Kurulum Seçenekleri:**
- ☐ **Restart the destination server automatically if required**
  - Otomatik yeniden başlatma (Genellikle gerekmez)
- 🔗 **Export configuration settings**
  - Kurulum ayarlarını XML olarak kaydetme
- 🔗 **Specify an alternate source path**
  - Alternatif kaynak dizini belirleme

**Teknik Notlar:**
- Kurulum süresi: ~5-10 dakika
- İndirme boyutu: ~500 MB
- Yeniden başlatma: Genellikle gerekmez

**Kurulum Öncesi Son Kontrol:**
```powershell
# Mevcut kurulu özellikleri kontrol et
Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"}

# Disk alanı kontrolü
Get-Volume -DriveLetter C | Select-Object DriveLetter, SizeRemaining
```

✅ **"Install"** butonuna tıklayarak kurulumu başlatın.

**Kurulum İlerlemesi:**
- Installation progress gösterge çubuğu
- Her bileşen için ayrı durum göstergesi
- Hata durumunda detaylı log kayıtları

**Kurulum Doğrulama (Sonrasında):**
```powershell
# WSUS servis durumunu kontrol et
Get-Service -Name WsusService | Select-Object Name, Status, StartType

# IIS durumu kontrolü
Get-Service -Name W3SVC | Select-Object Name, Status, StartType

# WSUS web sitesi kontrolü
Get-Website -Name "WSUS Administration"
```

---

### Adım 5: Post-Installation Tasks

![Adım 5: Post-Installation Configuration](Images/5.png)

**Post-Deployment Configuration:**

**Bildirim Detayı:**
```
⚠️ Post-deployment Configuration
Configuration required for Windows Server Update Services at DOMAIN
```

**Post-Installation Tasks:**
1. **WSUS Database Initialization**
   - WID veritabanı şeması oluşturma
   - Tablolar ve stored procedure'ler yükleme
2. **IIS Web Site Configuration**
   - WSUS Administration web sitesi yapılandırması
   - Application pool ayarları
3. **Service Startup**
   - WSUS servisi başlatılması
   - Update Services bileşenlerinin başlatılması

**Teknik İşlemler:**
- IIS Application Pool: `WsusPool`
- Web Site: `WSUS Administration` (Port 8530)
- SSL Web Site: `WSUS Administration` (Port 8531)

✅ **"Launch Post-Installation tasks"** bağlantısına tıklayın.

**Post-Installation İzleme:**
```powershell
# Post-installation task durumu
Get-WsusServer | Select-Object Name, PortNumber, ServerProtocolVersion

# IIS application pool durumu
Get-IISAppPool -Name "WsusPool"
```

**Bekleme Süresi:**
- Post-installation tasks: 5-10 dakika
- İlerleme: Server Manager bildirim alanından takip edilir
- Tamamlandığında: "Configuration successfully completed"

**Sorun Giderme:**
```powershell
# Post-installation logları kontrol et
Get-Content "C:\Program Files\Update Services\LogFiles\SoftwareDistribution.log" -Tail 50
```

---

### Adım 6: WSUS Configuration Wizard - Before You Begin

![Adım 6: Before You Begin](Images/6.png)

**WSUS Configuration Wizard Başlangıç Ekranı:**

**Ön Koşul Kontrolleri:**

1. **Sunucu Güvenlik Duvarı Yapılandırması**
   - İstemcilerin sunucuya erişebilmesi için gerekli portlar açık mı?
   - **Port 8530** (HTTP): İstemci bağlantıları için
   - **Port 8531** (HTTPS): Güvenli istemci bağlantıları için

2. **Upstream Server Bağlantısı**
   - Bu sunucu Microsoft Update'e mi bağlanacak?
   - Yoksa başka bir WSUS sunucusuna mı bağlanacak?

3. **Proxy Server Kimlik Bilgileri**
   - Kurum içi proxy kullanılıyor mu?
   - Proxy için kullanıcı adı ve şifre gerekiyor mu?

**Teknik Doğrulama Komutları:**
```powershell
# Güvenlik duvarı kurallarını kontrol et
New-NetFirewallRule -DisplayName "WSUS HTTP" -Direction Inbound -LocalPort 8530 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "WSUS HTTPS" -Direction Inbound -LocalPort 8531 -Protocol TCP -Action Allow

# Mevcut güvenlik duvarı kurallarını listele
Get-NetFirewallRule -DisplayName "WSUS*" | Select-Object DisplayName, Enabled, Direction

# İnternet bağlantısı kontrolü
Test-NetConnection -ComputerName "www.update.microsoft.com" -Port 443

# Proxy ayarlarını kontrol et
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable, ProxyServer
```

**Hiyerarşik WSUS Yapılandırması:**
- **Standalone WSUS:** Doğrudan Microsoft Update'e bağlanır
- **Replica Server:** Ana WSUS'tan tam kopya alır
- **Downstream Server:** Ana WSUS'tan güncelleme alır ama kendi onaylarını yapar

**Ağ Gereksinimleri:**
- İnternet erişimi (Microsoft Update için)
- DNS çözümlemesi
- HTTPS/TLS 1.2 desteği

💡 Bu sayfa yalnızca bilgilendiricidir. Sihirbaz, temel yapılandırma adımlarını gerçekleştirecektir.

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 7: Connect to Upstream Server

![Adım 7: Connect to Upstream Server](Images/7.png)

**Microsoft Update ile Senkronizasyon:**

**İndirilecek Bilgiler:**
- **Types of updates available** (Mevcut güncelleme türleri)
- **Products that can be updated** (Güncellenebilecek ürünler)
- **Available languages** (Desteklenen diller)

**Teknik Detaylar:**
- **İlk Senkronizasyon:** Sadece meta veriler indirilir
- **Gerçek Güncelleme Dosyaları:** Henüz indirilmez
- **Bağlantı Protokolü:** HTTPS (TLS 1.2)
- **Bekleme Süresi:** 3-10 dakika (bağlantı hızına bağlı)

**Hata Mesajı:**
```
⚠️ The synchronization with the upstream server or Microsoft Update was canceled.
```

**Bu Mesajın Anlamı:**
- Normal bir durumdur
- İlk senkronizasyon henüz başlatılmamıştır
- **"Start Connecting"** butonuna basılarak senkronizasyon başlatılır

**Bağlantı Ayarları:**
```powershell
# Microsoft Update'e bağlanma ayarı
Set-WsusServerSynchronization -SyncFromMU

# Proxy ayarları (gerekiyorsa)
$proxy = New-Object System.Net.WebProxy("http://proxy.domain.com:8080")
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[System.Net.WebRequest]::DefaultWebProxy = $proxy
```

**İlk Senkronizasyon Başlatma:**
✅ **"Start Connecting"** butonuna tıklayın.

**Senkronizasyon İlerlemesi:**
- Progress bar ile ilerleme takibi
- "Connecting to Microsoft Update..."
- "Downloading product categories..."
- "Downloading update classifications..."

**Senkronizasyon Tamamlandıkında:**
- ✅ "Synchronization completed successfully"
- Toplam ürün sayısı
- Toplam güncelleme kategorisi
- Desteklenen dil sayısı

**Manuel Senkronizasyon (Alternatif):**
```powershell
# Senkronizasyonu PowerShell ile başlatma
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()
$subscription.StartSynchronization()

# Senkronizasyon durumunu izleme
$subscription.GetSynchronizationStatus()
```

✅ Bağlantı tamamlandıktan sonra **"Next"** butonuna tıklayın.

---

### Adım 8: Choose Languages

![Adım 8: Choose Languages](Images/8.png)

**Dil Seçimi:**

**Seçenekler:**

1. **Download updates in all languages, including new languages**
   - Tüm dillerdeki güncellemeleri indir
   - Yeni eklenen diller otomatik dahil edilir
   - ⚠️ Çok fazla disk alanı gerektirir

2. **Download updates only in these languages** ✅ (Önerilen)
   - Sadece seçilen dillerdeki güncellemeleri indir
   - Disk alanı optimizasyonu sağlar

**Kullanılabilir Diller (Alfabetik):**
- ❌ Arabic
- ❌ Bulgarian
- ❌ Chinese (Hong Kong S.A.R.)
- ❌ Chinese (Simplified)
- ❌ Chinese (Traditional)
- ❌ Croatian
- ❌ Czech
- ❌ Danish
- ❌ Dutch
- ✅ **English** (Zorunlu - Varsayılan)
- ❌ Estonian
- ❌ Finnish
- ❌ French
- ❌ German
- ❌ Greek
- ❌ Hebrew
- ❌ Hindi
- ❌ Hungarian
- ❌ Italian
- ❌ Japanese
- ❌ Japanese (NEC)
- ❌ Korean
- ❌ Latvian
- ❌ Lithuanian
- ❌ Norwegian
- ❌ Polish
- ❌ Portuguese
- ❌ Portuguese (Brazil)
- ❌ Romanian
- ❌ Russian
- ❌ Serbian (Latin)
- ❌ Slovak
- ❌ Slovenian
- ❌ Spanish
- ❌ Swedish
- ❌ Thai
- ❌ Turkish

**Teknik Öneriler:**

**Disk Alanı Etkisi:**
| Dil Sayısı | Tahmini Disk Kullanımı |
|------------|------------------------|
| 1 dil (English) | 40-60 GB |
| 2-3 dil | 80-120 GB |
| Tüm diller | 400+ GB |

**En İyi Uygulamalar:**
- Sadece kuruluşunuzda kullanılan dilleri seçin
- English (İngilizce) her zaman seçili kalmalıdır
- Çoklu lokasyonlu ortamlarda gerekli dilleri ekleyin
- Test ortamında daha az dil seçerek alan tasarrufu yapın

**PowerShell ile Dil Ayarları:**
```powershell
# Sadece İngilizce güncellemeleri indir
$wsus = Get-WsusServer
$config = $wsus.GetConfiguration()
$config.AllUpdateLanguagesEnabled = $false
$config.SetEnabledUpdateLanguages("en")
$config.Save()

# Türkçe eklemek için
$config.SetEnabledUpdateLanguages("en","tr")
$config.Save()

# Mevcut dil ayarlarını kontrol et
$wsus.GetConfiguration().GetEnabledUpdateLanguages()
```

**Örnek Senaryo:**
- Türkiye'de kurumsal kullanım: **English + Turkish**
- Uluslararası şirket: **English + Bölge dilleri**
- Küçük işletme: **Sadece English**

✅ Dil seçimini yaptıktan sonra **"Next"** butonuna tıklayın.

---

### Adım 9: Choose Products - All Products

![Adım 9: Choose Products - All Products](Images/9.png)

**Ürün Seçimi (Genel Bakış):**

**Ürün Kategorileri:**
- ✅ **All Products** (Tüm Ürünler) - Varsayılan seçili

**Ana Ürün Grupları:**
```
All Products
├── Microsoft
│   ├── Active Directory
│   ├── Active Directory Rights Management Services Client 2.0
│   ├── AKS-EE
│   ├── AlcsEdge Category
│   ├── Antigen
│   │   └── Antigen for Exchange/SMTP
│   ├── ASP.NET Web and Data Frameworks
│   │   └── ASP.NET Web Frameworks
│   ├── Azure Connected Machine Agent
│   │   └── Azure Connected Machine Agent 3
│   ├── Azure File Sync
│   └── (Devamı...)
```

**Teknik Açıklama:**
- WSUS, Microsoft'un tüm ürün kataloğunu sunar
- "All Products" seçeneği tüm mevcut ve gelecek ürünleri kapsar
- Bu geniş seçim ilk yapılandırmada kullanılır
- Daha sonra ihtiyaca göre daraltılabilir

**Disk Alanı Uyarısı:**
- Tüm ürünleri seçmek **300-500 GB** disk alanı gerektirebilir
- İlk senkronizasyon **birkaç saat** sürebilir
- Sadece kullanılan ürünleri seçmek **önemlidir**

**Sık Kullanılan Ürün Örnekleri:**
- Windows 10/11
- Windows Server 2016/2019/2022/2025
- Microsoft 365 Apps
- Microsoft Defender
- Microsoft Edge
- SQL Server
- Exchange Server

**PowerShell ile Ürün Yönetimi:**
```powershell
# Tüm ürünleri listele
Get-WsusProduct | Select-Object Title, ProductState

# Tüm ürünleri devre dışı bırak
Get-WsusProduct | Set-WsusProduct -Disable

# Sadece belirli ürünleri etkinleştir
Get-WsusProduct | Where-Object {$_.Product.Title -like "*Windows 10*"} | Set-WsusProduct
```

**Önemli Not:**
- Bu ekranda sadece genel kategori görünür
- Sonraki adımda spesifik işletim sistemleri seçilecek
- İlk kurulumda "All Products" seçili bırakılabilir
- Yapılandırma sonrası WSUS Console'dan detaylı seçim yapılır

**Alt Bilgi:**
"All products, including products that are added in the future."

💡 Bu seçenek, gelecekte eklenecek yeni Microsoft ürünlerini otomatik olarak kataloğa dahil eder.

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 10: Choose Products - Operating Systems

![Adım 10: Choose Products - Windows 11](Images/10.png)

**İşletim Sistemi Seçimi:**

**Windows 11 Ürün Ailesi:**
- ✅ **Windows 11** (Ana kategori - Seçili)
- ❌ Windows 11 Client, version 25H2 and later, Upgrade & Servicing Drivers
- ❌ Windows 11 Client, version 24H2 and later, Servicing Drivers
- ❌ Windows 11 Client, version 24H2 and later, Upgrade & Servicing Drivers
- ❌ Windows 11 Client, version 24H2 and later, Servicing Drivers
- ❌ Windows 11 Client, version 23H2 and later, Upgrade & Servicing Drivers
- ❌ Windows 11 Client, version 23H2 and later, Servicing Drivers
- ❌ Windows 11 Dynamic Update
- ❌ Windows 11 GDR-DU

**Diğer İşletim Sistemleri:**
- ❌ Windows 2000 (Eski - Artık desteklenmiyor)
- ❌ Windows 7 (Desteği sona erdi)
- ❌ Windows 8 Dynamic Update

**Alt Bilgi:**
"Windows 10 S, Vibranium and later, Servicing Drivers"

**Teknik Açıklamalar:**

**Sürücü Güncellemeleri:**
- **Servicing Drivers:** Rutin sürücü güncellemeleri
- **Upgrade & Servicing Drivers:** Sürüm yükseltmelerinde gerekli sürücüler

**Dynamic Update:**
- Windows kurulumu sırasında kullanılan güncellemeler
- Kurulum medyasını güncellemek için kullanılır

**GDR-DU (General Distribution Release - Dynamic Update):**
- Kritik güvenlik güncellemeleri
- Out-of-band (acil) yamalar

**Sürüm Yönetimi:**
- **21H2:** 2021 yılı 2. yarı sürümü
- **22H2:** 2022 yılı 2. yarı sürümü
- **23H2:** 2023 yılı 2. yarı sürümü
- **24H2:** 2024 yılı 2. yarı sürümü
- **25H2:** 2025 yılı 2. yarı sürümü

**En İyi Uygulamalar:**

**Küçük İşletmeler için:**
```
✅ Windows 11 (Ana güncellemeler)
❌ Sürücü güncellemeleri (Opsiyonel)
```

**Orta/Büyük İşletmeler için:**
```
✅ Windows 11
✅ Windows 11 Client, version 23H2 and later, Servicing Drivers
✅ Windows 11 Dynamic Update (Yeni kurulumlar için)
```

**Enterprise Ortamlar için:**
```
✅ Tüm Windows 11 kategorileri
✅ Test ortamında önce doğrulama
```

**PowerShell ile İşletim Sistemi Seçimi:**
```powershell
# Windows 11 ürünlerini etkinleştir
Get-WsusProduct | Where-Object {$_.Product.Title -eq "Windows 11"} | Set-WsusProduct

# Sadece temel Windows 11 güncellemelerini al
Get-WsusProduct | Where-Object {
    $_.Product.Title -eq "Windows 11" -and
    $_.Product.Title -notlike "*Driver*"
} | Set-WsusProduct

# Mevcut seçili ürünleri görüntüle
Get-WsusProduct | Where-Object {$_.Product.ProductState -eq "Enabled"} | Select-Object -ExpandProperty Title
```

**Disk Alanı Etkisi:**
| Seçim | Tahmini Boyut |
|-------|---------------|
| Sadece Windows 11 | 20-30 GB |
| Windows 11 + Drivers | 40-60 GB |
| Tüm Windows 11 kategorileri | 60-80 GB |

**Uyarı:**
- Sürücü güncellemeleri donanım uyumluluğu sorunlarına neden olabilir
- Test ortamında önce doğrulama yapılmalıdır
- Kritik sistemlerde manuel onay önerilir

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 11: Choose Classifications

![Adım 11: Choose Classifications](Images/11.png)

**Güncelleme Sınıflandırmaları:**

**Seçili Sınıflandırmalar:**
- ❌ **All Classifications** (Tüm Sınıflandırmalar)
- ✅ **Critical Updates** (Kritik Güncellemeler)
- ✅ **Definition Updates** (Tanım Güncellemeleri)
- ❌ **Driver Sets** (Sürücü Setleri)
- ❌ **Drivers** (Sürücüler)
- ❌ **Feature Packs** (Özellik Paketleri)
- ✅ **Security Updates** (Güvenlik Güncellemeleri)
- ❌ **Service Packs** (Servis Paketleri)
- ❌ **Tools** (Araçlar)
- ❌ **Update Rollups** (Toplu Güncellemeler)
- ❌ **Updates** (Genel Güncellemeler)
- ✅ **Upgrades** (Sürüm Yükseltmeleri)

**Alt Bilgi:**
"All classifications, including classifications that are added in the future."

**Sınıflandırma Detayları:**

**1. Critical Updates (Kritik Güncellemeler):**
- Kritik güvenlik açıklarını kapatır
- Sistem kararlılığı için gerekli yamalar
- Hemen uygulanması önerilir
- Örnek: Zero-day exploitleri için yamalar

**2. Security Updates (Güvenlik Güncellemeleri):**
- Güvenlik açıklarını giderir
- Kötü amaçlı yazılımlara karşı koruma
- Aylık Patch Tuesday güncellemeleri
- Örnek: CVE açıklarına karşı yamalar

**3. Definition Updates (Tanım Güncellemeleri):**
- Windows Defender tanım dosyaları
- Antivirüs imza güncellemeleri
- Günlük olarak güncellenir
- Otomatik onay önerilir

**4. Upgrades (Sürüm Yükseltmeleri):**
- Windows 10 → Windows 11
- Büyük versiyon yükseltmeleri
- Dikkatli test gerektirir
- Manuel onay önerilir

**5. Driver Sets / Drivers:**
- Donanım sürücü güncellemeleri
- Uyumsuzluk riski yüksek
- Test ortamında önce doğrulama
- Üretimde otomatik onay önerilmez

**6. Feature Packs:**
- Yeni özellik eklemeleri
- Opsiyonel işlevler
- Test gerektirir

**7. Service Packs:**
- Toplu güncelleme paketleri
- Windows 7/8.1 döneminden kalma
- Modern Windows'ta kullanılmıyor

**8. Update Rollups:**
- Birden fazla güncellemenin bir arada dağıtımı
- Aylık toplu güncellemeler
- Cumulative Updates olarak bilinir

**9. Tools:**
- Yardımcı araç güncellemeleri
- Windows Assessment ve Deployment Kit
- Opsiyonel

**En İyi Uygulamalar:**

**Üretim Ortamı için Önerilen Seçim:**
```
✅ Critical Updates
✅ Security Updates  
✅ Definition Updates
❌ Drivers (Manuel test sonrası onay)
❌ Upgrades (Planlı dağıtım)
```

**Test Ortamı için Seçim:**
```
✅ Critical Updates
✅ Security Updates
✅ Definition Updates
✅ Update Rollups
✅ Upgrades
⚠️ Drivers (Kontrollü test)
```

**PowerShell ile Sınıflandırma Yönetimi:**
```powershell
# Kritik güncellemeleri etkinleştir
Get-WsusClassification | Where-Object {
    $_.Classification.Title -eq "Critical Updates"
} | Set-WsusClassification

# Güvenlik güncellemelerini etkinleştir
Get-WsusClassification | Where-Object {
    $_.Classification.Title -eq "Security Updates"
} | Set-WsusClassification

# Tanım güncellemelerini etkinleştir
Get-WsusClassification | Where-Object {
    $_.Classification.Title -eq "Definition Updates"
} | Set-WsusClassification

# Tüm seçili sınıflandırmaları listele
Get-WsusClassification | Where-Object {
    $_.Classification.IsSubscribed -eq $true
} | Select-Object -ExpandProperty Title
```

**Disk Alanı ve Bant Genişliği Etkisi:**
| Sınıflandırma | Aylık Boyut | Frekans |
|---------------|-------------|---------|
| Critical Updates | 1-2 GB | Aylık |
| Security Updates | 2-4 GB | Aylık |
| Definition Updates | 500 MB | Günlük |
| Drivers | 5-10 GB | Değişken |
| Upgrades | 20-30 GB | Yıllık |

**Otomatik Onay Önerileri:**
- ✅ Definition Updates (Günlük, düşük risk)
- ⚠️ Critical/Security Updates (Test sonrası)
- ❌ Drivers (Her zaman manuel)
- ❌ Upgrades (Her zaman manuel)

✅ Seçimlerinizi tamamladıktan sonra **"Next"** butonuna tıklayın.

---

### Adım 12: Configure Sync Schedule

![Adım 12: Configure Sync Schedule](Images/12.png)

**Senkronizasyon Zamanlaması:**

**Seçenekler:**

**1. Synchronize manually** ✅ (Seçili)
- Elle tetiklenen senkronizasyon
- Admin kontrolünde güncelleme
- Test ortamları için ideal

**2. Synchronize automatically**
- **First synchronization:** `06:39:27` (Örnek saat)
- **Synchronizations per day:** `1` (Günde 1 kez)

**Teknik Detaylar:**

**Otomatik Senkronizasyon Davranışı:**
- Belirtilen saatten itibaren **0-30 dakika** rastgele gecikme
- Microsoft sunucularına yük dağılımı için
- Tüm WSUS sunucuları aynı anda bağlanmaz

**Senkronizasyon Süresi:**
- İlk senkronizasyon: 30-60 dakika
- Günlük senkronizasyon: 10-30 dakika
- Delta sync (artırımlı): Daha hızlı

**Network Trafiği:**
| Senkronizasyon Tipi | Tahmini Trafik |
|---------------------|----------------|
| İlk Senkronizasyon | 500 MB - 2 GB |
| Günlük Senkronizasyon | 50-200 MB |
| Tanım Güncellemeleri | 100-500 MB |

**En İyi Uygulamalar:**

**Üretim Ortamı için:**
```
✅ Otomatik senkronizasyon
⏰ Saat: 02:00 - 04:00 arası (Gece saatleri)
📊 Frekans: Günde 1 kez
```

**Test Ortamı için:**
```
⚠️ Manuel senkronizasyon
📅 İhtiyaç anında tetikleme
🧪 Kontrollü güncelleme
```

**Çoklu WSUS Sunucusu:**
```
📍 Ana Sunucu: 02:00 (Microsoft'tan)
📍 Alt Sunucular: 04:00 (Ana sunucudan)
```

**PowerShell ile Zamanlama Ayarları:**
```powershell
# Günlük otomatik senkronizasyon (02:00)
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()
$subscription.SynchronizeAutomatically = $true
$subscription.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 2)
$subscription.NumberOfSynchronizationsPerDay = 1
$subscription.Save()

# Manuel senkronizasyon
$subscription.SynchronizeAutomatically = $false
$subscription.Save()

# Hemen senkronizasyon başlat
$subscription.StartSynchronization()

# Senkronizasyon durumunu kontrol et
$subscription.GetSynchronizationStatus()
```

**Zamanlama Önerileri:**

**Gece Saatleri Avantajları:**
- Düşük ağ trafiği
- Kullanıcılar etkilenmez
- Sunucu yükü düşük
- Patch Tuesday sonrası güncellemeler

**Çalışma Saatleri Dezavantajları:**
- Yüksek ağ yükü
- Kullanıcı deneyimi etkilenir
- Sunucu performansı düşer

**Özel Senaryolar:**

**24/7 Operasyon:**
- Düşük kullanım saatlerini belirleyin
- Birden fazla senkronizasyon penceresi
- Coğrafi lokasyon bazlı zamanlama

**Sınırlı Bant Genişliği:**
- Gece saatleri zorunlu
- Günde 1 senkronizasyon
- Express files devre dışı

**Senkronizasyon İzleme:**
```powershell
# Son senkronizasyon zamanı
$wsus.GetSubscription().LastSynchronizationTime

# Sonraki zamanlanmış senkronizasyon
$wsus.GetSubscription().GetNextScheduledSync()

# Senkronizasyon geçmişi
Get-WsusServer | Get-WsusSubscription | Select-Object LastSynchronizationTime, LastSynchronizationResult
```

**Önemli Notlar:**
- 💡 Otomatik senkronizasyon üretim ortamı için **şiddetle önerilir**
- ⚠️ İlk kurulumda manuel senkronizasyon yapıp sonra otomatiğe geçilebilir
- 📅 Patch Tuesday: Her ayın ikinci Salı günü Microsoft güncelleme yayınlar
- ⏰ Senkronizasyon zamanını Patch Tuesday + 1 gün sonrasına ayarlayın

✅ **"Next"** butonuna tıklayarak devam edin.

---

### Adım 13: Update Services Management Console

![Adım 13: Update Services Console](Images/13.png)

**WSUS Management Console Ana Ekranı:**

**Sol Panel - Update Services Yapısı:**

```
Update Services
└── DOMAIN
    ├── Updates
    │   ├── All Updates
    │   ├── Critical Updates
    │   ├── Security Updates
    │   └── WSUS Updates
    ├── Computers
    │   ├── All Computers
    │   └── Unassigned Computers
    ├── Downstream Servers
    ├── Synchronizations
    └── Reports
```

**Options (Seçenekler) Menüsü:**

**1. Update Source and Proxy Server**
- **Açıklama:** Microsoft Update veya üst seviye WSUS sunucu seçimi
- **Kullanım:** Hiyerarşik WSUS yapılandırması
- **Proxy Ayarları:** Kurum içi proxy yapılandırması

**Teknik Detaylar:**
```powershell
# Update kaynağını ayarlama
Set-WsusServerSynchronization -SyncFromMU

# Proxy ayarları
$wsus = Get-WsusServer
$config = $wsus.GetConfiguration()
$config.ProxyName = "proxy.domain.com"
$config.ProxyServerPort = 8080
$config.Save()
```

**2. Products and Classifications**
- **Açıklama:** Güncellenecek ürünler ve güncelleme türleri
- **Kullanım:** İhtiyaca göre ürün/sınıflandırma ekleme/çıkarma
- **Disk Yönetimi:** Gereksiz ürünleri kaldırarak alan tasarrufu

**Teknik Detaylar:**
```powershell
# Seçili ürünleri görüntüle
Get-WsusProduct | Where-Object {$_.Product.ProductState -eq "Enabled"}

# Yeni ürün ekle
Get-WsusProduct -TitleIncludes "Windows Server 2025" | Set-WsusProduct
```

**3. Update Files and Languages**
- **Açıklama:** Güncelleme dosyalarının depolanma konumu ve dil seçimi
- **Kullanım:** Disk konumu değiştirme, dil ekleme/çıkarma
- **Express Files:** Hızlı kurulum dosyaları (daha fazla disk alanı)

**Teknik Detaylar:**
```powershell
# Content dizinini değiştirme
$wsus = Get-WsusServer
$config = $wsus.GetConfiguration()
$config.LocalContentCachePath = "D:\WSUS"
$config.Save()

# Dil ayarları
$config.AllUpdateLanguagesEnabled = $false
$config.SetEnabledUpdateLanguages("en", "tr")
$config.Save()
```

**4. Synchronization Schedule**
- **Açıklama:** Otomatik veya manuel senkronizasyon zamanlaması
- **Kullanım:** Günlük senkronizasyon saati ayarlama
- **Önerilen:** Gece 02:00-04:00 arası

**Teknik Detaylar:**
```powershell
# Senkronizasyon zamanlaması
$subscription = $wsus.GetSubscription()
$subscription.SynchronizeAutomatically = $true
$subscription.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 2)
$subscription.NumberOfSynchronizationsPerDay = 1
$subscription.Save()
```

**5. Automatic Approvals**
- **Açıklama:** Belirli gruplar için otomatik güncelleme onayı
- **Kullanım:** Test grupları için otomatik onay kuralları
- **Dikkat:** Üretim sistemlerinde dikkatli kullanılmalı

**Teknik Detaylar:**
```powershell
# Otomatik onay kuralı oluşturma
$rule = $wsus.GetInstallApprovalRules() | Where-Object {$_.Name -eq "Test Group Auto Approval"}
if (-not $rule) {
    $rule = $wsus.CreateInstallApprovalRule("Test Group Auto Approval")
    $rule.SetUpdateClassifications(@("Critical Updates", "Security Updates"))
    $rule.SetComputerTargetGroups(@("Test Computers"))
    $rule.Enabled = $true
    $rule.Save()
}
```

**6. Computers**
- **Açıklama:** İstemci bilgisayarları gruplara atama
- **Kullanım:** Departman, lokasyon veya rol bazlı gruplandırma
- **Hedefleme:** Group Policy ile otomatik grup ataması

**Teknik Detaylar:**
```powershell
# Bilgisayar grubu oluşturma
$wsus.CreateComputerTargetGroup("Production Servers")
$wsus.CreateComputerTargetGroup("Test Computers")
$wsus.CreateComputerTargetGroup("Workstations")

# Grupları listele
$wsus.GetComputerTargetGroups() | Select-Object Name, Id
```

**7. Server Cleanup Wizard**
- **Açıklama:** Eski bilgisayar kayıtları, güncellemeler ve dosyaları temizleme
- **Kullanım:** Aylık bakım için önerilir
- **Disk Tasarrufu:** 20-50 GB alan kazanımı mümkün

**Teknik Detaylar:**
```powershell
# Server Cleanup Wizard işlemleri
$cleanupScope = New-Object Microsoft.UpdateServices.Administration.CleanupScope

# Eski bilgisayarları temizle
$cleanupScope.CleanupObsoleteComputers = $true

# Kullanılmayan güncellemeleri temizle
$cleanupScope.CleanupUnneededContentFiles = $true

# Eski güncelleme revizyonlarını temizle
$cleanupScope.DeclineExpiredUpdates = $true

# Temizleme işlemini başlat
$wsus.GetCleanupManager().PerformCleanup($cleanupScope)
```

**8. Reporting Rollup**
- **Açıklama:** Alt seviye WSUS sunucularından raporları toplama
- **Kullanım:** Çoklu WSUS hiyerarşisinde merkezi raporlama
- **Gereksinim:** Downstream WSUS sunucuları olmalı

**Teknik Detaylar:**
```powershell
# Rapor toplama ayarları
$config = $wsus.GetConfiguration()
$config.ServerId = [Guid]::NewGuid()
$config.UpstreamWsusServerName = "upstream-wsus.domain.com"
$config.Save()
```

**9. E-Mail Notifications**
- **Açıklama:** Yeni güncellemeler ve durum raporları için e-posta bildirimleri
- **Kullanım:** Proaktif izleme ve uyarılar
- **SMTP Gereksinimi:** SMTP sunucu yapılandırması gerekli

**Teknik Detaylar:**
```powershell
# E-posta bildirim ayarları
$notification = $wsus.GetEmailNotificationConfiguration()
$notification.SmtpHostName = "smtp.domain.com"
$notification.SenderEmailAddress = "wsus@domain.com"
$notification.SenderDisplayName = "WSUS Server"
$notification.Save()

# Bildirim gönder
$notification.SendTestEmail("admin@domain.com")
```

**10. Microsoft Update Improvement Program**
- **Açıklama:** Microsoft'un WSUS kalitesini artırmak için anonim veri toplama
- **Kullanım:** Opsiyonel katılım
- **Gizlilik:** Hassas veri paylaşılmaz

**11. Personalization**
- **Açıklama:** Konsol görünüm özelleştirmeleri
- **Kullanım:** Downstream server verileri, To-Do listesi, hata gösterimi
- **Kullanıcı Deneyimi:** Admin tercihlerine göre özelleştirme

**12. WSUS Server Configuration Wizard**
- **Açıklama:** Tüm temel ayarların tek sihirbazdan yapılandırılması
- **Kullanım:** İlk kurulum sonrası yeniden yapılandırma
- **Kolaylık:** Adım adım rehberli yapılandırma

**Sağ Panel - Actions (Eylemler):**

- **Options:** Yukarıdaki seçeneklere erişim
- **Search...:** Güncelleme arama
- **View:** Görünüm seçenekleri
- **New Window from Here:** Yeni konsol penceresi
- **Refresh:** Verileri yenile
- **Help:** Yardım dokümantasyonu

**Kurulum Tamamlandı! 🎉**

✅ WSUS sunucusu artık güncellemeleri yönetebilir durumdadır.

**İlk Senkronizasyonu Başlatma:**
```powershell
# İlk senkronizasyonu manuel başlat
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()
$subscription.StartSynchronization()

# Senkronizasyon ilerlemesini izle
while ($subscription.GetSynchronizationStatus() -eq "Running") {
    Write-Host "Senkronizasyon devam ediyor..."
    Start-Sleep -Seconds 30
    $progress = $subscription.GetSynchronizationProgress()
    Write-Host "İlerleme: $($progress.TotalItems) / $($progress.ProcessedItems)"
}
```

---

## 🔧 Kurulum Sonrası Ekstra Özellikler

### 1. İstemci Bilgisayar Yapılandırması (Group Policy)

**GPO Ayarları:**
```
Computer Configuration
└── Policies
    └── Administrative Templates
        └── Windows Components
            └── Windows Update
```

**Gerekli Ayarlar:**
1. **Configure Automatic Updates**
   - Enabled
   - Option: 4 - Auto download and schedule install

2. **Specify intranet Microsoft update service location**
   - Enabled
   - Intranet update service: `http://wsus-server:8530`
   - Intranet statistics server: `http://wsus-server:8530`

3. **Enable client-side targeting**
   - Enabled
   - Target group name: `Production Servers` veya `Workstations`

**PowerShell ile GPO Ayarları:**
```powershell
# WSUS sunucu adresini registry'ye yazma
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wsusServer = "http://wsus-server:8530"

New-ItemProperty -Path $registryPath -Name "WUServer" -Value $wsusServer -Force
New-ItemProperty -Path $registryPath -Name "WUStatusServer" -Value $wsusServer -Force

# Otomatik güncelleme ayarları
$auPath = "$registryPath\AU"
New-ItemProperty -Path $auPath -Name "UseWUServer" -Value 1 -Force
New-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Force

# İstemci tarafında grup hedefleme
New-ItemProperty -Path $registryPath -Name "TargetGroup" -Value "Production Servers" -Force
New-ItemProperty -Path $registryPath -Name "TargetGroupEnabled" -Value 1 -Force

# Ayarları uygula
gpupdate /force
wuauclt /detectnow /reportnow
```

### 2. Update Yönetimi ve Onaylama

**Manuel Onay Süreci:**
1. **Updates** → **All Updates**
2. Filter: **Approval: Unapproved**, **Status: Needed**
3. Güncellemeyi seç → **Approve**
4. Hedef grubu seç → **Approved for Install**

**PowerShell ile Toplu Onay:**
```powershell
# Kritik güncellemeleri test grubuna onayla
$wsus = Get-WsusServer
$testGroup = $wsus.GetComputerTargetGroups() | Where-Object {$_.Name -eq "Test Computers"}

Get-WsusUpdate -Approval Unapproved -Classification "Critical Updates" | 
    ForEach-Object {
        $_.Approve("Install", $testGroup)
    }

# Güvenlik güncellemelerini onayla
Get-WsusUpdate -Approval Unapproved -Classification "Security Updates" | 
    ForEach-Object {
        $_.Approve("Install", $testGroup)
    }
```

### 3. Raporlama ve İzleme

**Yerleşik Raporlar:**
- **Update Status Summary:** Genel güncelleme durumu
- **Computer Status Summary:** Bilgisayar durumu özeti
- **Synchronization Results:** Senkronizasyon sonuçları
- **Update Detailed Status:** Detaylı güncelleme durumu

**PowerShell ile Raporlama:**
```powershell
# Güncelleme özet raporu
$wsus = Get-WsusServer
$wsus.GetUpdateSummary() | Format-Table

# Bilgisayar durumu raporu
$wsus.GetComputerTargets() | 
    Select-Object FullDomainName, LastReportedStatusTime, LastSyncTime |
    Format-Table -AutoSize

# Başarısız güncellemeleri listele
Get-WsusUpdate -Approval Approved | 
    Where-Object {$_.GetUpdateInstallationInfoPerComputerTarget().FailedCount -gt 0} |
    Select-Object Title, @{N="FailedCount";E={$_.GetUpdateInstallationInfoPerComputerTarget().FailedCount}}
```

### 4. Bakım ve Optimizasyon

**Haftalık Bakım:**
```powershell
# WSUS servisini yeniden başlat
Restart-Service WsusService

# IIS uygulama havuzunu geri dönüştür
Restart-WebAppPool -Name "WsusPool"
```

**Aylık Bakım:**
```powershell
# Server Cleanup Wizard çalıştır
$cleanupScope = New-Object Microsoft.UpdateServices.Administration.CleanupScope
$cleanupScope.CleanupObsoleteComputers = $true
$cleanupScope.CleanupObsoleteUpdates = $true
$cleanupScope.CleanupUnneededContentFiles = $true
$cleanupScope.CompressUpdates = $true
$cleanupScope.DeclineExpiredUpdates = $true
$cleanupScope.DeclineSupersededUpdates = $true

$wsus = Get-WsusServer
$cleanupManager = $wsus.GetCleanupManager()
$cleanupResults = $cleanupManager.PerformCleanup($cleanupScope)

Write-Host "Temizleme Sonuçları:"
Write-Host "Silinen eski bilgisayarlar: $($cleanupResults.ObsoleteComputersDeleted)"
Write-Host "Silinen güncellemeler: $($cleanupResults.ObsoleteUpdatesDeleted)"
Write-Host "Kaldırılan dosyalar: $($cleanupResults.DiskSpaceFreed) MB"
```

**Veritabanı Bakımı:**
```powershell
# Veritabanı indeksleme
wsusutil.exe deleteunneededrevisions

# Veritabanı sıkıştırma
$wsus = Get-WsusServer
$database = $wsus.GetDatabase()
$database.Reindex()
```

---

## 🛠️ Sık Karşılaşılan Sorunlar ve Çözümler

### 1. Senkronizasyon Sorunları

**Belirtiler:**
- "The synchronization with the upstream server or Microsoft Update was canceled."
- Senkronizasyon tamamlanamıyor
- "Connection timeout" hataları

**Çözüm:**
```powershell
# Veritabanı indekslerini yeniden oluştur
wsusutil.exe deleteunneededrevisions

# Veritabanı bakımını çalıştır
$wsus = Get-WsusServer
$database = $wsus.GetDatabase()
$database.PerformMaintenance([Microsoft.UpdateServices.Administration.MaintenanceOperation]::ReIndexDatabase)

# SQL Server sorgu optimizasyonu (WID için)
sqlcmd -S np:\\.\pipe\MICROSOFT##WID\tsql\query -E -Q "USE SUSDB; EXEC sp_updatestats;"

# IIS application pool memory limitini artır
Import-Module WebAdministration
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name recycling.periodicRestart.memory -Value 0
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name processModel.maxProcesses -Value 4
```

### 5. Disk Alanı Dolması

**Belirtiler:**
- "Insufficient disk space" uyarıları
- WSUS servisi başlamıyor
- Güncelleme indirme başarısız

**Çözüm:**
```powershell
# Disk alanını kontrol et
Get-Volume -DriveLetter C | Select-Object DriveLetter, SizeRemaining

# Server Cleanup Wizard çalıştır
$cleanupScope = New-Object Microsoft.UpdateServices.Administration.CleanupScope
$cleanupScope.CleanupObsoleteComputers = $true
$cleanupScope.CleanupObsoleteUpdates = $true
$cleanupScope.CleanupUnneededContentFiles = $true
$cleanupScope.DeclineExpiredUpdates = $true
$cleanupScope.DeclineSupersededUpdates = $true

$wsus = Get-WsusServer
$cleanupManager = $wsus.GetCleanupManager()
$cleanupResults = $cleanupManager.PerformCleanup($cleanupScope)

# Eski güncelleme dosyalarını temizle
Remove-Item "C:\WSUS\WsusContent\*" -Recurse -Force -ErrorAction SilentlyContinue

# Gereksiz ürünleri kaldır
Get-WsusProduct | Where-Object {$_.Product.Title -like "*Windows 7*"} | Set-WsusProduct -Disable

# Express installation files'ı devre dışı bırak
$config = $wsus.GetConfiguration()
$config.DownloadExpressPackages = $false
$config.Save()
```

### 6. SSL/HTTPS Sertifika Sorunları

**Belirtiler:**
- "Certificate error" mesajları
- İstemciler HTTPS üzerinden bağlanamıyor

**Çözüm:**
```powershell
# Self-signed sertifika oluştur
$cert = New-SelfSignedCertificate -DnsName "wsus-server.domain.com" `
    -CertStoreLocation "cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(5)

# Sertifikayı IIS'e bağla
$binding = Get-WebBinding -Name "WSUS Administration" -Protocol https
if ($null -eq $binding) {
    New-WebBinding -Name "WSUS Administration" -Protocol https -Port 8531
}
$binding = Get-WebBinding -Name "WSUS Administration" -Protocol https -Port 8531
$binding.AddSslCertificate($cert.GetCertHashString(), "my")

# İstemcilere sertifikayı dağıt (GPO ile)
Export-Certificate -Cert $cert -FilePath "C:\WSUS-Cert.cer"
```

### 7. Update Onay Sorunları

**Belirtiler:**
- Onaylanan güncellemeler yüklenmiyor
- "Waiting for install" durumunda takılı kalıyor

**Çözüm:**
```powershell
# Update durumunu kontrol et
$wsus = Get-WsusServer
Get-WsusUpdate -Approval Approved | 
    Select-Object Title, ApprovalCount, InstalledCount, NotInstalledCount |
    Format-Table -AutoSize

# İstemci tarafında güncelleme kontrolü tetikle
Invoke-WUJob -ComputerName "Client-PC" -Script {
    wuauclt /detectnow
    wuauclt /reportnow
}

# Onayları yenile
Get-WsusUpdate -Approval Approved | ForEach-Object {
    $_.Refresh()
}
```

### 8. Performance Sorunları

**Belirtiler:**
- Konsol yavaş çalışıyor
- Raporlar uzun sürede yükleniyor
- Yüksek CPU/Memory kullanımı

**Çözüm:**
```powershell
# IIS Application Pool ayarlarını optimize et
Import-Module WebAdministration

# Queue Length artır
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name queueLength -Value 2000

# Idle Timeout artır
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name processModel.idleTimeout -Value "00:20:00"

# Recycling ayarları
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name recycling.periodicRestart.time -Value "00:00:00"
Set-ItemProperty -Path "IIS:\AppPools\WsusPool" -Name recycling.periodicRestart.requests -Value 0

# WsusPool restart
Restart-WebAppPool -Name "WsusPool"

# Veritabanı optimizasyonu
$wsus = Get-WsusServer
$database = $wsus.GetDatabase()
$database.Reindex()
```

---

## 📊 İzleme ve Raporlama

### PowerShell ile Detaylı Raporlama

**1. Genel Durum Raporu:**
```powershell
$wsus = Get-WsusServer
$computerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

Write-Host "=== WSUS Server Durumu ===" -ForegroundColor Cyan
Write-Host "Sunucu Adı: $($wsus.Name)"
Write-Host "Port: $($wsus.PortNumber)"
Write-Host "Versiyon: $($wsus.Version)"

Write-Host "`n=== Bilgisayar İstatistikleri ===" -ForegroundColor Cyan
$computers = $wsus.GetComputerTargets($computerScope)
Write-Host "Toplam Bilgisayar: $($computers.Count)"
Write-Host "Online: $(($computers | Where-Object {$_.LastReportedStatusTime -gt (Get-Date).AddDays(-7)}).Count)"
Write-Host "Offline: $(($computers | Where-Object {$_.LastReportedStatusTime -lt (Get-Date).AddDays(-7)}).Count)"

Write-Host "`n=== Güncelleme İstatistikleri ===" -ForegroundColor Cyan
$updates = $wsus.GetUpdates($updateScope)
Write-Host "Toplam Güncelleme: $($updates.Count)"
Write-Host "Onaylanan: $(($updates | Where-Object {$_.IsApproved}).Count)"
Write-Host "Declined: $(($updates | Where-Object {$_.IsDeclined}).Count)"

Write-Host "`n=== Son Senkronizasyon ===" -ForegroundColor Cyan
$subscription = $wsus.GetSubscription()
Write-Host "Son Senkronizasyon: $($subscription.LastSynchronizationTime)"
Write-Host "Sonraki Senkronizasyon: $($subscription.GetNextScheduledSync())"
Write-Host "Durum: $($subscription.GetSynchronizationStatus())"
```

**2. Bilgisayar Uyumluluk Raporu:**
```powershell
$wsus = Get-WsusServer
$computers = $wsus.GetComputerTargets()

$report = foreach ($computer in $computers) {
    $summary = $computer.GetUpdateInstallationSummary()
    [PSCustomObject]@{
        'Computer Name' = $computer.FullDomainName
        'Last Sync' = $computer.LastSyncTime
        'OS' = $computer.OSDescription
        'Needed' = $summary.NotInstalledCount
        'Installed' = $summary.InstalledCount
        'Failed' = $summary.FailedCount
        'Downloaded' = $summary.DownloadedCount
        'Compliance %' = [math]::Round(($summary.InstalledCount / ($summary.InstalledCount + $summary.NotInstalledCount)) * 100, 2)
    }
}

$report | Format-Table -AutoSize
$report | Export-Csv -Path "C:\WSUS-Reports\Compliance-$(Get-Date -Format 'yyyy-MM-dd').csv" -NoTypeInformation
```

**3. Başarısız Güncellemeler Raporu:**
```powershell
$wsus = Get-WsusServer
$updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$updateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved

$failedUpdates = $wsus.GetUpdates($updateScope) | Where-Object {
    $installInfo = $_.GetUpdateInstallationInfoPerComputerTarget()
    $installInfo.FailedCount -gt 0
}

$report = foreach ($update in $failedUpdates) {
    $installInfo = $update.GetUpdateInstallationInfoPerComputerTarget()
    [PSCustomObject]@{
        'Update Title' = $update.Title
        'Classification' = $update.UpdateClassificationTitle
        'Failed Count' = $installInfo.FailedCount
        'KB Article' = $update.KnowledgebaseArticles -join ', '
        'Release Date' = $update.CreationDate
    }
}

$report | Sort-Object 'Failed Count' -Descending | Format-Table -AutoSize
```

---

## 🔐 Güvenlik En İyi Uygulamaları

### 1. WSUS Sunucu Güvenliği

**Güvenlik Duvarı Yapılandırması:**
```powershell
# Sadece belirli ağlardan erişim izni
New-NetFirewallRule -DisplayName "WSUS HTTP - LAN Only" `
    -Direction Inbound `
    -LocalPort 8530 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress 192.168.31.0/24

New-NetFirewallRule -DisplayName "WSUS HTTPS - LAN Only" `
    -Direction Inbound `
    -LocalPort 8531 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress 192.168.31.0/24
```

**SSL/TLS Zorunlu Kullanım:**
```powershell
# HTTP'yi devre dışı bırak, sadece HTTPS kullan
$wsus = Get-WsusServer
$config = $wsus.GetConfiguration()
$config.UseSSL = $true
$config.Save()

# İstemcilerde HTTPS kullanımını zorla (GPO)
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
New-ItemProperty -Path $registryPath -Name "WUServer" -Value "https://wsus-server:8531" -Force
```

### 2. Erişim Kontrolü

**WSUS Administrators Grubu:**
```powershell
# WSUS yöneticileri için özel grup oluştur
New-ADGroup -Name "WSUS-Admins" -GroupScope Global -GroupCategory Security

# Kullanıcıları ekle
Add-ADGroupMember -Identity "WSUS-Admins" -Members "user1", "user2"

# WSUS Console erişimi için izin ver
$wsus = Get-WsusServer
$wsus.GetConfiguration().ServerRole = "UpdateServer"
```

### 3. Yedekleme Stratejisi

**WSUS Veritabanı Yedeği:**
```powershell
# WID veritabanı yedeği
$backupPath = "D:\Backups\WSUS"
New-Item -Path $backupPath -ItemType Directory -Force

# Veritabanını dışa aktar
$date = Get-Date -Format "yyyy-MM-dd"
sqlcmd -S np:\\.\pipe\MICROSOFT##WID\tsql\query -E `
    -Q "BACKUP DATABASE SUSDB TO DISK='$backupPath\SUSDB-$date.bak' WITH FORMAT"

# Content klasörünü yedekle
$contentBackup = "$backupPath\Content-$date"
robocopy "C:\WSUS\WsusContent" $contentBackup /MIR /Z /R:3 /W:10
```

**Yapılandırma Yedeği:**
```powershell
# WSUS yapılandırmasını dışa aktar
$wsus = Get-WsusServer
$config = $wsus.GetConfiguration()

$configBackup = @{
    UpdateSource = $config.SyncFromMicrosoftUpdate
    ProxySettings = $config.ProxyName
    ContentPath = $config.LocalContentCachePath
    Languages = $config.GetEnabledUpdateLanguages()
    Products = (Get-WsusProduct | Where-Object {$_.Product.ProductState -eq "Enabled"}).Product.Title
    Classifications = (Get-WsusClassification | Where-Object {$_.Classification.IsSubscribed}).Classification.Title
}

$configBackup | ConvertTo-Json | Out-File "D:\Backups\WSUS\Config-$(Get-Date -Format 'yyyy-MM-dd').json"
```

---

## 📈 Performans İyileştirmeleri

### 1. IIS Optimizasyonu

```powershell
Import-Module WebAdministration

# Connection limits artır
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.applicationHost/sites/site[@name='WSUS Administration']/limits" `
    -Name "maxConnections" -Value 4294967295

# Request timeout artır
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/WSUS Administration" `
    -Filter "system.web/httpRuntime" `
    -Name "executionTimeout" -Value 7200

# Max request length artır
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/WSUS Administration" `
    -Filter "system.web/httpRuntime" `
    -Name "maxRequestLength" -Value 4194304
```

### 2. SQL/WID Optimizasyonu

```powershell
# Veritabanı bakım planı
$maintenanceScript = @"
USE SUSDB;
-- İndeks yeniden oluşturma
EXEC sp_MSforeachtable 'ALTER INDEX ALL ON ? REBUILD';
-- İstatistik güncelleme
EXEC sp_updatestats;
-- Log dosyası temizliği
DBCC SHRINKFILE (SUSDB_log, 1);
"@

sqlcmd -S np:\\.\pipe\MICROSOFT##WID\tsql\query -E -Q $maintenanceScript
```

### 3. Disk I/O İyileştirme

```powershell
# Content klasörü için disk önbelleğini optimize et
fsutil behavior set disablelastaccess 1

# WSUS klasörü için 8.3 adlandırmayı devre dışı bırak
fsutil 8dot3name set C:\WSUS 1

# Disk tamlama işlemi
Optimize-Volume -DriveLetter C -Defrag -Verbose
```

---

## 🚀 İleri Seviye Yapılandırmalar

### 1. Hiyerarşik WSUS (Upstream/Downstream)

**Upstream Server (Ana WSUS):**
```powershell
# Microsoft Update'ten güncelleme al
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()
$subscription.SyncFromMicrosoftUpdate = $true
$subscription.Save()
```

**Downstream Server (Alt WSUS):**
```powershell
# Upstream WSUS'tan güncelleme al
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()
$subscription.SyncFromMicrosoftUpdate = $false
$subscription.SetUpstreamWsusServer("upstream-wsus.domain.com", $false, 8530)
$subscription.Save()

# Replica mode (tam kopya)
$config = $wsus.GetConfiguration()
$config.IsReplicaServer = $true
$config.Save()
```

### 2. PowerShell ile Otomasyon

**Günlük Otomatik Bakım Scripti:**
```powershell
# DailyWSUSMaintenance.ps1
[CmdletBinding()]
param(
    [string]$LogPath = "C:\WSUS-Logs\Maintenance-$(Get-Date -Format 'yyyy-MM-dd').log"
)

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogPath -Append
}

try {
    Write-Log "=== WSUS Günlük Bakım Başlıyor ==="
    
    # 1. Senkronizasyon durumu kontrol
    Write-Log "Senkronizasyon durumu kontrol ediliyor..."
    $wsus = Get-WsusServer
    $subscription = $wsus.GetSubscription()
    $syncStatus = $subscription.GetSynchronizationStatus()
    Write-Log "Senkronizasyon Durumu: $syncStatus"
    
    # 2. Veritabanı bakımı
    Write-Log "Veritabanı bakımı başlıyor..."
    wsusutil.exe deleteunneededrevisions
    Write-Log "Gereksiz revizyonlar silindi"
    
    # 3. IIS App Pool recycle
    Write-Log "IIS Application Pool yeniden başlatılıyor..."
    Restart-WebAppPool -Name "WsusPool"
    Write-Log "WsusPool yeniden başlatıldı"
    
    # 4. Disk alanı kontrolü
    Write-Log "Disk alanı kontrol ediliyor..."
    $volume = Get-Volume -DriveLetter C
    $freeSpaceGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
    Write-Log "Boş Disk Alanı: $freeSpaceGB GB"
    
    if ($freeSpaceGB -lt 20) {
        Write-Log "UYARI: Düşük disk alanı! Temizlik yapılıyor..."
        $cleanupScope = New-Object Microsoft.UpdateServices.Administration.CleanupScope
        $cleanupScope.DeclineSupersededUpdates = $true
        $cleanupScope.CleanupUnneededContentFiles = $true
        $cleanupManager = $wsus.GetCleanupManager()
        $cleanupResults = $cleanupManager.PerformCleanup($cleanupScope)
        Write-Log "Temizlik tamamlandı. Kazanılan alan: $($cleanupResults.DiskSpaceFreed) MB"
    }
    
    Write-Log "=== WSUS Günlük Bakım Tamamlandı ==="
    
} catch {
    Write-Log "HATA: $($_.Exception.Message)"
}
```

**Zamanlanmış Görev Oluşturma:**
```powershell
# Scheduled Task oluştur
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\DailyWSUSMaintenance.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At "03:00AM"

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "WSUS Daily Maintenance" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "WSUS günlük bakım işlemleri"
```

### 3. Email Bildirimleri

```powershell
# Send-WSUSReport.ps1
param(
    [string]$SmtpServer = "smtp.domain.com",
    [string]$From = "wsus@domain.com",
    [string[]]$To = @("admin@domain.com"),
    [string]$Subject = "WSUS Günlük Rapor - $(Get-Date -Format 'dd.MM.yyyy')"
)

$wsus = Get-WsusServer
$computers = $wsus.GetComputerTargets()
$updates = $wsus.GetUpdates()

$htmlBody = @"
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .warning { background-color: #ff9800; color: white; }
        .error { background-color: #f44336; color: white; }
    </style>
</head>
<body>
    <h2>WSUS Günlük Durum Raporu</h2>
    <h3>Sunucu Bilgileri</h3>
    <table>
        <tr><th>Özellik</th><th>Değer</th></tr>
        <tr><td>Sunucu Adı</td><td>$($wsus.Name)</td></tr>
        <tr><td>Port</td><td>$($wsus.PortNumber)</td></tr>
        <tr><td>Son Senkronizasyon</td><td>$($wsus.GetSubscription().LastSynchronizationTime)</td></tr>
    </table>
    
    <h3>Bilgisayar İstatistikleri</h3>
    <table>
        <tr><th>Durum</th><th>Sayı</th></tr>
        <tr><td>Toplam Bilgisayar</td><td>$($computers.Count)</td></tr>
        <tr><td>Güncelleme Bekleyen</td><td>$(($computers | Where-Object {$_.GetUpdateInstallationSummary().NotInstalledCount -gt 0}).Count)</td></tr>
        <tr class="error"><td>Başarısız Güncelleme</td><td>$(($computers | Where-Object {$_.GetUpdateInstallationSummary().FailedCount -gt 0}).Count)</td></tr>
    </table>
    
    <h3>Güncelleme İstatistikleri</h3>
    <table>
        <tr><th>Kategori</th><th>Sayı</th></tr>
        <tr><td>Onaylanan Güncellemeler</td><td>$(($updates | Where-Object {$_.IsApproved}).Count)</td></tr>
        <tr><td>Bekleyen Güncellemeler</td><td>$(($updates | Where-Object {-not $_.IsApproved -and -not $_.IsDeclined}).Count)</td></tr>
    </table>
</body>
</html>
"@

Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $htmlBody -BodyAsHtml
```

---

## 📜 Doküman Bilgileri

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 6 Kasım 2025 |
| **Versiyon** | 2.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **WSUS Versiyon** | 10.0.20348 |
| **WSUS Content** | `C:\WSUS` |
| **Database** | Windows Internal Database (WID) |
| **Lisans** | Evaluation (180 gün) |

---

## 🔗 Faydalı Kaynaklar

### Microsoft Resmi Dokümantasyon
- [WSUS Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus)
- [WSUS Best Practices](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus)
- [Patch Tuesday Information](https://docs.microsoft.com/en-us/security-updates/)

### PowerShell Cmdlet Referansları
- [Get-WsusServer](https://docs.microsoft.com/en-us/powershell/module/wsus/get-wsusserver)
- [Get-WsusUpdate](https://docs.microsoft.com/en-us/powershell/module/wsus/get-wsusupdate)
- [Approve-WsusUpdate](https://docs.microsoft.com/en-us/powershell/module/wsus/approve-wsusupdate)

### Community Resources
- [Windows Server TechNet Forum](https://social.technet.microsoft.com/Forums/en-US/home?forum=winserverwsus)
- [WSUS Package Publisher](https://wsuspackagepublisher.codeplex.com/)
- [WSUS Automated Maintenance](https://gallery.technet.microsoft.com/scriptcenter/WSUS-Automated-Maintenance-94dc4e5e)

---

## ⚠️ Önemli Notlar ve Uyarılar

### Güvenlik Uyarıları
- 🔐 **SSL/TLS Kullanımı:** Üretim ortamlarında mutlaka HTTPS kullanılmalıdır
- 🛡️ **Güvenlik Duvarı:** Sadece gerekli portlar ve ağlar için erişim açılmalıdır
- 👥 **Erişim Kontrolü:** WSUS yönetim konsoluna erişim sınırlandırılmalıdır
- 💾 **Yedekleme:** Düzenli veritabanı ve yapılandırma yedekleri alınmalıdır

### Performans Önerileri
- ⚡ **Donanım:** Minimum 8 GB RAM, SSD disk önerilir
- 📊 **Kapasite Planlaması:** 1000 istemci başına 1 GB RAM ekleyin
- 🔄 **Düzenli Bakım:** Haftalık IIS restart, aylık veritabanı optimizasyonu
- 📦 **Disk Alanı:** Başlangıçta 200 GB, büyüme için ek alan planlayın

### Test ve Doğrulama
- ✅ **Test Ortamı:** Kritik güncellemeleri önce test ortamında doğrulayın
- 🧪 **Pilot Grup:** Yeni güncellemeleri önce pilot gruba uygulayın
- 📋 **Geri Alma Planı:** Her güncelleme için rollback stratejisi hazırlayın
- 📊 **İzleme:** Güncelleme sonrası sistem durumunu yakından takip edin

### Bakım ve İzleme
- 📅 **Günlük:** Senkronizasyon durumu, disk alanı kontrolü
- 📅 **Haftalık:** Başarısız güncellemeler, offline istemciler
- 📅 **Aylık:** Veritabanı bakımı, temizlik işlemleri, kapasite planlaması
- 📅 **Üç Aylık:** Güvenlik denetimi, performans değerlendirmesi

---

## 📧 Destek ve İletişim

**Teknik Destek:**
- 📧 Email: mserifselen@gmail.com
- 🔗 GitHub: [https://github.com/serifselen](https://github.com/serifselen)
- 📂 Repository: [Windows-Server-Update-Services-WSUS-Kurulum](https://github.com/serifselen/Windows-Server-Update-Services-WSUS-Kurulum)

