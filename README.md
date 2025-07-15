# BitLockerPolicyScopes
This PowerShell script offers three different methods for analyzing the scopes where BitLocker policies are applied.

<img width="502" height="236" alt="image" src="https://github.com/user-attachments/assets/8c8e7ac9-2e64-4739-a72a-c5b1dc75a486" />

This PowerShell script offers three different methods for analyzing the scopes where BitLocker policies are applied:

Basic Functions:
1. Get-BitLockerPolicyScopes
Scans all GPOs in the domain
Identifies GPOs that contain BitLocker policies
Shows which OUs each GPO is linked to
Calculates the number of affected computers
2. Get-ComputerBitLockerPolicyScope
Analyzes BitLocker policies applied to a specific computer
Shows which GPOs are applied
Checks policy settings in the registry
3. Get-BitLockerPolicyDistribution
Shows the BitLocker policy scope for all OUs in the domain
Calculates the scope ratio
Lists which OUs have BitLocker policies
Output Information:
GPO Name and ID
Connected OUs
Number of affected computers
Policy creation/modification dates
Scope ratio percentage
Usage Examples:

powershell
# List all BitLocker policy scopes
Get-BitLockerPolicyScopes

# Save results to CSV
Get-BitLockerPolicyScopes -OutputPath "C:\BitLocker-Scopes.csv"

# Check policies on a specific computer
Get-ComputerBitLockerPolicyScope -ComputerName "PC001"

# Show distribution in the domain
Get-BitLockerPolicyDistribution
Requirements:
Domain Admin permissions
Group Policy Management module
Active Directory module
PowerShell Remoting enabled
This script analyzes and reports in detail which BitLocker policies are applied in which scopes.

BitLocker politikalarının uygulandığı scope'ları (kapsamları) almak için PowerShell scripti yazabilirim. İşte Group Policy ve BitLocker scope'larını analiz eden detaylı bir script:Bu PowerShell scripti, BitLocker politikalarının uygulandığı scope'ları (kapsamları) analiz etmek için üç farklı yöntem sunuyor:

## **Temel Fonksiyonlar:**

### **1. `Get-BitLockerPolicyScopes`**
- Domain'deki tüm GPO'ları tarar
- BitLocker politikası içeren GPO'ları tespit eder
- Her GPO'nun hangi OU'lara bağlı olduğunu gösterir
- Etkilenen bilgisayar sayısını hesaplar

### **2. `Get-ComputerBitLockerPolicyScope`**
- Belirli bir bilgisayarda uygulanan BitLocker politikalarını analiz eder
- Hangi GPO'ların uygulandığını gösterir
- Registry'den politika ayarlarını kontrol eder

### **3. `Get-BitLockerPolicyDistribution`**
- Domain'deki tüm OU'ların BitLocker politika kapsamını gösterir
- Kapsam oranını hesaplar
- Hangi OU'larda BitLocker politikası olduğunu listeler

## **Çıktı Bilgileri:**
- **GPO Adı ve ID'si**
- **Bağlı OU'lar**
- **Etkilenen bilgisayar sayısı**
- **Politika oluşturma/değiştirme tarihleri**
- **Kapsam oranı yüzdesi**

## **Kullanım Örnekleri:**
```powershell
# Tüm BitLocker politika scope'larını listele
Get-BitLockerPolicyScopes

# Sonuçları CSV'ye kaydet
Get-BitLockerPolicyScopes -OutputPath "C:\BitLocker-Scopes.csv"

# Belirli bilgisayardaki politikaları kontrol et
Get-ComputerBitLockerPolicyScope -ComputerName "PC001"

# Domain'deki dağılımı göster
Get-BitLockerPolicyDistribution
```

## **Gereksinimler:**
- **Domain Admin** yetkileri
- **Group Policy Management** modülü
- **Active Directory** modülü
- **PowerShell Remoting** aktif

Bu script, BitLocker politikalarının hangi kapsamlarda uygulandığını detaylı bir şekilde analiz eder ve raporlar.
