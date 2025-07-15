# BitLocker Policy Scope'larını analiz eden PowerShell scripti

# Yöntem 1: Group Policy Management Console (GPMC) kullanarak
function Get-BitLockerPolicyScopes {
    param(
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$OutputPath = $null
    )
    
    try {
        # Group Policy modülünü import et
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
        
        Write-Host "BitLocker politika scope'ları analiz ediliyor..." -ForegroundColor Yellow
        
        # Domain'deki tüm GPO'ları al
        $gpos = Get-GPO -Domain $Domain -All
        $bitlockerPolicies = @()
        
        foreach ($gpo in $gpos) {
            Write-Progress -Activity "GPO'lar taranıyor" -Status "İşleniyor: $($gpo.DisplayName)" -PercentComplete (($gpos.IndexOf($gpo) / $gpos.Count) * 100)
            
            try {
                # GPO'nun XML raporunu al
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain
                
                # BitLocker ile ilgili ayarları ara
                if ($gpoReport -match "BitLocker|FVE|Full Volume Encryption") {
                    # GPO'nun link'lerini al
                    $gpoLinks = (Get-GPO -Guid $gpo.Id -Domain $Domain).DisplayName | ForEach-Object {
                        try {
                            $links = @()
                            $gpoLinks = Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink, distinguishedName
                            
                            foreach ($link in $gpoLinks) {
                                $links += [PSCustomObject]@{
                                    LinkedOU = $link.distinguishedName
                                    GPOName = $gpo.DisplayName
                                    LinkEnabled = $true
                                }
                            }
                            return $links
                        } catch {
                            return $null
                        }
                    }
                    
                    # BitLocker ayarlarını detaylı analiz et
                    $bitlockerSettings = Get-BitLockerSettingsFromGPO -GPOId $gpo.Id -Domain $Domain
                    
                    $bitlockerPolicies += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOId = $gpo.Id
                        GPOStatus = $gpo.GpoStatus
                        CreationTime = $gpo.CreationTime
                        ModificationTime = $gpo.ModificationTime
                        LinkedOUs = $gpoLinks
                        BitLockerSettings = $bitlockerSettings
                        AffectedComputers = Get-AffectedComputers -GPOId $gpo.Id -Domain $Domain
                    }
                }
            } catch {
                Write-Warning "GPO işlenirken hata: $($gpo.DisplayName) - $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "GPO'lar taranıyor" -Completed
        
        # Sonuçları göster
        if ($bitlockerPolicies.Count -gt 0) {
            Write-Host "`nBitLocker politikası içeren GPO'lar ($($bitlockerPolicies.Count) adet):" -ForegroundColor Green
            
            foreach ($policy in $bitlockerPolicies) {
                Write-Host "`n" + "="*50 -ForegroundColor Cyan
                Write-Host "GPO Adı: $($policy.GPOName)" -ForegroundColor Yellow
                Write-Host "GPO ID: $($policy.GPOId)" -ForegroundColor Gray
                Write-Host "Durum: $($policy.GPOStatus)" -ForegroundColor Green
                Write-Host "Oluşturma: $($policy.CreationTime)" -ForegroundColor Gray
                Write-Host "Değişiklik: $($policy.ModificationTime)" -ForegroundColor Gray
                
                Write-Host "`nBağlı OU'lar:" -ForegroundColor Cyan
                if ($policy.LinkedOUs) {
                    $policy.LinkedOUs | ForEach-Object { Write-Host "  - $($_.LinkedOU)" -ForegroundColor White }
                } else {
                    Write-Host "  Hiç bağlantı bulunamadı" -ForegroundColor Red
                }
                
                Write-Host "`nEtkilenen Bilgisayar Sayısı: $($policy.AffectedComputers.Count)" -ForegroundColor Cyan
                if ($policy.AffectedComputers.Count -gt 0) {
                    Write-Host "İlk 5 bilgisayar:" -ForegroundColor Gray
                    $policy.AffectedComputers | Select-Object -First 5 | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
                }
            }
            
            # CSV'ye kaydet
            if ($OutputPath) {
                $exportData = @()
                foreach ($policy in $bitlockerPolicies) {
                    $exportData += [PSCustomObject]@{
                        GPOName = $policy.GPOName
                        GPOId = $policy.GPOId
                        GPOStatus = $policy.GPOStatus
                        LinkedOUs = ($policy.LinkedOUs | ForEach-Object { $_.LinkedOU }) -join "; "
                        AffectedComputerCount = $policy.AffectedComputers.Count
                        CreationTime = $policy.CreationTime
                        ModificationTime = $policy.ModificationTime
                    }
                }
                $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                Write-Host "`nSonuçlar kaydedildi: $OutputPath" -ForegroundColor Green
            }
        } else {
            Write-Host "BitLocker politikası içeren GPO bulunamadı." -ForegroundColor Yellow
        }
        
        return $bitlockerPolicies
    }
    catch {
        Write-Error "Hata: $($_.Exception.Message)"
    }
}

# Yöntem 2: Belirli bir bilgisayardaki BitLocker politika scope'unu kontrol etme
function Get-ComputerBitLockerPolicyScope {
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Host "Bilgisayar: $ComputerName için BitLocker politika scope'u kontrol ediliyor..." -ForegroundColor Yellow
        
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Uygulanan GPO'ları al
                $gpResult = gpresult /r /scope:computer 2>$null
                
                # BitLocker ile ilgili politikaları filtrele
                $bitlockerPolicies = @()
                
                # Registry'den BitLocker politika ayarlarını kontrol et
                $registryPaths = @{
                    "HKLM:\SOFTWARE\Policies\Microsoft\FVE" = "BitLocker Drive Encryption Policies"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" = "Group Policy Extension"
                }
                
                foreach ($regPath in $registryPaths.Keys) {
                    if (Test-Path $regPath) {
                        $keys = Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue
                        if ($keys) {
                            $bitlockerPolicies += [PSCustomObject]@{
                                PolicyType = $registryPaths[$regPath]
                                RegistryPath = $regPath
                                KeyCount = $keys.Count
                                LastModified = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).PSChildName
                            }
                        }
                    }
                }
                
                # WMI'dan Group Policy bilgilerini al
                $appliedGPOs = Get-WmiObject -Class RSOP_GPO -Namespace root\rsop\computer -ErrorAction SilentlyContinue
                
                return [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    AppliedGPOs = $appliedGPOs | Select-Object Name, GUID, AccessDenied
                    BitLockerPolicies = $bitlockerPolicies
                    PolicyRefreshTime = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine" -Name "LastGPORefreshTime" -ErrorAction SilentlyContinue).LastGPORefreshTime
                }
            } catch {
                Write-Error "Remote komut hatası: $($_.Exception.Message)"
                return $null
            }
        } -ErrorAction Stop
        
        if ($result) {
            Write-Host "`nBilgisayar: $($result.ComputerName)" -ForegroundColor Green
            Write-Host "Son GP Refresh: $($result.PolicyRefreshTime)" -ForegroundColor Gray
            
            Write-Host "`nUygulanan GPO'lar:" -ForegroundColor Cyan
            $result.AppliedGPOs | ForEach-Object {
                Write-Host "  - $($_.Name) ($($_.GUID))" -ForegroundColor White
            }
            
            Write-Host "`nBitLocker Politikaları:" -ForegroundColor Cyan
            if ($result.BitLockerPolicies.Count -gt 0) {
                $result.BitLockerPolicies | ForEach-Object {
                    Write-Host "  - $($_.PolicyType): $($_.KeyCount) anahtar" -ForegroundColor White
                }
            } else {
                Write-Host "  BitLocker politikası bulunamadı" -ForegroundColor Red
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Hata: $($_.Exception.Message)"
    }
}

# Yardımcı fonksiyonlar
function Get-BitLockerSettingsFromGPO {
    param(
        [string]$GPOId,
        [string]$Domain
    )
    
    try {
        $gpoReport = Get-GPOReport -Guid $GPOId -ReportType Xml -Domain $Domain
        $settings = @()
        
        # XML'den BitLocker ayarlarını çıkar
        if ($gpoReport -match "BitLocker") {
            $settings += "BitLocker Policies Found"
        }
        
        return $settings
    } catch {
        return @("Error reading GPO settings")
    }
}

function Get-AffectedComputers {
    param(
        [string]$GPOId,
        [string]$Domain
    )
    
    try {
        # GPO'nun bağlı olduğu OU'ları al
        $linkedOUs = Get-ADObject -Filter "gPLink -like '*$GPOId*'" -Properties gPLink
        $computers = @()
        
        foreach ($ou in $linkedOUs) {
            $ouComputers = Get-ADComputer -SearchBase $ou.DistinguishedName -Filter *
            $computers += $ouComputers
        }
        
        return $computers
    } catch {
        return @()
    }
}

# Yöntem 3: Tüm domain'deki BitLocker politika dağılımını göster
function Get-BitLockerPolicyDistribution {
    Write-Host "Domain'deki BitLocker politika dağılımı:" -ForegroundColor Yellow
    
    try {
        # Domain'deki tüm OU'ları al
        $ous = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
        $distribution = @()
        
        foreach ($ou in $ous) {
            $computers = Get-ADComputer -SearchBase $ou.DistinguishedName -Filter *
            $gpos = Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction SilentlyContinue
            
            $hasBitLockerPolicy = $false
            if ($gpos) {
                foreach ($gpo in $gpos.InheritedGpoLinks) {
                    $gpoReport = Get-GPOReport -Guid $gpo.GpoId -ReportType Xml -ErrorAction SilentlyContinue
                    if ($gpoReport -match "BitLocker") {
                        $hasBitLockerPolicy = $true
                        break
                    }
                }
            }
            
            $distribution += [PSCustomObject]@{
                OUName = $ou.Name
                OUPath = $ou.DistinguishedName
                ComputerCount = $computers.Count
                HasBitLockerPolicy = $hasBitLockerPolicy
            }
        }
        
        # Sonuçları göster
        Write-Host "`nBitLocker Politika Dağılımı:" -ForegroundColor Green
        $distribution | Format-Table -AutoSize
        
        $totalComputers = ($distribution | Measure-Object ComputerCount -Sum).Sum
        $coveredComputers = ($distribution | Where-Object { $_.HasBitLockerPolicy } | Measure-Object ComputerCount -Sum).Sum
        
        Write-Host "`nÖzet:" -ForegroundColor Cyan
        Write-Host "Toplam Bilgisayar: $totalComputers" -ForegroundColor White
        Write-Host "BitLocker Politikası Kapsamındaki: $coveredComputers" -ForegroundColor Green
        Write-Host "Kapsam Oranı: $([math]::Round(($coveredComputers / $totalComputers) * 100, 2))%" -ForegroundColor Yellow
        
        return $distribution
    } catch {
        Write-Error "Dağılım analizi hatası: $($_.Exception.Message)"
    }
}

# Kullanım örnekleri
Write-Host "BitLocker Policy Scope Analizi" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Kullanım örnekleri:"
Write-Host "1. Get-BitLockerPolicyScopes"
Write-Host "2. Get-BitLockerPolicyScopes -OutputPath 'C:\BitLocker-Scopes.csv'"
Write-Host "3. Get-ComputerBitLockerPolicyScope -ComputerName 'PC001'"
Write-Host "4. Get-BitLockerPolicyDistribution"
Write-Host ""
Write-Host "Not: Bu script Domain Admin yetkileri gerektirir." -ForegroundColor Red
Write-Host "Scripti çalıştırmak için yukarıdaki komutlardan birini kullanın." -ForegroundColor Yellow
