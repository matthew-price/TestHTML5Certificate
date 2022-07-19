
Function CheckCertificate{
    param($certToCheck)
    $errorCount = 0
    $certToCheck.Thumbprint
    $hasPrivateKey = $certToCheck.HasPrivateKey
    if(!$hasPrivateKey){
        $errorCount++
        Write-Warning "We couldn't detect a private key installed for this certificate. This certifiate can't be used."
    }

    $certHasExpired = $certToCheck.NotAfter -lt (Get-Date)
    if($certHasExpired){
        $errorCount++
        Write-Warning "This certificate has expired. This certificate can't be used"
    }

    $certNotValidYet = $certToCheck.NotBefore -gt (Get-Date)
    if($certNotValidYet){
        $errorCount++
        Write-Warning "This certificate isn't yet valid. This certificate can't be used"
    }

    $certMissingKeyUsage = $certToCheck.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1"
    if(!$certMissingKeyUsage){
        $errorCount++
        Write-Warning "This certificate appears to be missing the `"Server Authentication`" Enhanced Key Usage. This certificate can't be used"
    }

    $certMissingDnsName = $certToCheck.DnsNameList -contains ([system.net.dns]::GetHostByName("localhost")).hostname
    if(!$certMissingDnsName){
        $errorCount++
        Write-Warning "This certificate doesn't appear to match the hostname of the machine. This certificate can't be used"
    }

    $errorCount
}




$selectedCert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -Property * | Out-GridView -PassThru -Title "Select the certificate to use for PSM"
CheckCertificate $selectedCert
