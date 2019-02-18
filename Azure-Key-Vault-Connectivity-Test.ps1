param (
    [String]$AppId = "",
    [String]$AppSecret = "",    
    [String]$KeyVaultName = ""
)

cls

# Clear Variables
$TestKeyVaultConnection = $null
$KeyVaultKeysResponse = $null
$KeyVaultKeysAuthURI = $null
$KeyVaultKeysAuthBody = $null
$KeyVaultKeysAuthResponse = $null
$KeyVaultKeysAccessToken = $null
$KeyVaultKeysHeaders = $null
$KeyVaultKeys = $null

# Set Variables
$AADServicePrincipalAppID = $AppId
$AADServicePrincipalAppSecret = $AppSecret
$AzureKeyVaultName = $KeyVaultName

# Get Proxy details
Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "Get-ItemProperty: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer"
Write-Host
$proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer

if ($proxies)
{
    if ($proxies -ilike "*=*")
    {
        $proxy = $proxies -replace "=","://" -split(';') | Select-Object -First 1
    }

    else
    {
        $proxy = $proxies
    }

    write-host "Proxy: $proxy"
    Write-Host

    $proxyhost = $proxy.Replace('//','').split(':')[1]
    $proxyport = $proxy.split(':')[2]

    if (!$proxyport) { $proxyport = '80' } 

    # Test network connection to Proxy
    Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "Test-NetConnection: $($proxyhost):$($proxyport)"
    Write-Host
    Try
    {
        Test-NetConnection -ComputerName $proxyhost -port $proxyport
    }
    Catch
    {
        Write-Host -BackgroundColor Red -ForegroundColor White "$($_.Exception)"
        Write-Host
        Break
    }
}

# Test network connection to Key Vault
Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "Test-NetConnection: $AzureKeyVaultName.vault.azure.net (TCP Port 443)"
Write-Host
Try
{
    #$TestKeyVaultConnection = Test-NetConnection -ComputerName "$AzureKeyVaultName.vault.azure.net" -Port 443 -InformationLevel Quiet
    If (-Not $(Test-NetConnection -ComputerName "$AzureKeyVaultName.vault.azure.net" -Port 443 -InformationLevel Quiet))
    {
        Write-Host -BackgroundColor Red -ForegroundColor White "TCP connection to $AzureKeyVaultName.vault.azure.net failed"
        Write-Host
        Break
    }
}
Catch
{
    Write-Host -BackgroundColor Red -ForegroundColor White "$($_.Exception)"
    Write-Host
    Break
}

# Call Key Vault Keys Endpoint Unauthenticated
Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "Invoke-RestMethod: https://$AzureKeyVaultName.vault.azure.net/keys?api-version=7.0 (Unauthenticated)"
Write-Host
$KeyVaultKeysException = try 
{ 
    Invoke-RestMethod -Method GET -Uri "https://$AzureKeyVaultName.vault.azure.net/keys?api-version=7.0" -Headers @{}
}
Catch
{
    If ($_.Exception.Response.StatusCode.value__ -ne 401)
    {
        Write-Host -BackgroundColor Red -ForegroundColor White "$_.Exception"
        Write-Host
        Break
    }
    $_.Exception
}

# Call Key Vault Keys Authentication Endpoint With Service Principal ID & Secret
$KeyVaultKeysAuthURI = [regex]::match($KeyVaultKeysException.Response.Headers['www-authenticate'], 'authorization="(.*?)"').Groups[1].Value
$KeyVaultKeysAuthURI += "/oauth2/token"
$KeyVaultKeysAuthBody = 'grant_type=client_credentials'
$KeyVaultKeysAuthBody += '&client_id=' + $AADServicePrincipalAppID
$KeyVaultKeysAuthBody += '&client_secret=' + [Uri]::EscapeDataString($AADServicePrincipalAppSecret)
$KeyVaultKeysAuthBody += '&resource=' + [Uri]::EscapeDataString("https://vault.azure.net")
Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "Invoke-RestMethod: $KeyVaultKeysAuthURI"
Write-Host
try
{
    $KeyVaultKeysAuthResponse = Invoke-RestMethod -Method POST -Uri $KeyVaultKeysAuthURI -Headers @{} -Body $KeyVaultKeysAuthBody
}
catch
{
    Write-Host -BackgroundColor Red -ForegroundColor White "$($_.Exception)"
    Write-Host
    Break
}

# Call Key Vault Keys Endpoint Authenticated
$KeyVaultKeysAccessToken = "Bearer " + $KeyVaultKeysAuthResponse.access_token
$KeyVaultKeysHeaders = @{"Content-Type"="application\json"; "Authorization"="$KeyVaultKeysAccessToken"}
Write-Host -BackgroundColor Yellow -ForegroundColor DarkBlue "6. Invoke-RestMethod: https://$AzureKeyVaultName.vault.azure.net/keys?api-version=7.0 (Authenticated)"
Write-Host
try
{
    $KeyVaultKeys = Invoke-RestMethod -Method "Get" -Headers $KeyVaultKeysHeaders -Uri "https://$AzureKeyVaultName.vault.azure.net/keys?api-version=7.0"  | Select-Object -ExpandProperty value
}
catch
{
    Write-Host -BackgroundColor Red -ForegroundColor White "$($_.Exception)"
    Write-Host
    Break
}

$KeyVaultKeys | FT
