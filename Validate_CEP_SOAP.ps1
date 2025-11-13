# CEP URL
$CEPUrl = "https://win2k22ca.antdom.local/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"

# Prompt for credentials
$Cred = Get-Credential
$username = $Cred.UserName
$password = $Cred.GetNetworkCredential().Password

# Generate WS-Security elements
$created = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$nonceBytes = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
$nonce = [System.Convert]::ToBase64String($nonceBytes)

function Invoke-SOAPRequest {
    param ([string]$Url, [string]$SoapBody)

    Write-Host "`nSending SOAP request to $Url ..."
    try {
        $response = Invoke-WebRequest -Uri $Url -Method POST -Body $SoapBody `
                                      -ContentType "application/soap+xml; charset=utf-8" -TimeoutSec 30

        Write-Host "✅ Response received from $Url" -ForegroundColor Green
        Write-Host "Status Code: $($response.StatusCode)"

        # Save full response
        $responseFile = "CEP_Response.xml"
        $response.Content | Out-File -FilePath $responseFile -Encoding UTF8
        Write-Host "`nFull SOAP response saved to: $responseFile" -ForegroundColor Cyan

        # Parse template names
        [xml]$xmlResponse = $response.Content
        $templates = $xmlResponse.SelectNodes("//*[local-name()='commonName']")
        if ($templates.Count -gt 0) {
            Write-Host "`nAvailable Certificate Templates:" -ForegroundColor Cyan
            foreach ($template in $templates) { Write-Host "- $($template.InnerText)" }
        } else {
            Write-Host "`nNo template names found in the response." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ SOAP request failed for $Url" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)"
    }
}

# WS-Security header
$SecurityHeader = @"
<o:Security s:mustUnderstand="1"
    xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <o:UsernameToken>
    <o:Username>$username</o:Username>
    <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$password</o:Password>
    <o:Nonce>$nonce</o:Nonce>
    <u:Created>$created</u:Created>
  </o:UsernameToken>
</o:Security>
"@

# SOAP Envelope
$CEPSoap = @"
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
    <a:To s:mustUnderstand="1">$CEPUrl</a:To>
    $SecurityHeader
  </s:Header>
  <s:Body>
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client>
        <osVersion>10.0.19041</osVersion>
        <machineName>TestMachine</machineName>
      </client>
    </GetPolicies>
  </s:Body>
</s:Envelope>
"@

# ✅ Test CEP and parse templates
Invoke-SOAPRequest -Url $CEPUrl -SoapBody $CEPSoap
