function Convert-PemToPfx {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('[System.Security.Cryptography.X509Certificates.X509Certificate2]')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$InputPath,
        [string]$KeyPath,
        [string]$OutputPath,
        [Security.Cryptography.X509Certificates.X509KeySpecFlags]$KeySpec = "AT_KEYEXCHANGE",
        [Security.SecureString]$Password,
        [string]$ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
        [switch]$Install
    )
    if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
    if ($PSBoundParameters.Debug) {
        $DebugPreference = "continue"
    }
    
    #region helper functions
    function __normalizeAsnInteger ($array) {
        $padding = $array.Length % 8
        if ($padding) {
            $array = $array[$padding..($array.Length - 1)]
        }
        [array]::Reverse($array)
        [Byte[]]$array
    }
    function __extractCert([string]$Text) {
        if ($Text -match "(?msx).*-{5}BEGIN\sCERTIFICATE-{5}(.+)-{5}END\sCERTIFICATE-{5}") {
        $keyFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        if ($Install) {
            $keyFlags += if ($StoreLocation -eq "CurrentUser") {
                [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
            } else {
                [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
            }
        }
        $RawData = [Convert]::FromBase64String($matches[1])
            try {
                New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $RawData, "", $keyFlags
            } catch {throw "The data is not valid security certificate."}
            Write-Debug "X.509 certificate is correct."
        } else {throw "Missing certificate file."}
    }
    # returns [byte[]]
    function __composePRIVATEKEYBLOB($modulus, $PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1, $Exponent2, $Coefficient) {
        Write-Debug "Calculating key length."
        $bitLen = "{0:X4}" -f $($modulus.Length * 8)
        Write-Debug "Key length is $($modulus.Length * 8) bits."
        [byte[]]$bitLen1 = Invoke-Expression 0x$([int]$bitLen.Substring(0,2))
        [byte[]]$bitLen2 = Invoke-Expression 0x$([int]$bitLen.Substring(2,2))
        [Byte[]]$PrivateKey = 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00
        [Byte[]]$PrivateKey = $PrivateKey + $bitLen1 + $bitLen2 + $PublicExponent + ,0x00 + `
            $modulus + $Prime1 + $Prime2 + $Exponent1 + $Exponent2 + $Coefficient + $PrivateExponent
        $PrivateKey
    }
    # returns RSACryptoServiceProvider for dispose purposes
    function __attachPrivateKey([Byte[]]$PrivateKey) {
        $cspParams = New-Object Security.Cryptography.CspParameters -Property @{
            ProviderName = $ProviderName
            KeyContainerName = "pspki-" + [Guid]::NewGuid().ToString()
            KeyNumber = [int]$KeySpec
        }
        if ($Install -and $StoreLocation -eq "LocalMachine") {
            $cspParams.Flags += [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
        }
        $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider $cspParams
        $rsa.ImportCspBlob($PrivateKey)
        if ($PSVersionTable.PSEdition -eq "Core") {
            Add-Type -AssemblyName "System.Security.Cryptography.X509Certificates"
            $script:Cert = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($_Cert.RawData, $rsa)

        } else {
            $script:Cert.PrivateKey = $rsa
        }
        $rsa
    }
    # returns Asn1Reader
    function __decodePkcs1($base64) {
        Write-Debug "Processing PKCS#1 RSA KEY module."
        $asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
        if ($asn.Tag -ne 48) {throw "The data is invalid."}
        $asn
    }
    # returns Asn1Reader
    function __decodePkcs8($base64) {
        Write-Debug "Processing PKCS#8 Private Key module."
        $asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
        if ($asn.Tag -ne 48) {throw "The data is invalid."}
        # version
        if (!$asn.MoveNext()) {throw "The data is invalid."}
        # algorithm identifier
        if (!$asn.MoveNext()) {throw "The data is invalid."}
        # octet string
        if (!$asn.MoveNextCurrentLevel()) {throw "The data is invalid."}
        if ($asn.Tag -ne 4) {throw "The data is invalid."}
        if (!$asn.MoveNext()) {throw "The data is invalid."}
        $asn
    }
    #endregion
    $ErrorActionPreference = "Stop"
    
    $File = Get-Item $InputPath -Force -ErrorAction Stop
    if ($KeyPath) {$Key = Get-Item $KeyPath -Force -ErrorAction Stop}
    
    # parse content
    $Text = Get-Content -Path $InputPath -Raw -ErrorAction Stop
    Write-Debug "Extracting certificate information..."
    $Cert = __extractCert $Text
    if ($Key) {$Text = Get-Content -Path $KeyPath -Raw -ErrorAction Stop}
    $asn = if ($Text -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
        __decodePkcs8 $matches[1]
    } elseif ($Text -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
        __decodePkcs1 $matches[1]
    }  else {throw "The data is invalid."}
    # private key version
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    # modulus n
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $modulus = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Modulus length: $($modulus.Length)"
    # public exponent e
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    # public exponent must be 4 bytes exactly.
    $PublicExponent = if ($asn.GetPayload().Length -eq 3) {
        ,0 + $asn.GetPayload()
    } else {
        $asn.GetPayload()
    }
    Write-Debug "PublicExponent length: $($PublicExponent.Length)"
    # private exponent d
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $PrivateExponent = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "PrivateExponent length: $($PrivateExponent.Length)"
    # prime1 p
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $Prime1 = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Prime1 length: $($Prime1.Length)"
    # prime2 q
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $Prime2 = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Prime2 length: $($Prime2.Length)"
    # exponent1 d mod (p-1)
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $Exponent1 = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Exponent1 length: $($Exponent1.Length)"
    # exponent2 d mod (q-1)
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $Exponent2 = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Exponent2 length: $($Exponent2.Length)"
    # coefficient (inverse of q) mod p
    if (!$asn.MoveNext()) {throw "The data is invalid."}
    $Coefficient = __normalizeAsnInteger $asn.GetPayload()
    Write-Debug "Coefficient length: $($Coefficient.Length)"
    # creating Private Key BLOB structure
    $PrivateKey = __composePRIVATEKEYBLOB $modulus $PublicExponent $PrivateExponent $Prime1 $Prime2 $Exponent1 $Exponent2 $Coefficient
    #region key attachment and export
    try {
        $rsaKey = __attachPrivateKey $PrivateKey
        if (![string]::IsNullOrEmpty($OutputPath)) {
            if (!$Password) {
                $Password = Read-Host -Prompt "Enter PFX password" -AsSecureString
            }
            $pfxBytes = $Cert.Export("pfx", $Password)
            if ($PsIsCore) {
                Set-Content -Path $OutputPath -Value $pfxBytes -AsByteStream
            } else {
                Set-Content -Path $OutputPath -Value $pfxBytes -Encoding Byte
            }
        }
        #endregion
        if ($Install) {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store "my", $StoreLocation
            $store.Open("ReadWrite")
            $store.Add($Cert)
            $store.Close()
        }
    } finally {
        if ($rsaKey -ne $null) {
            $rsaKey.Dispose()
            $Cert
        }
    }
}
# SIG # Begin signature block
# MIIfhgYJKoZIhvcNAQcCoIIfdzCCH3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCP04L7vO7lkSic
# 09g4LHb/wsvbQY9IvqbnXtG80Avc6aCCGYYwggX1MIID3aADAgECAhAdokgwb5sm
# GNCC4JZ9M9NqMA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKTmV3IEplcnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRo
# ZSBVU0VSVFJVU1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xODExMDIwMDAwMDBaFw0zMDEyMzEyMzU5
# NTlaMHwxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIx
# EDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIG
# A1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAhiKNMoV6GJ9J8JYvYwgeLdx8nxTP4ya2JWYpQIZU
# RnQxYsUQ7bKHJ6aZy5UwwFb1pHXGqQ5QYqVRkRBq4Etirv3w+Bisp//uLjMg+gwZ
# iahse60Aw2Gh3GllbR9uJ5bXl1GGpvQn5Xxqi5UeW2DVftcWkpwAL2j3l+1qcr44
# O2Pej79uTEFdEiAIWeg5zY/S1s8GtFcFtk6hPldrH5i8xGLWGwuNx2YbSp+dgcRy
# QLXiX+8LRf+jzhemLVWwt7C8VGqdvI1WU8bwunlQSSz3A7n+L2U18iLqLAevRtn5
# RhzcjHxxKPP+p8YU3VWRbooRDd8GJJV9D6ehfDrahjVh0wIDAQABo4IBZDCCAWAw
# HwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFA7hOqhT
# OjHVir7Bu61nGgOFrTQOMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMDBggrBgEFBQcDCDARBgNVHSAECjAIMAYG
# BFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29t
# L1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUF
# BwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VT
# RVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2Nz
# cC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBNY1DtRzRKYaTb3moq
# jJvxAAAeHWJ7Otcywvaz4GOz+2EAiJobbRAHBE++uOqJeCLrD0bs80ZeQEaJEvQL
# d1qcKkE6/Nb06+f3FZUzw6GDKLfeL+SU94Uzgy1KQEi/msJPSrGPJPSzgTfTt2Sw
# piNqWWhSQl//BOvhdGV5CPWpk95rcUCZlrp48bnI4sMIFrGrY1rIFYBtdF5KdX6l
# uMNstc/fSnmHXMdATWM19jDTz7UKDgsEf6BLrrujpdCEAJM+U100pQA1aWy+nyAl
# EA0Z+1CQYb45j3qOTfafDh7+B1ESZoMmGUiVzkrJwX/zOgWb+W/fiH/AI57SHkN6
# RTHBnE2p8FmyWRnoao0pBAJ3fEtLzXC+OrJVWng+vLtvAxAldxU0ivk2zEOS5LpP
# 8WKTKCVXKftRGcehJUBqhFfGsp2xvBwK2nxnfn0u6ShMGH7EezFBcZpLKewLPVdQ
# 0srd/Z4FUeVEeN0B3rF1mA1UJP3wTuPi+IO9crrLPTru8F4XkmhtyGH5pvEqCgul
# ufSe7pgyBYWe6/mDKdPGLH29OncuizdCoGqC7TtKqpQQpOEN+BfFtlp5MxiS47V1
# +KHpjgolHuQe8Z9ahyP/n6RRnvs5gBHN27XEp6iAb+VT1ODjosLSWxr6MiYtaldw
# HDykWC6j81tLB9wyWfOHpxptWDCCBkowggUyoAMCAQICEBdBS6OH2/E/xEs3Bf5c
# krcwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0
# ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSQwIgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0Ew
# HhcNMTkwODEzMDAwMDAwWhcNMjIwODEyMjM1OTU5WjCBmTELMAkGA1UEBhMCVVMx
# DjAMBgNVBBEMBTk3MjE5MQ8wDQYDVQQIDAZPcmVnb24xETAPBgNVBAcMCFBvcnRs
# YW5kMRwwGgYDVQQJDBMxNzEwIFNXIE1pbGl0YXJ5IFJkMRswGQYDVQQKDBJQS0kg
# U29sdXRpb25zIEluYy4xGzAZBgNVBAMMElBLSSBTb2x1dGlvbnMgSW5jLjCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANC9ao+Uw7Owaxi+v5FF1+eKGIpv
# QnKBFu61VsoHFyotJ8yoeC8tiRjmHggRbmQm0sTAdAXw23Rj5ZW6ndMWgA258car
# a6+oWB071e3ctsHoavc7NkDoCkKS2uh5tTmqclNMg6xaU1IIp9IWFq00K1jkeXex
# HIFLjTF2AA2SEteJO6VY08EiN6ktAOa1P4NbB0fTRUmca0j3W552hvU5Ig8G0DJt
# b4IDMMnu6WllNuxfqyNJiUOYkDET1p52XzvhMFMFnhbsH9JPcR4IA7Pp4xc1mRhe
# D9uE+KVx1astA/GvWtkpeZy/efbaMOxY4VuTW9kdgc8tB4VPamQQpoVmD3ULsaPz
# iv8cOum0CMrTtwKA/meas20A69u3xg8KeuDwxE0rysT4a68lXjFZViyHQQQzeZi4
# wAifk3URIABuKy6DQdQ4FJRjIvAXh5PD2WatY7aJJw9nc0biEB7bEjDNYufJ4OL9
# M9ibVqQxpLz0Vm9D+aCD1CJFySCcIOg7VRWCNyTqtDxDlWd6I7H1s2QwsiEWIOCE
# MtOlve+rZi9RgJhtrdoINgmgSPNH+lITexCMrNDvpEzYxggsTLcEs4jq6XzoD/bR
# G9gvSv/d5Di8Js0gjaqpwDZbLsProdRFX0AlAROarTVW0m9nqVHcP4o0Lc/jKCJ6
# 8073khO+aMOJKW/9AgMBAAGjggGoMIIBpDAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+
# wbutZxoDha00DjAdBgNVHQ4EFgQUd9YCgc1i67qdUtY6jeRnT0YzsVAwDgYDVR0P
# AQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJ
# YIZIAYb4QgEBBAQDAgQQMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMCMCUwIwYI
# KwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMEMGA1UdHwQ8MDowOKA2
# oDSGMmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1JTQUNvZGVTaWduaW5n
# Q0EuY3JsMHMGCCsGAQUFBwEBBGcwZTA+BggrBgEFBQcwAoYyaHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUlNBQ29kZVNpZ25pbmdDQS5jcnQwIwYIKwYBBQUH
# MAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMCAGA1UdEQQZMBeBFWluZm9AcGtp
# c29sdXRpb25zLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAa4IZBlHU1V6Dy+atjrwS
# YugL+ryvzR1eGH5+nzbwxAi4h3IaknQBIuWzoamR+hRUga9/Rd4jrBbXGTgkqM7A
# tnzXP7P5NZOmxOdFOl1UfgNIv5MfJNPzsvn54bnx9rgKWJlpmKPCr1xtfj2ERlhA
# f6ADOfUyCcTnSwlBi1Bai60wqqDPuj1zcDaD2XGddVmqVrplx1zNoX7vhyErA7V9
# psRWQYIflYY0L58gposEUVMKM6TJRRjndibRnO2CI9plXDBz4j3cTni3fXGM3UuB
# VInKSeC+mTsvJVYTHjBowWohhxMBdqD0xFVbysoRKGtWSJwErdAomjMCrY2q6oYc
# xzCCBmowggVSoAMCAQICEAMBmgI6/1ixa9bV6uYX8GYwDQYJKoZIhvcNAQEFBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xMB4XDTE0MTAyMjAwMDAwMFoXDTI0MTAyMjAwMDAwMFowRzELMAkGA1UEBhMC
# VVMxETAPBgNVBAoTCERpZ2lDZXJ0MSUwIwYDVQQDExxEaWdpQ2VydCBUaW1lc3Rh
# bXAgUmVzcG9uZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2Rd
# /Hyz4II14OD2xirmSXU7zG7gU6mfH2RZ5nxrf2uMnVX4kuOe1VpjWwJJUNmDzm9m
# 7t3LhelfpfnUh3SIRDsZyeX1kZ/GFDmsJOqoSyyRicxeKPRktlC39RKzc5YKZ6O+
# YZ+u8/0SeHUOplsU/UUjjoZEVX0YhgWMVYd5SEb3yg6Np95OX+Koti1ZAmGIYXIY
# aLm4fO7m5zQvMXeBMB+7NgGN7yfj95rwTDFkjePr+hmHqH7P7IwMNlt6wXq4eMfJ
# Bi5GEMiN6ARg27xzdPpO2P6qQPGyznBGg+naQKFZOtkVCVeZVjCT88lhzNAIzGvs
# YkKRrALA76TwiRGPdwIDAQABo4IDNTCCAzEwDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNVHSAEggG2MIIB
# sjCCAaEGCWCGSAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBz
# AGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBv
# AG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAg
# AHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAg
# AHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBt
# AGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0
# AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABo
# AGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9
# bAMVMB8GA1UdIwQYMBaAFBUAEisTmLKZB+0e36K+Vw0rZwLNMB0GA1UdDgQWBBRh
# Wk0ktkkynUoqeRqDS/QeicHKfTB9BgNVHR8EdjB0MDigNqA0hjJodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDA4oDagNIYy
# aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5j
# cmwwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQCd
# JX4bM02yJoFcm4bOIyAPgIfliP//sdRqLDHtOhcZcRfNqRu8WhY5AJ3jbITkWkD7
# 3gYBjDf6m7GdJH7+IKRXrVu3mrBgJuppVyFdNC8fcbCDlBkFazWQEKB7l8f2P+fi
# EUGmvWLZ8Cc9OB0obzpSCfDscGLTYkuw4HOmksDTjjHYL+NtFxMG7uQDthSr849D
# p3GdId0UyhVdkkHa+Q+B0Zl0DSbEDn8btfWg8cZ3BigV6diT5VUW8LsKqxzbXEgn
# Zsijiwoc5ZXarsQuWaBh3drzbaJh6YoLbewSGL33VVRAA5Ira8JRwgpIr7DUbuD0
# FAo6G+OPPcqvao173NhEMIIGzTCCBbWgAwIBAgIQBv35A5YDreoACus/J7u6GzAN
# BgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2Vy
# dCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMjExMTEwMDAw
# MDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVk
# IElEIENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDogi2Z+crC
# QpWlgHNAcNKeVlRcqcTSQQaPyTP8TUWRXIGf7Syc+BZZ3561JBXCmLm0d0ncicQK
# 2q/LXmvtrbBxMevPOkAMRk2T7It6NggDqww0/hhJgv7HxzFIgHweog+SDlDJxofr
# Nj/YMMP/pvf7os1vcyP+rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds97bFBo+0/vtuV
# SMTuHrPyvAwrmdDGXRJCgeGDboJzPyZLFJCuWWYKxI2+0s4Grq2Eb0iEm09AufFM
# 8q+Y+/bOQF1c9qjxL6/siSLyaxhlscFzrdfx2M8eCnRcQrhofrfVdwonVnwPYqQ/
# MhRglf0HBKIJAgMBAAGjggN6MIIDdjAOBgNVHQ8BAf8EBAMCAYYwOwYDVR0lBDQw
# MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQGCCsGAQUF
# BwMIMIIB0gYDVR0gBIIByTCCAcUwggG0BgpghkgBhv1sAAEEMIIBpDA6BggrBgEF
# BQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBvc2l0b3J5
# Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAg
# AHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0
# AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABE
# AGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABS
# AGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3
# AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBk
# ACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBu
# ACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwEgYDVR0T
# AQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0f
# BHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNz
# dXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQUFQASKxOYspkH
# 7R7for5XDStnAs0wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJ
# KoZIhvcNAQEFBQADggEBAEZQPsm3KCSnOB22WymvUs9S6TFHq1Zce9UNC0Gz7+x1
# H3Q48rJcYaKclcNQ5IK5I9G6OoZyrTh4rHVdFxc0ckeFlFbR67s2hHfMJKXzBBlV
# qefj56tizfuLLZDCwNK1lL1eT7EF0g49GqkUW6aGMWKoqDPkmzmnxPXOHXh2lCVz
# 5Cqrz5x2S+1fwksW5EtwTACJHvzFebxMElf+X+EevAJdqP77BzhPDcZdkbkPZ0XN
# 1oPt55INjbFpjE/7WeAjD9KqrgB87pxCDs+R1ye3Fu4Pw718CqDuLAhVhSK46xga
# TfwqIa1JMYNHlXdx3LEbS0scEJx3FMGdTy9alQgpECYxggVWMIIFUgIBATCBkDB8
# MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
# VQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJDAiBgNVBAMT
# G1NlY3RpZ28gUlNBIENvZGUgU2lnbmluZyBDQQIQF0FLo4fb8T/ESzcF/lyStzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCBpuaD1SBM4kUW3s7INMVK36m5afjWV948LWRIt
# DANi5DANBgkqhkiG9w0BAQEFAASCAgAzJP1fhNxQ8pvYTB1ngPYv94LY2r/4xU04
# GPpd6Pt8usvhX6KvzZTKTWRj8K7Mr6s6mxX2PzMh2fNRyDQd4lpEf3YWHrIPAVR3
# ep+ad+qDlwb52VzCcU7tow46T2tY6w2AHvEO1yu6LTrqRoKUc6oyCBmMppek/Gt9
# aisjZqzTocgf5usYaHBzyfXSBKG/GSLXbPbvpQp65lrlLk3qdyNnmUKkAJj+ce9M
# eGOn9tjZ1SdP+6pFb1bIY3u+Oun/fMwrQ1NpZ4PwKh2L/hfvZabEyRoW9HCmdcNr
# Ub9bg1nL7IcvDDLKdaGb7dQdSU2WQNSoqbNv5cOjuIAwtSveg/k/9iVqhh2xnqKj
# TUp7I71JvNLd4sUYhiA7TeYlsGaCINezFBOEw2HNqCJ+fJMBETe2bEz9xHdS3BVn
# GrkYpoF+4d3ykPigiwW3a6Epexyz1y87yObEQeNcY7Chobo1JstOZ50yJFAmXW73
# G79umCQg6P5UXffKt6U8bwVdG3rCknZHz01un4GKczmwkWc90Y+KD7hy2gFx7NM4
# 2qOM3D6JvwNE5E9pwe18efKPKBsdULJ6shaLvip67sM+EbzzOwcUQWQHQ45mbNgB
# WgKq1TS+AziVrx3cBGPOM4Mo9Ks+5ztBN/v7Z+05+IaAOt6cE/5wXAmj97NvRCMQ
# 2+rgJBgfHKGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwODEzMDcxNTA4WjAjBgkqhkiG9w0BCQQx
# FgQUx8XUKeaPALmLWBTPd4IBTWOIAtwwDQYJKoZIhvcNAQEBBQAEggEAnCOyyQnn
# LELCdxXnOQC2mjNsAa67gI+Tgn0BSXqH0sGZ40AXcJOEwdkEdjANVBpZ0A2V5UZU
# iZrMn+owmX1RJxxlDo7INsv+yb/1MifttqNL0/GaerLqq9kxeAxYRQFFWKicRtzJ
# PtGZOR0vTLhcF0w0k71bEK2HD7L+tg4/RtLE9wjCdRmTawzC94cPpNPGBB4Kt+hW
# g6zdZdivezjs96H3sR4frW8K4jZ+xZlC6S3TaVZEfWr2VbAf41qOl5TMohYnDuVG
# sMYirkNo5DMOcWUAO/Uw3VJ8oVyZkDWOC3wSiD8bU/M5ZGG577zi/DsJs0DohK6G
# D7SevFOwCcDxZA==
# SIG # End signature block
