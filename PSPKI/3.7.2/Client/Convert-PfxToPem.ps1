function Convert-PfxToPem {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding(DefaultParameterSetName = '__pfxfile')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 0)]
        [IO.FileInfo]$InputFile,
        [Parameter(Mandatory = $true, ParameterSetName = '__cert', Position = 0)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 1)]
        [Security.SecureString]$Password,
        [Parameter(Mandatory = $true, Position = 2)]
        [IO.FileInfo]$OutputFile,
        [Parameter(Position = 3)]
        [ValidateSet("Pkcs1","Pkcs8")]
        [string]$OutputType = "Pkcs8",
		[switch]$IncludeChain
    )
$signature = @"
[DllImport("crypt32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptAcquireCertificatePrivateKey(
    IntPtr pCert,
    uint dwFlags,
    IntPtr pvReserved,
    ref IntPtr phCryptProv,
    ref uint pdwKeySpec,
    ref bool pfCallerFreeProv
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptGetUserKey(
    IntPtr hProv,
    uint dwKeySpec,
    ref IntPtr phUserKey
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptExportKey(
    IntPtr hKey,
    IntPtr hExpKey,
    uint dwBlobType,
    uint dwFlags,
    byte[] pbData,
    ref uint pdwDataLen
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptDestroyKey(
    IntPtr hKey
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXIsPFXBlob(
    CRYPTOAPI_BLOB pPFX
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXVerifyPassword(
    CRYPTOAPI_BLOB pPFX,
    [MarshalAs(UnmanagedType.LPWStr)]
    string szPassword,
    int dwFlags
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRYPTOAPI_BLOB {
    public int cbData;
    public IntPtr pbData;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct PUBKEYBLOBHEADERS {
    public byte bType;
    public byte bVersion;
    public short reserved;
    public uint aiKeyAlg;
    public uint magic;
    public uint bitlen;
    public uint pubexp;
 }
"@
    Add-Type -MemberDefinition $signature -Namespace PKI -Name PfxTools
#region helper functions
    function Encode-Integer ([Byte[]]$RawData) {
        # since CryptoAPI is little-endian by nature, we have to change byte ordering
        # to big-endian.
        [array]::Reverse($RawData)
        # if high byte contains more than 7 bits, an extra zero byte is added
        if ($RawData[0] -ge 128) {$RawData = ,0 + $RawData}
        [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($RawData, 2)
    }
#endregion

#region parameterset processing
    switch ($PsCmdlet.ParameterSetName) {
        "__pfxfile" {
            $bytes = [IO.File]::ReadAllBytes($InputFile)
            $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
            [Runtime.InteropServices.Marshal]::Copy($bytes,0,$ptr,$bytes.Length)
            $pfx = New-Object PKI.PfxTools+CRYPTOAPI_BLOB -Property @{
                cbData = $bytes.Length;
                pbData = $ptr
            }
            # just check whether input file is valid PKCS#12/PFX file.
            if ([PKI.PfxTools]::PFXIsPFXBlob($pfx)) {
				$certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
				try {
					$certs.Import(
						$bytes,
						[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
						"Exportable"
					)
					$Certificate = ($certs | Where-Object {$_.HasPrivateKey})[0]
				} catch {
					throw $_
					return
				} finally {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                    Remove-Variable bytes, ptr, pfx -Force
                }
            } else {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                Remove-Variable bytes, ptr, pfx -Force
                Write-Error -Category InvalidData -Message "Input file is not valid PKCS#12/PFX file." -ErrorAction Stop
            }
        }
        "__cert" {
            if (!$Certificate.HasPrivateKey) {
                Write-Error -Category InvalidOperation -Message "Specified certificate object does not contain associated private key." -ErrorAction Stop
            }
        }
    }
#endregion

#region constants
	$CRYPT_ACQUIRE_SILENT_FLAG = 0x40
	$PRIVATEKEYBLOB = 0x7
	$CRYPT_OAEP = 0x40
#endregion

#region private key export routine
    $phCryptProv = [IntPtr]::Zero
    $pdwKeySpec = 0
    $pfCallerFreeProv = $false
    # attempt to acquire private key container
    if (![PKI.PfxTools]::CryptAcquireCertificatePrivateKey($Certificate.Handle,$CRYPT_ACQUIRE_SILENT_FLAG,0,[ref]$phCryptProv,[ref]$pdwKeySpec,[ref]$pfCallerFreeProv)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$phUserKey = [IntPtr]::Zero
	# attempt to acquire private key handle
	if (![PKI.PfxTools]::CryptGetUserKey($phCryptProv,$pdwKeySpec,[ref]$phUserKey)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$pdwDataLen = 0
	# attempt to export private key. This method fails if certificate has non-exportable private key.
	if (![PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$null,[ref]$pdwDataLen)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$pbytes = New-Object byte[] -ArgumentList $pdwDataLen
	[void][PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$pbytes,[ref]$pdwDataLen)
	# release private key handle
	[void][PKI.PfxTools]::CryptDestroyKey($phUserKey)
#endregion

#region private key blob splitter
    # extracting private key blob header.
    $headerblob = $pbytes[0..19]
    # extracting actual private key data exluding header.
    $keyblob = $pbytes[20..($pbytes.Length - 1)]
    Remove-Variable pbytes -Force
    # public key structure header has fixed length: 20 bytes: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    # copy header information to unmanaged memory and copy it to structure.
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal(20)
    [Runtime.InteropServices.Marshal]::Copy($headerblob,0,$ptr,20)
    $header = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[Type][PKI.PfxTools+PUBKEYBLOBHEADERS])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    # extract public exponent from blob header and convert it to a byte array
    $pubExponentHex = "{0:x2}" -f $header.pubexp
    if ($pubExponentHex.Length % 2) {$pubExponentHex = "0" + $pubExponentHex}
    $publicExponent = $pubExponentHex -split "([a-f0-9]{2})" | Where-Object {$_} | ForEach-Object {[Convert]::ToByte($_,16)}
    # this object is created to reduce code size. This object has properties, where each property represents
    # a part (component) of the private key and property value contains private key component length.
    # 8 means that the length of the component is KeyLength / 8. Resulting length is measured in bytes.
    # for details see private key structure description: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    $obj = New-Object psobject -Property @{
        modulus = 8; privateExponent = 8;
        prime1 = 16; prime2 = 16; exponent1 = 16; exponent2 = 16; coefficient = 16;
    }
    $offset = 0
    # I pass variable names (each name represents the component of the private key) to foreach loop
    # in the order as they follow in the private key structure and parse private key for
    # appropriate offsets and write component information to variable.
    "modulus","prime1","prime2","exponent1","exponent2","coefficient","privateExponent" | ForEach-Object {
        Set-Variable -Name $_ -Value ($keyblob[$offset..($offset + $header.bitlen / $obj.$_ - 1)])
        $offset = $offset + $header.bitlen / $obj.$_
    }
    # PKCS#1/PKCS#8 uses slightly different component order, therefore I reorder private key
    # components and pass them to a simplified ASN encoder.
    $asnblob = Encode-Integer 0
    $asnblob += "modulus","publicExponent","privateExponent","prime1","prime2","exponent1","exponent2","coefficient" | ForEach-Object {
        Encode-Integer (Get-Variable -Name $_).Value
    }
    # remove unused variables
    Remove-Variable modulus,publicExponent,privateExponent,prime1,prime2,exponent1,exponent2,coefficient -Force
    # encode resulting set of INTEGERs to a SEQUENCE
    $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
    # $out variable just holds output file. The file will contain private key and public certificate
    # each will be enclosed with header and footer.
	$out = New-Object Text.StringBuilder
    if ($OutputType -eq "Pkcs8") {
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 4)
        $algid = [Security.Cryptography.CryptoConfig]::EncodeOID("1.2.840.113549.1.1.1") + 5,0
        $algid = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($algid, 48)
        $asnblob = 2,1,0 + $algid + $asnblob
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
		$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
		[void]$out.AppendFormat("{0}{1}", "-----BEGIN PRIVATE KEY-----", [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", "-----END PRIVATE KEY-----", [Environment]::NewLine)
    } else {
        # PKCS#1 requires RSA identifier in the header.
        # PKCS#1 is an inner structure of PKCS#8 message, therefore no additional encodings are required.
		$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
		[void]$out.AppendFormat("{0}{1}", "-----BEGIN RSA PRIVATE KEY-----", [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", "-----END RSA PRIVATE KEY-----", [Environment]::NewLine)
    }
    $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($Certificate.RawData,"Base64Header")
	$out.Append($base64)
	if ($IncludeChain) {
		$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
		$chain.ChainPolicy.RevocationMode = "NoCheck"
		if ($certs) {
			$chain.ChainPolicy.ExtraStore.AddRange($certs)
		}
		[void]$chain.Build($Certificate)
		for ($n = 1; $n -lt $chain.ChainElements.Count; $n++) {
			$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($chain.ChainElements[$n].Certificate.RawData,"Base64Header")
			$out.Append($base64)
		}
	}
    [IO.File]::WriteAllLines($OutputFile,$out.ToString())
#endregion
}
# SIG # Begin signature block
# MIIfhgYJKoZIhvcNAQcCoIIfdzCCH3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3M9HxcEr6xez6
# SDJ0wWfBLj3Lb9a8lRhGqlmkXrYaKqCCGYYwggX1MIID3aADAgECAhAdokgwb5sm
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCDhdee6rFpDfKqZb2AEndpywmBakA8ZvOSvIj8M
# pDmsfjANBgkqhkiG9w0BAQEFAASCAgBpoWdZOe111mcvdl8scuTNQqEj7SlddadY
# WsSUxqJ8+Su4FQZ3ECChuhlpp0h6dWUhXh+4kneYsC22tolahdZ+ptPAGTYQlBo9
# jgQ1/8xxyVTsM+Jsaev9QkoPnY7NCk9tfxCftu87RMKVEAhxI+qL0iFavVuRs4fD
# jPuKfzTM3+eqtu5nTwe0sJYwquGxxmFXdxlaXVsNCaGsY2Ho170GaT7sDY7ZqrvR
# RffrebV9f+bGOuVNzs5BaZ/Qf3h3KZU9xjlw92EoW37jSQhiyAOb7Zljq5FD5TsG
# rBUQ3IG8aaCGMeSPi5VQJq9lgzPEhW7IXz4hozPiqSmiPB8SBLGRaxnfia0/9+jN
# 0FttjLa08rrGzNxpae+7FvLNrq8YXT7wwuCaY6mkbRd+pgj5JBfwONpUqTTeQJyR
# BgRsz0jePOxg+ql3lYs56nCNkhooFmsIvi44CNbVGa6myNVSp2UkFoRjRwoOsiY6
# +K0qTOwif977PuH/RsdNsMvZz1vS8WEfXjofFJQvjryX0NuJtXILO32So6PFfE9w
# aK83Bz4ppQx8GVPVJZZxFMJaG+kx/EWbwEebarPd886/JVhjVIhyEfizmpVpG8TR
# A2SD0TjaqW7mPVqF8IGVo/ebFDOgEcU7bmBGm1PQZQDLF89jVJP1exLwjmmNFsxT
# slYYk2xLn6GCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwODAzMTUyNjM2WjAjBgkqhkiG9w0BCQQx
# FgQUb63JamEtYv7hroVXOCEtRBxWBoAwDQYJKoZIhvcNAQEBBQAEggEAAB416Qvo
# Sn3Z23EQWswolO7yFFi7OoDIaRyGJo272zK6Dr7SOFmV/2+2Yo6kCqjmI1z1R8uB
# OjtBztL1TQjkWv3x9Q24pVYVyjDYRIioZdD+4PEsOveoIXK4DP8FLgP64W9oTIW3
# /728fldhmntD/sFEWkZwOD+8PeulYusrWBK+7JfvS4p/RJpHTcIO8NdkjLQUS7vu
# 8czmiGDzisOu5D9D1UVR7L9OxNAEjD1ViP3G2/5fxFm8/dVPEvFaikElDwMSSKlj
# dJYTejlvBtJ8QsA4Z/iWVbsaZvtWSVTywQmoyQHUW47CTcPq8lyY3wZ3HBK6EOAA
# WPi0pp7sBpJYjQ==
# SIG # End signature block
