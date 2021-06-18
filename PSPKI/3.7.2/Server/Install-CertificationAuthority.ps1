function Install-CertificationAuthority {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Utils.IServiceOperationResult')]
[CmdletBinding(
	DefaultParameterSetName = 'NewKeySet',
	ConfirmImpact = 'High',
	SupportsShouldProcess = $true
)]
	param(
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CAName,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CADNSuffix,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[ValidateSet("Standalone Root","Standalone Subordinate","Enterprise Root","Enterprise Subordinate")]
		[string]$CAType,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$ParentCA,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CSP,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[int]$KeyLength,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$HashAlgorithm,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[int]$ValidForYears = 5,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$RequestFileName,
		[Parameter(Mandatory = $true, ParameterSetName = 'PFXKeySet')]
		[IO.FileInfo]$CACertFile,
		[Parameter(Mandatory = $true, ParameterSetName = 'PFXKeySet')]
		[Security.SecureString]$Password,
		[Parameter(Mandatory = $true, ParameterSetName = 'ExistingKeySet')]
		[string]$Thumbprint,
		[string]$DBDirectory = $(Join-Path $env:SystemRoot "System32\CertLog"),
		[string]$LogDirectory = $(Join-Path $env:SystemRoot "System32\CertLog"),
		[switch]$OverwriteExisting,
		[switch]$AllowCSPInteraction,
		[switch]$Force
	)

#region OS and existing CA checking
	# check if script running on Windows Server 2008 or Windows Server 2008 R2
	$OS = Get-WmiObject Win32_OperatingSystem -Property ProductType
	if ($OSVersion.Major -lt 6) {
		Write-Error -Category NotImplemented -ErrorId "NotSupportedException" `
		-Message "Windows XP, Windows Server 2003 and Windows Server 2003 R2 are not supported!"
		return
	}
	if ($OS.ProductType -eq 1) {
		Write-Error -Category NotImplemented -ErrorId "NotSupportedException" `
		-Message "Client operating systems are not supported!"
		return
	}
	$CertConfig = New-Object -ComObject CertificateAuthority.Config
	try {$ExistingDetected = $CertConfig.GetConfig(3)}
	catch {}
	if ($ExistingDetected) {
		Write-Error -Category ResourceExists -ErrorId "ResourceExistsException" `
		-Message "Certificate Services are already installed on this computer. Only one Certification Authority instance per computer is supported."
		return
	}
	
#endregion

#region Binaries checking and installation if necessary
	if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 0) {
		cmd /c "servermanagercmd -install AD-Certificate 2> null" | Out-Null
	} else {
		try {Import-Module ServerManager -ErrorAction Stop}
		catch {
			ocsetup 'ServerManager-PSH-Cmdlets' /quiet | Out-Null
			Start-Sleep 1
			Import-Module ServerManager -ErrorAction Stop
		}
		$status = (Get-WindowsFeature -Name AD-Certificate).Installed
		# if still no, install binaries, otherwise do nothing
		if (!$status) {$retn = Add-WindowsFeature -Name AD-Certificate -ErrorAction Stop
			if (!$retn.Success) {
				Write-Error -Category NotInstalled -ErrorId "NotInstalledException" `
				-Message "Unable to install ADCS installation packages due of the following error: $($retn.breakCode)"
				return
			}
		}
	}
	try {$CASetup = New-Object -ComObject CertOCM.CertSrvSetup.1}
	catch {
		Write-Error -Category NotImplemented -ErrorId "NotImplementedException" `
		-Message "Unable to load necessary interfaces. Your Windows Server operating system is not supported!"
		return
	}
	# initialize setup binaries
	try {$CASetup.InitializeDefaults($true, $false)}
	catch {
		Write-Error -Category InvalidArgument -ErrorId ParameterIncorrectException `
		-ErrorAction Stop -Message "Cannot initialize setup binaries!"
	}
#endregion

#region Property enums
	$CATypesByName = @{"Enterprise Root" = 0; "Enterprise Subordinate" = 1; "Standalone Root" = 3; "Standalone Subordinate" = 4}
	$CATypesByVal = @{}
	$CATypesByName.keys | ForEach-Object {$CATypesByVal.Add($CATypesByName[$_],$_)}
	$CAPRopertyByName = @{"CAType"=0;"CAKeyInfo"=1;"Interactive"=2;"ValidityPeriodUnits"=5;
		"ValidityPeriod"=6;"ExpirationDate"=7;"PreserveDataBase"=8;"DBDirectory"=9;"Logdirectory"=10;
		"ParentCAMachine"=12;"ParentCAName"=13;"RequestFile"=14;"WebCAMachine"=15;"WebCAName"=16
	}
	$CAPRopertyByVal = @{}
	$CAPRopertyByName.keys | ForEach-Object {$CAPRopertyByVal.Add($CAPRopertyByName[$_],$_)}
	$ValidityUnitsByName = @{"years" = 6}
	$ValidityUnitsByVal = @{6 = "years"}
#endregion
	$ofs = ", "
#region Key set processing functions

#region NewKeySet
function NewKeySet ($CAName, $CADNSuffix, $CAType, $ParentCA, $CSP, $KeyLength, $HashAlgorithm, $ValidForYears, $RequestFileName, $AllowCSPInteraction) {

#region CSP, key length and hashing algorithm verification
	$CAKey = $CASetup.GetCASetupProperty(1)
	if ($AllowCSPInteraction) {$CASetup.SetCASetupProperty(0x2,$true)}
	if ($CSP -ne "") {
		if ($CASetup.GetProviderNameList() -notcontains $CSP) {
			# TODO add available CSP list
			Write-Error -Category InvalidArgument -ErrorId "InvalidCryptographicServiceProviderException" `
			-ErrorAction Stop -Message "Specified CSP '$CSP' is not valid!"
		} else {
			$CAKey.ProviderName = $CSP
		}
	} else {
		$CAKey.ProviderName = "RSA#Microsoft Software Key Storage Provider"
	}
	if ($KeyLength -ne 0) {
		if ($CASetup.GetKeyLengthList($CAKey.ProviderName).Length -eq 1) {
			$CAKey.Length = $CASetup.GetKeyLengthList($CAKey.ProviderName)[0]
		} else {
			if ($CASetup.GetKeyLengthList($CAKey.ProviderName) -notcontains $KeyLength) {
				Write-Error -Category InvalidArgument -ErrorId "InvalidKeyLengthException" `
				-ErrorAction Stop -Message @"
The specified key length '$KeyLength' is not supported by the selected CSP '$($CAKey.ProviderName)' The following
key lengths are supported by this CSP: $($CASetup.GetKeyLengthList($CAKey.ProviderName))
"@
			}
			$CAKey.Length = $KeyLength
		}
	}
	if ($HashAlgorithm -ne "") {
		if ($CASetup.GetHashAlgorithmList($CAKey.ProviderName) -notcontains $HashAlgorithm) {
				Write-Error -Category InvalidArgument -ErrorId "InvalidHashAlgorithmException" `
				-ErrorAction Stop -Message @"
The specified hash algorithm is not supported by the selected CSP '$($CAKey.ProviderName)' The following
hash algorithms are supported by this CSP: $($CASetup.GetHashAlgorithmList($CAKey.ProviderName))
"@
		}
		$CAKey.HashAlgorithm = $HashAlgorithm
	}
	$CASetup.SetCASetupProperty(1,$CAKey)
#endregion

#region Setting CA type
	if ($CAType) {
		$SupportedTypes = $CASetup.GetSupportedCATypes()
		$SelectedType = $CATypesByName[$CAType]
		if ($SupportedTypes -notcontains $CATypesByName[$CAType]) {
			Write-Error -Category InvalidArgument -ErrorId "InvalidCATypeException" `
			-ErrorAction Stop -Message @"
Selected CA type: '$CAType' is not supported by current Windows Server installation.
The following CA types are supported by this installation: $([int[]]$CASetup.GetSupportedCATypes() | %{$CATypesByVal[$_]})
"@
		} else {$CASetup.SetCASetupProperty($CAPRopertyByName.CAType,$SelectedType)}
	}
#endregion

#region setting CA certificate validity
	if ($SelectedType -eq 0 -or $SelectedType -eq 3 -and $ValidForYears -ne 0) {
		try{$CASetup.SetCASetupProperty(6,$ValidForYears)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidCAValidityException" `
			-ErrorAction Stop -Message "The specified CA certificate validity period '$ValidForYears' is invalid."
		}
	}
#endregion

#region setting CA name
	if ($CAName -ne "") {
		if ($CADNSuffix -ne "") {$Subject = "CN=$CAName" + ",$CADNSuffix"} else {$Subject = "CN=$CAName"}
		$DN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
		# validate X500 name format
		try {$DN.Encode($Subject,0x0)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidX500NameException" `
			-ErrorAction Stop -Message "Specified CA name or CA name suffix is not correct X.500 Distinguished Name."
		}
		$CASetup.SetCADistinguishedName($Subject, $true, $true, $true)
	}
#endregion

#region set parent CA/request file properties
	if ($CASetup.GetCASetupProperty(0) -eq 1 -and $ParentCA) {
		[void]($ParentCA -match "^(.+)\\(.+)$")
		try {$CASetup.SetParentCAInformation($ParentCA)}
		catch {
			Write-Error -Category ObjectNotFound -ErrorId "ObjectNotFoundException" `
			-ErrorAction Stop -Message @"
The specified parent CA information '$ParentCA' is incorrect. Make sure if parent CA
information is correct (you must specify existing CA) and is supplied in a 'CAComputerName\CASanitizedName' form.
"@
		}
	} elseif ($CASetup.GetCASetupProperty(0) -eq 1 -or $CASetup.GetCASetupProperty(0) -eq 4 -and $RequestFileName -ne "") {
		$CASetup.SetCASetupProperty(14,$RequestFileName)
	}
#endregion
}

#endregion

#region PFXKeySet
function PFXKeySet ($CACertFile, $Password) {
	$FilePath = Resolve-Path $CACertFile -ErrorAction Stop
	try {[void]$CASetup.CAImportPFX(
		$FilePath.Path,
		[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
		$true)
	} catch {Write-Error $_ -ErrorAction Stop}
}
#endregion

#region ExistingKeySet
function ExistingKeySet ($Thumbprint) {
	$ExKeys = $CASetup.GetExistingCACertificates() | Where-Object {
		([Security.Cryptography.X509Certificates.X509Certificate2]$_.ExistingCACertificate).Thumbprint -eq $Thumbprint
	}
	if (!$ExKeys) {
		Write-Error -Category ObjectNotFound -ErrorId "ElementNotFoundException" `
		-ErrorAction Stop -Message "The system cannot find a valid CA certificate with thumbprint: $Thumbprint"
	} else {$CASetup.SetCASetupProperty(1,@($ExKeys)[0])}
}
#endregion

#endregion

#region set database settings
	if ($DBDirectory -ne "" -and $LogDirectory -ne "") {
		try {$CASetup.SetDatabaseInformation($DBDirectory,$LogDirectory,$null,$OverwriteExisting)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
			-ErrorAction Stop -Message "Specified path to either database directory or log directory is invalid."
		}
	} elseif ($DBDirectory -ne "" -and $LogDirectory -eq "") {
		Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
		-ErrorAction Stop -Message "CA Log file directory cannot be empty."
	} elseif ($DBDirectory -eq "" -and $LogDirectory -ne "") {
		Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
		-ErrorAction Stop -Message "CA database directory cannot be empty."
	}

#endregion
	# process parametersets.
	switch ($PSCmdlet.ParameterSetName) {
		"ExistingKeySet" {ExistingKeySet $Thumbprint}
		"PFXKeySet" {PFXKeySet $CACertFile $Password}
		"NewKeySet" {NewKeySet $CAName $CADNSuffix $CAType $ParentCA $CSP $KeyLength $HashAlgorithm $ValidForYears $RequestFileName $AllowCSPInteraction}
	}
	try {
		Write-Verbose "Installing Certification Authority role on $env:computername ..." -ForegroundColor Cyan
		if ($Force -or $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install Certification Authority")) {
			$CASetup.Install()
			$PostRequiredMsg = @"
Certification Authority role was successfully installed, but not completed. To complete
installation submit request file '$($CASetup.GetCASetupProperty(14))' to parent Certification Authority
and install issued certificate by running the following command: certutil -installcert 'PathToACertFile'
"@
			if ($CASetup.GetCASetupProperty(0) -eq 1 -and $ParentCA -eq "") {
				Write-Warning $PostRequiredMsg
			} elseif ($CASetup.GetCASetupProperty(0) -eq 1 -and $PSCmdlet.ParameterSetName -eq "NewKeySet" -and $ParentCA -ne "") {
				$CASName = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration).Active
				$SetupStatus = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$CASName).SetupStatus
				$RequestID = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$CASName).RequestID
				if ($SetupStatus -ne 1) {
					Write-Warning $PostRequiredMsg
				}
			} elseif ($CASetup.GetCASetupProperty(0) -eq 4) {
				Write-Warning $PostRequiredMsg
			} else {New-Object SysadminsLV.PKI.Utils.ServiceOperationResult 0}
		}
	} catch {New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $_.Exception.HResult}
	Remove-Module ServerManager -ErrorAction SilentlyContinue
}
# SIG # Begin signature block
# MIIfhgYJKoZIhvcNAQcCoIIfdzCCH3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCPTIx5EjytWljF
# 2XinppWVuPHP0X/kcINUJ6VHT/eLL6CCGYYwggX1MIID3aADAgECAhAdokgwb5sm
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCBKV1bC6X+wwR0TVMm+fqTDEIcJVivE3Wo/8sEq
# G6/AVzANBgkqhkiG9w0BAQEFAASCAgC595Hx26oolkKy556BNjIDVpUdaYEMQ5JA
# uQTZrdxCoMgyHQh/6y17IkU1UrrkFErVqNNx9MDuqaN0jiI8ItrFEVpyCURskGHn
# fd9N+PjKiOgTB/KybNmeNhDH4PtwYjLbj8D04kYeJUyJ26jtO/gmLlXRe8+4HNd/
# lVI2hsZzzoJwV7WoiZVSZdBTQaUYxAWNCjsYE/WQl/Zm3zuNHrC/Uoc/X2PZex6A
# 9l0dDTuCry0Zwy+jG2fcRrV9xqKpqzVlRc7WqA4E/r3+JNkzsR1s3PpXGbBqT2Hm
# 4ZpE6zi2AfyvK9MSb4LU0pslW9DLu/fE00Y7X4MY4wX334Ud20jHxz7WR21NPKPi
# OuWNb3p5nlTwTLJk/HXoK5SB78+PHHqyNu9sexEQLGgjLj7TeGb1qesNynLAySGN
# i+r+FUl6sXnQkIZNWYaoXAk4liszJ3Pa1RvmkmtZn5LjYS3jBo3MuHKCdXzHNuGs
# rK3P+He/kOUi1xWRPrQrIwYENmikIT9x+3qiRvhaItJJq3oohJQdMjGTRWuL7ZZd
# N+SKRIDOoMztaHifXp0UCPMdOJnVf67cPwpW6PsDZz/BZ8zQoqf38paUgUclrvj/
# /O8e/zBYWHGQzHI3jwhumUJKxwdiRSkd0VIomPNdBBEeRiThEuY0FYJzquCjcbzS
# eonP1MrhnqGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwODAzMTUyNjEyWjAjBgkqhkiG9w0BCQQx
# FgQUCDKRoiHsB3jzV/ByzQIH5/kmnoMwDQYJKoZIhvcNAQEBBQAEggEAcAbaRnXl
# UL225dww1llbnnL7ilT4ZBDqmpiZhOG+jeP4WCvP/+Mi6I79PV8Qi9VXLmFKfc46
# 58UdW9sqthKsh3JB25Ugey5lPezOaMgcTyMvPQjTEdyeSkvKH6yzjzy8Zgt07i+x
# p6S1+B9H6NdkJLEsgMT4jWM3/b3Xpto/DGup+ymFTcIaE8XIDMNEmFDS8yitLjIA
# NuitcQTf/Q0h4MpiB/YBfnwtVXCoY8QOOCgkIDLdW9xlyktkJNbyYYFbQdpBI/cJ
# 5jU2Si2xBGOYCaDvlP/QwOG5SKgvQiLFbgGmAX400W4vsSxW0IHpE07IAXgdP8Ee
# dh8YoX37eGvgQA==
# SIG # End signature block
