# if($(Get-WindowsCapability -Name "Rsat.CertificateServices.Tools*" -Online).State -eq 'NotPresent') {
#     # Note: try this if there are errors on installation https://www.wincert.net/microsoft-windows/windows-10/cannot-install-rsat-tools-on-windows-10-1809-error0x80244022/
#     Write-Warning "Please install RSAT tools with 'Get-WindowsCapability -Name `"Rsat*`" -Online | Add-WindowsCapability -Online'"
#     exit(1)
# }

<#
# module automatically loaded based on manifest
try {
    Import-Module PSPKI -Force -ErrorAction Stop
} catch {
    Write-Warning "Please install PSPKI with '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Install-Module PSPKI'"
    exit(1)
}
#>

<#
# use version published on GIT instead
try {
    Import-Module "$($PSScriptRoot)\PSPKI\3.7.2\PSPKI.psm1" -ErrorAction Stop -Force
} catch {
    Write-Warning "Unable to load PSPKI: $_"
    return
}
#>

<#
# use version published on GIT instead
# Ensure the version of PSPKI that comes bundled here is used and not the one from the gallery
if(![SysadminsLV.PKI.Win32.Crypt32].Assembly.Location.Contains($PSScriptRoot)) {
    Write-Warning "The wrong version of PSPKI is loaded. Please open a new PowerShell window and reload this module."
    return
}
#>

<#
# module automatically loaded based on manifest
try {
    Import-Module ActiveDirectory -Force -ErrorAction Stop
}
catch {
    Write-Warning "Please install the ActiveDirectory module'"
    return
}
#>

Get-ChildItem -Path "$($PSScriptRoot)\Code\" -Recurse -Include *.ps1 | ForEach-Object { . $_.FullName }
