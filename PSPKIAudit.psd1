@{

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '64ceb619-0a9d-4657-8ca8-889f9453bf31'

# Author of this module
Author = 'Will Schroeder,Lee Christensen'

# Copyright statement for this module
Copyright = 'Ms-PL'

# Description of the functionality provided by this module
Description = ''

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Modules that must be imported into the global environment prior to importing this module
#RequiredModules = @('PSPKI','ActiveDirectory')
RequiredModules = @('ActiveDirectory')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'Get-CertRequest',
    'Invoke-PKIAudit',
    'Get-AuditCertificateAuthority',
    'Get-AuditCertificateTemplate',
    'Get-AuditPKIADObjectControllers',
    'Format-PKIAdObjectControllers'
)
}