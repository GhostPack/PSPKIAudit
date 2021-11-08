$Version = "0.3.6"

# regex of low-privileged principal names used for testing vulnerable enrollment/access control
#   Everyone                S-1-1-0
#   Authenticated Users     S-1-5-11
#   Domain Users            S-1-5-21domain-513
#   Domain Computers        S-1-5-21domain-515
#   Users                   S-1-5-32-545
$CommonLowprivPrincipals = "S-1-1-0|S-1-5-11|S-1-5-21.*-513$|S-1-5-21.*-515$|S-1-5-32-545"`

# cache for username->SID translations
$SIDTranslationCache = @{}


function Invoke-PKIAudit {
    <#
    .SYNOPSIS

    Audits Certificate Authority settings and Certificate Template settings.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER CAComputerName

    The name of the Certificate Authority computer to audit.

    .PARAMETER CAName

    The name of the Certificate Authority to audit.

    .PARAMETER ShowAllVulnerableTemplates

    Show all vulnerable templates, not just templates published to a CA.
    #>

    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $CAComputerName,

        [Parameter()]
        [String]
        $CAName,

        [Switch]
        $ShowAllVulnerableTemplates
    )
    

    Write-Host -ForegroundColor Green @"

  _____   _____ _____  _  _______                   _ _ _   
 |  __ \ / ____|  __ \| |/ /_   _|   /\            | (_) |  
 | |__) | (___ | |__) | ' /  | |    /  \  _   _  __| |_| |_ 
 |  ___/ \___ \|  ___/|  <   | |   / /\ \| | | |/ ``  | | __|
 | |     ____) | |    | . \ _| |_ / ____ \ |_| | (_| | | |_ 
 |_|    |_____/|_|    |_|\_\_____/_/    \_\__,_|\__,_|_|\__|
  v$($Version)                                                       
                                                            
"@


    $Args = @{}
    if ($PSBoundParameters['CAComputerName']) { $Args['CAComputerName'] = $CAComputerName }
    if ($PSBoundParameters['CAName']) { $Args['CAName'] = $CAName }

    Write-Host -ForegroundColor Green "`n[*] Enumerating certificate authorities with Get-AuditCertificateAuthority...`n"

    $CAs = Get-AuditCertificateAuthority @Args

    ForEach($CA in $CAs) {
        $Args['CAComputerName'] = $CA.ComputerName
        $Args['CAName'] = $CA.Name
        if ($PSBoundParameters['ShowAllVulnerableTemplates']) { $Args['ShowAllVulnerableTemplates'] = $True }

        $CAMisconfigurations = @()
        $TemplateMisconfigurations = @()
        
        Write-Host -ForegroundColor Green "`n`n=== Certificate Authority ==="

        if($CA.VulnerableACL) {
            $CAMisconfigurations += "ESC7"
        }
        if($CA.AllowsUserSuppliedSans) {
            $CAMisconfigurations += "ESC6"
        }
        if($CA.NTLMEnrollmentEndpoints) {
            $CAMisconfigurations += "ESC8"
        }
        
        $CA | Add-Member -MemberType NoteProperty -Name 'Misconfigurations' -Value $($CAMisconfigurations -join ",")
        $CA

        if($CA.Misconfigurations) {
            Write-Host -ForegroundColor Red "[!] The above CA is misconfigured!"
        }

        # get the set of templates published to this CA (or all templates if -ShowAllVulnerableTemplates is passed)
        $CATemplates = Get-AuditCertificateTemplate @Args
        
        foreach($Template in $CATemplates) {
            $TemplateMisconfigurations = @()

            if( (-not $Template.CAManagerApproval) -and 
                ($Template.IssuanceRequirements -match "Authorized signature count: 0") -and 
                ($Template.LowPrivCanEnroll) -and 
                ($Template.HasAuthenticationEku) -and 
                ($Template.EnrolleeSuppliesSubject)
                ) {
                    $TemplateMisconfigurations += "ESC1"
            }

            if( (-not $Template.CAManagerApproval) -and 
                ($Template.IssuanceRequirements -match "Authorized signature count: 0") -and 
                ($Template.LowPrivCanEnroll) -and
                ($Template.HasDangerousEku)
                ) {
                    $TemplateMisconfigurations += "ESC2"
            }

            if( (-not $Template.CAManagerApproval) -and 
                ($Template.IssuanceRequirements -match "Authorized signature count: 0") -and 
                ($Template.LowPrivCanEnroll) -and 
                ($Template.EnrollmentAgentTemplate)
                ) {
                    $TemplateMisconfigurations += "ESC3"
            }

            if ( $Template.VulnerableTemplateACL) {
                    $TemplateMisconfigurations += "ESC4"
            }

            $Template | Add-Member -MemberType NoteProperty -Name 'Misconfigurations' -Value $($TemplateMisconfigurations -join ",")
        }

        if($($CATemplates | Where-Object {$_.Misconfigurations}).Count -eq 0) {
            Write-Host -ForegroundColor Green "`n[*] No vulnerable certificate templates found for this CA."
            Write-Host -ForegroundColor Green "`n[*] NOTE: this is not a guarantee that this CA environment is secure!`n"
        }
        else {
            Write-Host -ForegroundColor Red "`n[!] Potentially vulnerable Certificate Templates:`n"
            $CATemplates | Where-Object {$_.Misconfigurations}
        }

        if($CA.AllowsUserSuppliedSans) {
            $AuthTemplates = $CATemplates | Where-Object {
                $_.HasAuthenticationEku -and
                (-not $_.CAManagerApproval) -and
                ($_.IssuanceRequirements -match 'Authorized signature count: 0') -and
                $_.LowPrivCanEnroll
            }

            if($AuthTemplates.Count -gt 0) {
                Write-Host -ForegroundColor Red "[!] EDITF_ATTRIBUTESUBJECTALTNAME2 set on this CA, the following templates may be vulnerable:`n"
                $AuthTemplates
            }
        }
    }
}


function Get-AuditCertificateAuthority {
    <#
    .SYNOPSIS
    
    Returns security-related information for all (or the specified) certificate authority.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER CAComputerName

    The name of the Certificate Authority computer to return information for.

    .PARAMETER CAName

    The name of the Certificate Authority to return information for.
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $CAComputerName,

        [Parameter()]
        [String]
        $CAName
    )

    $CAs = @()

    if($CAComputerName) {
        $CAs = Get-CertificationAuthority -ComputerName $CAComputerName
    }
    elseif($CAName) {
        $CAs = Get-CertificationAuthority -Name $CAName
    }
    else {
        $CAs = Get-CertificationAuthority
    }

    ForEach($CA in $CAs) {
        $CAServer = $CA.ComputerName
        $CAName = $CA.Name
        Write-Verbose "[Get-AuditCertificateAuthorit] CA: '$CAServer\$CAName'"

        try {
            $CAACL = $CA | Get-CertificationAuthorityAcl
            $DACLString = (($CAACL.Access | ForEach-Object { "$($_.IdentityReference) ($($_.AccessControlType)) - $($_.Rights)"}) -join "`n")

            $EnrollmentPrincipals = ForEach($Ace in $CAACL.Access) {
                if(
                    ($Ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
                    ($Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertSrvRights]::Enroll))
                ) {
                    $Ace.IdentityReference
                }
            }

            $AllowsUserSANs = Test-UserSpecifiesSAN -ComputerName $CAServer -CAName $CAName
        }
        catch {
            Write-Warning "Error enumerating ACL information for CA '$CAServer\$CAName' : $_"
        }

        $CAACLVulnerable = $False
        
        if($CAACL) {
            $CAACLVulnerable = Test-IsCertificateAuthorityACLVulnerable $CAACL
        }

        $EnrollmentEndpoints = Get-ADCSEnrollmentEndpoint -ComputerName $CAServer -CAName $CAName -AuthType "Negotiate"
        $NTLMEnrollmentEndpoints = Get-ADCSEnrollmentEndpoint -ComputerName $CAServer -CAName $CAName -AuthType "NTLM"

        [pscustomobject] @{
            ComputerName = $CAServer
            CAName = $CAName
            ConfigString = "$CAServer\$CAName"
            IsRoot = $CA.IsRoot
            AllowsUserSuppliedSans = $AllowsUserSANs
            VulnerableACL = $CAACLVulnerable
            EnrollmentPrincipals = ($EnrollmentPrincipals -join "`n")
            EnrollmentEndpoints = ($EnrollmentEndpoints -join "|")
            NTLMEnrollmentEndpoints = ($NTLMEnrollmentEndpoints -join "|")
            DACL = $DACLString
        }
    }
}


function Get-ADCSEnrollmentEndpoint {
    <#
    .SYNOPSIS
    
    Given an AD CS server name, return the enrollment endpoints alive/reachable for the given authentication method.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER ComputerName

    The dns hostname of the CA server to check.

    .PARAMETER CANAme

    The CA name.

    .PARAMETER AuthType

    The type of authentication to use for the request, default of Negotiate.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [String]
        $ComputerName,

        [Parameter(Position=1, Mandatory=$True)]
        [String]
        $CAName,

        [Parameter(Position=2)]
        [String]
        [ValidateSet("NTLM", "Negotiate")]
        $AuthType = "Negotiate"
    )

    foreach($P in @("http://", "https://")) {
        foreach($Suffix in @("/certsrv/", "/$($CAName)_CES_Kerberos/service.svc", "/$($CAName)_CES_Kerberos/service.svc/CES", "/ADPolicyProvider_CEP_Kerberos/service.svc", "/certsrv/mscep/")) {
            $URL = "$($P)$($ComputerName)$($Suffix)"
            Write-Verbose "Testing enrollment URL: $URL"
            if(Test-URLEndpoint -URL $URL) {
                $URL
            }
        }
    }
}


function Test-URLEndpoint {
    <#
    .SYNOPSIS
    
    Checks if an HTTP endpoint exists and is reachable given the specified authentication type.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER URL

    The URL of the endpoint to check.

    .PARAMETER AuthType

    The type of authentication to use for the request, default of NTLM.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [String]
        $URL,

        [Parameter(Position=1)]
        [String]
        [ValidateSet("NTLM", "Negotiate")]
        $AuthType = "NTLM"
    )

    $Request = [System.Net.WebRequest]::Create($URL)
    $Cache = New-Object System.Net.CredentialCache
    $Cache.Add([System.Uri]::new($URL), $AuthType, [System.Net.CredentialCache]::DefaultNetworkCredentials)
    
    $Request.Credentials = $Cache
    $Request.Timeout = 3000

    try {
        $Response = $Request.GetResponse()
        return $Response.StatusCode -eq [System.Net.HttpStatusCode]::OK
    }
    catch {
        return $False
    }
}


function Get-AuditCertificateTemplate {
    <#
    .SYNOPSIS
    
    Returns security-related information for certificate templates for all (or the specified) certificate authority.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER CAComputerName

    The name of the Certificate Authority computer to return information for.

    .PARAMETER CAName

    The name of the Certificate Authority to return information for.

    .PARAMETER ShowAllVulnerableTemplates

    Show all vulnerable templates, not just templates published to a CA.
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $CAComputerName,

        [Parameter()]
        [String]
        $CAName,

        [Switch]
        $ShowAllVulnerableTemplates
    )
    
    $CAs = @()

    if($CAComputerName) {
        $CAs = Get-CertificationAuthority -ComputerName $CAComputerName
    }
    elseif($CAName) {
        $CAs = Get-CertificationAuthority -Name $CAName
    }
    else {
        $CAs = Get-CertificationAuthority
    }

    $Templates = Get-CertificateTemplate

    if($ShowAllVulnerableTemplates) {
        ForEach($CATemplate in $Templates) {
            $CATemplateACL = $CATemplate | Get-CertificateTemplateAcl
            $DACLString = (($CATemplateACL.Access | ForEach-Object { "$($_.IdentityReference) ($($_.AccessControlType)) - $($_.Rights)"}) -join "`n")
            $IsTemplateACLVulnerable = Test-IsCertificateTemplateACLVulnerable $CATemplateACL
            $CanLowPrivEnrollInTemplate = Test-CanLowPrivEnrollInTemplate $CATemplateACL
            $EnrolleeSuppliesSubject = $CATemplate.Settings.SubjectName.HasFlag([PKI.CertificateTemplates.CertificateTemplateNameFlags]::EnrolleeSuppliesSubject)

            # Client Authentication - 1.3.6.1.5.5.7.3.2
            # PKINIT Client Authentication - 1.3.6.1.5.2.3.4
            # Smart Card Logon - 1.3.6.1.4.1.311.20.2.2
            # Any Purpose - 2.5.29.37.0
            # SubCA - (no EKUs present)

            $HasAuthenticationEku = ($CATemplate.Settings.EnhancedKeyUsage.Count -eq 0) -or (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'}).Count -gt 0)
            
            $HasDangerousEku = ($CATemplate.Settings.EnhancedKeyUsage.Count -eq 0) -or (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '2\.5\.29\.37\.0'}).Count -gt 0)

            # Certificate Request Agent - 1.3.6.1.4.1.311.20.2.1
            $EnrollmentAgentTemplate = (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'}).Count -gt 0)

            [pscustomobject] @{
                CA = ""
                Name = $CATemplate.Name
                SchemaVersion = $CATemplate.SchemaVersion
                OID = $CATemplate.OID
                VulnerableTemplateACL = $IsTemplateACLVulnerable
                LowPrivCanEnroll = $CanLowPrivEnrollInTemplate
                EnrolleeSuppliesSubject = $EnrolleeSuppliesSubject
                EnhancedKeyUsage = ($CATemplate.Settings.EnhancedKeyUsage -join "|")
                HasAuthenticationEku = $HasAuthenticationEku
                HasDangerousEku = $HasDangerousEku
                EnrollmentAgentTemplate = $EnrollmentAgentTemplate
                CAManagerApproval = $CATemplate.Settings.CAManagerApproval
                IssuanceRequirements = $CATemplate.Settings.RegistrationAuthority.ToString()
                ValidityPeriod = $CATemplate.Settings.ValidityPeriod
                RenewalPeriod = $CATemplate.Settings.RenewalPeriod
                Owner = $CATemplateACL.Owner
                DACL = $DACLString
            }
        }
    }
    else {
        ForEach($CA in $CAs) {

            $CAServer = $CA.ComputerName
            $CAName = $CA.Name

            # get the set of templates published to this CA
            $CATemplateNames = Get-ADObject $CA.DistinguishedName -Properties certificatetemplates | Select-Object -ExpandProperty certificatetemplates
            if ($null -eq $CATemplateNames) { continue }
            $CATemplates = $Templates | Where-Object {$CATemplateNames.Contains($_.Name)}

            try {
                ForEach($CATemplate in $CATemplates) {
                    $CATemplateACL = $CATemplate | Get-CertificateTemplateAcl
                    $DACLString = (($CATemplateACL.Access | ForEach-Object { "$($_.IdentityReference) ($($_.AccessControlType)) - $($_.Rights)"}) -join "`n")
                    $IsTemplateACLVulnerable = Test-IsCertificateTemplateACLVulnerable $CATemplateACL
                    $CanLowPrivEnrollInTemplate = Test-CanLowPrivEnrollInTemplate $CATemplateACL
                    $EnrolleeSuppliesSubject = $CATemplate.Settings.SubjectName.HasFlag([PKI.CertificateTemplates.CertificateTemplateNameFlags]::EnrolleeSuppliesSubject)

                    # Client Authentication - 1.3.6.1.5.5.7.3.2
                    # PKINIT Client Authentication - 1.3.6.1.5.2.3.4
                    # Smart Card Logon - 1.3.6.1.4.1.311.20.2.2
                    # Any Purpose - 2.5.29.37.0
                    # SubCA - (no EKUs present)

                    $HasAuthenticationEku = ($CATemplate.Settings.EnhancedKeyUsage.Count -eq 0) -or (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|2\.5\.29\.37\.0'}).Count -gt 0)
                    
                    $HasDangerousEku = ($CATemplate.Settings.EnhancedKeyUsage.Count -eq 0) -or (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '2\.5\.29\.37\.0'}).Count -gt 0)
                    
                    # Certificate Request Agent - 1.3.6.1.4.1.311.20.2.1
                    $EnrollmentAgentTemplate = (($CATemplate.Settings.EnhancedKeyUsage | Where-Object {$_.Value -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'}).Count -gt 0)

                    [pscustomobject] @{
                        CA = "$CAServer\$CAName"
                        Name = $CATemplate.Name
                        SchemaVersion = $CATemplate.SchemaVersion
                        OID = $CATemplate.OID
                        VulnerableTemplateACL = $IsTemplateACLVulnerable
                        LowPrivCanEnroll = $CanLowPrivEnrollInTemplate
                        EnrolleeSuppliesSubject = $EnrolleeSuppliesSubject
                        EnhancedKeyUsage = ($CATemplate.Settings.EnhancedKeyUsage -join "|")
                        HasAuthenticationEku = $HasAuthenticationEku
                        HasDangerousEku = $HasDangerousEku
                        EnrollmentAgentTemplate = $EnrollmentAgentTemplate
                        CAManagerApproval = $CATemplate.Settings.CAManagerApproval
                        IssuanceRequirements = $CATemplate.Settings.RegistrationAuthority.ToString()
                        ValidityPeriod = $CATemplate.Settings.ValidityPeriod
                        RenewalPeriod = $CATemplate.Settings.RenewalPeriod
                        Owner = $CATemplateACL.Owner
                        DACL = $DACLString
                    }
                }
            }
            catch {
                Write-Error $_
            }
        }
    }
}


function Test-IsCertificateTemplateACLVulnerable {
    <#
    .SYNOPSIS
    
    Returns true if a certicate template ACL is vulnerable.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER Template

    The certificate template ACL to audit.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor]
        $TemplateACL
    )
    
    if((ConvertName-ToSid $TemplateACL.Owner) -match $CommonLowprivPrincipals) {
        return $True
    }

    ForEach($Ace in $TemplateACL.Access) {
        if(
            ($Ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
            ( (ConvertName-ToSid $Ace.IdentityReference) -match $CommonLowprivPrincipals) -and 
            ($Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertTemplateRights]::FullControl) -or $Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertTemplateRights]::Write))
        ) {
            return $True
        }
    }

    return $False
}


function ConvertName-ToSid {
    <#
    .SYNOPSIS
    
    Converts a DOMAIN\username to a domain SID.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER Username

    The username to convert
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [String]
        $Username
    )

    # first check the translation cache
    if($SIDTranslationCache.ContainsKey($Username)) {
        return $SIDTranslationCache[$Username]
    }
    else {
        try {
            $NTAccount = New-Object System.Security.Principal.NTAccount($Username)
            $SID = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $SIDTranslationCache[$Username] = $SID.Value
        }
        catch {
            $SIDTranslationCache[$Username] = $Null
            Write-Warning "Error converting '$Username' to domain SID."
        }

        return $SIDTranslationCache[$Username]
    }
}


function Test-IsCertificateAuthorityACLVulnerable {
    <#
    .SYNOPSIS
    
    Returns true if a certicate authority ACL is vulnerable.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER CAACL

    The certificate authority ACL to audit.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [SysadminsLV.PKI.Security.AccessControl.CertSrvSecurityDescriptor]
        $CAACL
    )
    
    if( (ConvertName-ToSid $CAACL.Owner) -match $CommonLowprivPrincipals) {
        return $True
    }

    ForEach($Ace in $CAACL.Access) {
        if(
            ($Ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
            ( (ConvertName-ToSid $Ace.IdentityReference) -match $CommonLowprivPrincipals) -and 
            ($Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertSrvRights]::ManageCA) -or $Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertSrvRights]::ManageCertificates))
        ) {
            return $True
        }
    }

    return $False
}


function Test-CanLowPrivEnrollInTemplate {
    <#
    .SYNOPSIS
    
    Returns true if default low privileged principals can enroll in a template.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER TemplateACL

    The certificate template ACL to audit.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$True)]
        [SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor]
        $TemplateACL
    )
    
    ForEach($Ace in $TemplateACL.Access) {
        if(
            ($Ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
            ( (ConvertName-ToSid $Ace.IdentityReference) -match $CommonLowprivPrincipals) -and 
            ($Ace.Rights.HasFlag([SysadminsLV.PKI.Security.AccessControl.CertTemplateRights]::Enroll))
        ) {
            return $True
        }
    }

    return $False
}


function Test-UserSpecifiesSAN {
    <#
    .SYNOPSIS

    Returns true if the specified server\CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set.

    License: Ms-PL
    Required Dependencies: PSPKI
    #>
    [CmdletBinding()]
    Param
    ( 
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $ComputerName,

        [Parameter(Position=1, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $CAName
    )

    if (Test-Connection $ComputerName -Count 2 -Quiet) {
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
            $Key = $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CAName)\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
            $Data = $Key.GetValue("EditFlags")
            ($Data -band 0x00040000) -eq 0x00040000
        }
        catch {
            Write-Warning "[Test-UserSpecifiesSAN] Error: $_"
            return $false
        }
    }
    else {
        Write-Warning "[Test-UserSpecifiesSAN] $ComputerName not reachable!"
        return $false
    }
}


function Get-AuditPKIADObjectControllers {
    <#
    .SYNOPSIS

    Returns users who have control or edit rights to PKI AD objects.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER Server

    The domain controller to connect to.

    .PARAMETER Credential

    The credential used to authenticate.

    .EXAMPLE

    $Controllers = Get-AuditPKIADObjectControllers
    Format-PKIAdObjectControllers $Controllers
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]
        $Server,

        [Parameter(Mandatory=$False)]
        [pscredential]
        $Credential
    )

    $ObjectControllers = New-Object 'System.Collections.Generic.SortedDictionary[[string],[System.Collections.ArrayList]]'

    try {
        $RootDse = Get-ADRootDSE @PSBoundParameters -ErrorAction Stop
    } catch {
        throw "Could not query the forest root: $($_)"
    }

    $PkiServicesContainer = "CN=Public Key Services,CN=Services,$($RootDse.configurationNamingContext)"

    foreach($Obj in (Get-ADObject @PSBoundParameters -SearchBase $PkiServicesContainer -Filter * -Properties DistinguishedName,ntsecuritydescriptor)) {
        $Dn = $Obj.DistinguishedName
        
        $Sd = $Obj.ntsecuritydescriptor


        if($null -eq $Sd) {
            Write-Warning "Could not obtain AD security information for the object $($Obj.DistinguishedName)"
            continue
        }

        $OwnerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])

        try {
            $Owner = $sd.GetOwner([System.Security.Principal.NTAccount])
        } catch {
            $Owner = $null
        }

        $Key = "$($Owner)`t$($OwnerSid)"

        if(!$ObjectControllers.ContainsKey($Key)) {
            $ObjectControllers[$Key] = New-Object System.Collections.ArrayList
        }

        $null = $ObjectControllers[$Key].Add([PSCustomObject]@{
            Right = 'Owner'
            ADObject = $Dn
        })
        
        $Dacl = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach($Ace in $Dacl) {
            
            $AceOwnerSid = $Ace.IdentityReference
            try {
                $AceOwner = $AceOwnerSid.Translate([System.Security.Principal.NTAccount])
            } catch {
                $AceOwner = $null
            }
            $Key = "$($AceOwner)`t$($AceOwnerSid)"

            if(!$ObjectControllers.ContainsKey($Key)) {
                $ObjectControllers[$Key] = New-Object System.Collections.ArrayList
            }

            if($Dn -match 'ADObject') {
                $null = $null
            }
            $Right = $Ace.ActiveDirectoryRights

            if($Right.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
                $null = $ObjectControllers[$Key].Add([PSCustomObject]@{
                    Right = 'GenericAll'
                    ADObject = $Dn
                })
            } elseif($Right.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) {
                $null = $ObjectControllers[$Key].Add([PSCustomObject]@{
                    Right = 'WriteOwner'
                    ADObject = $Dn
                })
            } elseif($Right.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) {
                $null = $ObjectControllers[$Key].Add([PSCustomObject]@{
                    Right = 'WriteDacl'
                    ADObject = $Dn
                })
            } elseif($Right.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and $Ace.ObjectType -eq "00000000-0000-0000-0000-000000000000") {
                $null = $ObjectControllers[$Key].Add([PSCustomObject]@{
                    Right = 'WriteAllProperties'
                    ADObject = $Dn
                })
            }
        }
    }

    
    foreach($Entry in $ObjectControllers.GetEnumerator()) {
        $Obj = $Entry.Value
        if($Obj.Count -eq 0) {
            continue
        }
        
        $User,$UserSid = $Entry.Key.Split("`t")

        
        [PSCustomObject]@{
            User = $User
            UserSid = $UserSid
            Access = $Obj
        }
    }
}


function Format-PKIAdObjectControllers {
    <#
    .SYNOPSIS

    Formats the output of Get-AuditPKIADObjectControllers.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER InputObject

    Output objects from Get-AuditPKIADObjectControllers to format.

    .PARAMETER IncludeDefaultAdministrators

    Displays access rights where the principal is a default AD administrator (e.g. Enterprise Admins).

    .EXAMPLE

    $Controllers = Get-AuditPKIADObjectControllers
    Format-PKIAdObjectControllers $Controllers
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $InputObject,

        [switch]
        $IncludeDefaultAdministrators
    )

    Process {
        foreach($Obj in $InputObject) {

            if(!$IncludeDefaultAdministrators -and (
                    $Obj.UserSid.EndsWith('-519') -or
                    $Obj.UserSid.EndsWith('-512') -or
                    $Obj.UserSid -eq 'S-1-5-32-544' -or
                    $Obj.UserSid -eq 'S-1-5-18'
                )) {
                continue
            }

            if([string]::IsNullOrEmpty($Obj.User)) {
                $UserStr = "$($Obj.UserSid)"
            } else {
                $UserStr = "$($Obj.User) ($($Obj.UserSid))"
            }
            
            Write-Host $UserStr -ForegroundColor Red
            foreach($i in $Obj.Access) {
                Write-Host "    $($i.Right.PadRight(18)) $($i.ADObject)"
            }
            Write-Host
        }
    }
}
