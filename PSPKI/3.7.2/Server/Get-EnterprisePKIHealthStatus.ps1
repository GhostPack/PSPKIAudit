function Get-EnterprisePKIHealthStatus {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.EnterprisePKI.X509HealthPath')]
[CmdletBinding(DefaultParameterSetName = '__CA')]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = '__CA'
        )]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificateAuthority,
        [Parameter(Mandatory = $true, ParameterSetName = '__EndCerts')]
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        # configuration
        [int]$DownloadTimeout = 15,
        [ValidateRange(1,99)]
        [int]$CaCertExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$BaseCrlExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$DeltaCrlExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$OcspCertExpirationThreshold = 80
    )
    begin {
#region native function declarations
$cryptnetsignature = @"
[DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool CryptRetrieveObjectByUrl(
    //[MarshalAs(UnmanagedType.LPStr)]
    string pszUrl,
    //[MarshalAs(UnmanagedType.LPStr)]
    int pszObjectOid,
    int dwRetrievalFlags,
    int dwTimeout,
    ref IntPtr ppvObject,
    IntPtr hAsyncRetrieve,
    IntPtr pCredentials,
    IntPtr pvVerify,
    IntPtr pAuxInfo
);
"@
Add-Type -MemberDefinition $cryptnetsignature -Namespace "PKI.EnterprisePKI" -Name Cryptnet
$crypt32signature = @"
[DllImport("Crypt32.dll", SetLastError = true)]
public static extern Boolean CertFreeCertificateContext(
    [In] IntPtr pCertContext
);
[DllImport("Crypt32.dll", SetLastError = true)]
public static extern Boolean CertFreeCRLContext(
    [In] IntPtr pCrlContext
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRL_CONTEXT {
    public int dwCertEncodingType;
    public IntPtr pbCrlEncoded;
    public int cbCrlEncoded;
    public IntPtr pCrlInfo;
    public IntPtr hCertStore;
}
"@
Add-Type -MemberDefinition $crypt32signature -Namespace "PKI.EnterprisePKI" -Name Crypt32
Add-Type @"
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
namespace PKI.EnterprisePKI {
    public enum ChildStatus {
        Ok = 0x0,
        Warning = 0x100,
        Error = 0x8000,
    }
    // 0-49 -- common
    // 50-99 -- certs
    // 100-149 -- crls
    // 150-199 -- ocsp
    public enum UrlStatus {
        // common
        Ok = 0,
        // CRT/CRL/OCSP
        FailedToDownload = 10, NotYetValid = 11, Expired = 12, Expiring = 13,
        InvalidSignature = 14, NetworkRetrievalError = 15,
        // certs only
        Revoked = 50, InvalidCert = 51,
        // CRLs only. ScheduleExpired means that there is a "Next CRL Publish"
        // extension and current time is ahead of "Next CRL Publish value"
        InvalidIssuer = 100, ScheduleExpired = 101, InvalidBase = 102, InvalidCrlType = 103,
        NonCriticalDeltaIndicator = 104, StaleDelta = 105,
        // ocsp only
        MalformedRequest = 151, InternalError = 152, TryLater = 153,
        SignatureRequired = 155, Unauthorized = 156,
        ResponseInvalidData = 160, InvalidSignerCert = 161,
        // CAs only
        Offline,
    }
    public enum UrlType {
        Certificate, Crl, Ocsp
    }
    public class UrlElement {
        ushort error;

        Object hiddenObject;
        public String Name { get; set; }
        public UrlStatus Status {
            get {
                return (UrlStatus)(error & 0xff);
            }
        }
        public String ExtendedErrorInfo { get; set; }
        public Uri Url { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public UrlType UrlType { get; set; }

        public Object GetObject() { return hiddenObject; }
        public void SetObject(Object obj) { hiddenObject = obj; }
        public void SetError(ushort statusCode) {
            error = statusCode;
        }
        public ushort GetError() {
            return error;
        }
        public override String ToString() {
            return Name + ": " + Url + ", expire: " + ExpirationDate + ", Status: " + Status;
        }
    }
    public class CAObject {
        bool isOffline;
        public String Name { get; set; }
        // can be 'Ok', 'Warning', or 'Error'
        public ChildStatus Status {
            get {
                if (isOffline) { return ChildStatus.Error; }
                if (URLs == null) {
                    return ChainStatus == X509ChainStatusFlags.NoError ? ChildStatus.Ok : ChildStatus.Error;
                }
                ChildStatus retValue = ChildStatus.Ok;
                foreach (var url in URLs) {
                    if ((url.GetError() & 0xFF00) > (int)retValue) { retValue = (ChildStatus)(url.GetError() & 0xFF00); }
                }
                return retValue;
            }
        }
        public X509ChainStatusFlags ChainStatus { get; set; }
        public String ExtendedErrorInfo { get; set; }
        public UrlElement[] URLs { get; set; }
        public void Offline() {
            isOffline = true;
        }
    }
    public class X509HealthPath {
        public String Name { get; set; }
        public ChildStatus Status {
            get {
                if (Childs == null || Childs.Length == 0) { return ChildStatus.Ok; }
                return Childs.Any(child => child.Status == ChildStatus.Error)
                    ? ChildStatus.Error
                    : (Childs.Any(child => child.Status == ChildStatus.Warning)
                        ? ChildStatus.Warning
                        : ChildStatus.Ok);
            }
        }
        public CAObject[] Childs { get; set; }
    }
}
"@
#endregion
        #region Error severity
        $s_ok = 0x0
        $s_warning = 0x100
        $s_error = 0x8000
        #endregion

        #region script internal config
        if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
        if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
        $timeout = $DownloadTimeout * 1000
        #endregion

        #region helper functions
        # returns [X509ChainElement[]]
        $chainRoots = @()
        function __getChain([Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
            Write-Verbose "Entering certificate chaining engine."
            $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $status = $chain.Build($cert)
            Write-Debug "Chain status for certificate '$($cert.Subject)': $status"
            if ($chainRoots -notcontains $chain.ChainElements[0].Certificate.Thumbprint) {
                $chainRoots += $chain.ChainElements[0].Certificate.Thumbprint
            }
            $retValue = New-Object Security.Cryptography.X509Certificates.X509ChainElement[] -ArgumentList $chain.ChainElements.Count
            $chain.ChainElements.CopyTo($retValue,0)
            $chain.Reset()
            $retValue
        }
        # returns [X509Certificate2] or [String] that contains error message
        function __downloadCert($url) {
            Write-Debug "Downloading cert URL: $url."
            $ppvObject = [IntPtr]::Zero
            if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,1,4,$timeout,[ref]$ppvObject,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero)
            ) {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ppvObject
                Write-Debug "Certificate: $($cert.Subject)"
                $cert
                [void][PKI.EnterprisePKI.Crypt32]::CertFreeCertificateContext($ppvObject)
            } else {
                $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Debug "URL error: $hresult"
                $CertRequest = New-Object -ComObject CertificateAuthority.Request
                $CertRequest.GetErrorMessageText($hresult,0)
                [PKI.Utils.CryptographyUtils]::ReleaseCom($CertRequest)
            }
        }
        # returns [X509CRL2] or [String] that contains error message
        function __downloadCrl($url) {
            Write-Debug "Downloading CRL URL: $url."
            $ppvObject = [IntPtr]::Zero
            if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,2,4,$timeout,[ref]$ppvObject,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero)
            ) {
                $crlContext = [Runtime.InteropServices.Marshal]::PtrToStructure($ppvObject,[Type][PKI.EnterprisePKI.Crypt32+CRL_CONTEXT])
                $rawData = New-Object byte[] -ArgumentList $crlContext.cbCrlEncoded
                [Runtime.InteropServices.Marshal]::Copy($crlContext.pbCrlEncoded,$rawData,0,$rawData.Length)
                $crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 (,$rawData)
                Write-Debug "CRL: $($crl.Issuer)"
                $crl
                [void][PKI.EnterprisePKI.Crypt32]::CertFreeCRLContext($ppvObject)
            } else {
                $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Debug "URL error: $hresult"
                $CertRequest = New-Object -ComObject CertificateAuthority.Request
                $CertRequest.GetErrorMessageText($hresult,0)
                [PKI.Utils.CryptographyUtils]::ReleaseCom($CertRequest)
            }
        }
        # returns PSObject -- UrlPack
        function __getUrl ([Byte[]]$rawData, [bool]$isCert) {
            Write-Verbose "Getting URLs."
            Write-Debug "Getting URLs."
            $URLs = New-Object psobject -Property @{
                CDP = $null;
                AIA = $null;
                OCSP = $null;
                FreshestCRL = $null;
            }
            $ofs = "`n"
            if ($isCert) {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$rawData)
                # CRL Distribution Points
                Write-Debug "Fetching 'CRL Distribution Points' extension..."
                $e = $cert.Extensions["2.5.29.31"]
                if ($e) {
                    $asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
                    $cdp = New-Object Security.Cryptography.X509Certificates.X509CRLDistributionPointsExtension $asn, $false
                    $URLs.CDP = $cdp.GetURLs()
                    Write-Debug "Found $(($URLs.CDP).Length) CDP URLs."
                    if ($URLs.CDP) {$URLs.CDP | ForEach-Object {Write-Debug "$_"}}
                } else {
                    Write-Debug "Missing 'CRL Distribution Points' extension."
                }
                # Authority Information Access
                Write-Debug "Fetching 'Authority Information Access' extension..."
                $e = $cert.Extensions["1.3.6.1.5.5.7.1.1"]
                if ($e) {
                    $asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
                    $aia = New-Object Security.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension $asn, $false
                    $URLs.AIA = $aia.CertificationAuthorityIssuer
                    Write-Debug "Found $(($URLs.AIA).Length) Certification Authority Issuer URLs."
                    if ($URLs.AIA) {$URLs.AIA | ForEach-Object {Write-Debug $_}}
                    $URLs.OCSP = $aia.OnlineCertificateStatusProtocol
                    Write-Debug "Found $(($URLs.OCSP).Length) On-line Certificate Status Protocol URLs."
                    if ($URLs.OCSP) {$URLs.OCSP | ForEach-Object {Write-Debug $_}}
                } else {
                    Write-Debug "Missing 'Authority Information Access' extension."
                }
                $URLs
            } else {
                Write-Debug "Fetching 'Freshest CRL' extension..."
                $crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 @(,$rawData)
                $e = $crl.Extensions["2.5.29.46"] # Freshest CRL
                if ($e) {
                    $URLs.FreshestCRL = $e.GetURLs()
                    Write-Debug "Found $(($URLs.FreshestCRL).Length) Freshest CRL URLs."
                    if ($URLs.FreshestCRL) {$URLs.FreshestCRL | ForEach-Object {Write-Debug $_}}
                } else {
                    Write-Debug "Missing 'Freshest CRL' extension."
                }
                $URLs
            }
        }
        # returns UrlElement
        function __verifyAIA {
            param (
                [PKI.EnterprisePKI.UrlElement]$urlElement,
                [Security.Cryptography.X509Certificates.X509ChainElement]$CAcert
            )
            Write-Verbose "Entering certificate validation routine."
            Write-Debug "Entering certificate validation routine."
            $cert = $urlElement.GetObject()
            Write-Debug "Leaf certificate: $($cert.Subject)."
            $parent = if ($cert.Subject -eq $cert.Issuer) {
                Write-Debug "Self-signed certificate, issuer is itself."
                $cert
            } else {
                Write-Debug "Issuer candidate: $($CAcert.Certificate.Subject)."
                $CAcert.Certificate
            }
            Write-Debug "Certificate start validity : $($cert.NotBefore)"
            Write-Debug "Certificate end validity   : $($cert.NotAfter)"
            $urlElement.ExpirationDate = $cert.NotAfter
            $subjComp = Compare-Object $cert.SubjectName.RawData $parent.SubjectName.RawData
            $pubKeyComp = Compare-Object $cert.PublicKey.EncodedKeyValue.RawData $parent.PublicKey.EncodedKeyValue.RawData
            $pubKeyParamComp = Compare-Object $cert.PublicKey.EncodedParameters.RawData $parent.PublicKey.EncodedParameters.RawData
            Write-Debug "Subject name binary comparison         : $(if ($subjComp) {'failed'} else {'passed'})"
            Write-Debug "Public key binary comparison           : $(if ($pubKeyComp) {'failed'} else {'passed'})"
            Write-Debug "Public key parameters binary comparison: $(if ($pubKeyParamComp) {'failed'} else {'passed'})"
            $fullTime = ($cert.NotAfter - $cert.NotBefore).TotalSeconds
            $elapsed = ((Get-Date) - $cert.NotBefore).TotalSeconds
            $errorCode = if ($subjComp -or $pubKeyComp -or $pubKeyParamComp) {
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCert
            } elseif ($cert.NotBefore -gt (Get-Date)) {
                Write-Debug "Certificate is not yet valid."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
            } elseif ($cert.NotAfter -lt (Get-Date)) {
                Write-Debug "Certificate is expired."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
            } elseif ($CaCertExpirationThreshold -lt $elapsed / $fullTime * 100) {
                Write-Debug "Certificate is about to expire. Elapsed $([int]($elapsed / $fullTime * 100))%"
                $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
            } else {
                Write-Debug "Certificate passed all validity checks."
                $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
            }
            $urlElement.SetError($errorCode)
            $urlElement
        }
        # returns DateTime or Null (for CRL v1)
        function __getCrlNextPublish($crl) {
            $e = $crl.Extensions["1.3.6.1.4.1.311.21.4"]
            if (!$e) {return}
            $dt = try {
                    (New-Object SysadminsLV.Asn1Parser.Universal.Asn1UtcTime -ArgumentList @(,($e.RawData))).Value
                } catch {
                    [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeGeneralizedTime($e.RawData)
                }
        }
        # returns UrlElement. $cert -- issuer candidate/X509ChainElement.
        function __verifyCDP {
            param(
                [PKI.EnterprisePKI.UrlElement]$urlElement,
                [Security.Cryptography.X509Certificates.X509ChainElement]$cert,
                [Security.Cryptography.X509Certificates.X509CRL2]$BaseCRL,
                [switch]$DeltaCRL
            )
            Write-Verbose "Entering CRL validation routine..."
            Write-Debug "Entering CRL validation routine..."
            $crl = $urlElement.GetObject()
            Write-Debug "$($crl.Type) start validity : $($crl.ThisUpdate)"
            Write-Debug "$($crl.Type) end validity   : $($crl.NextUpdate)"
            $urlElement.ExpirationDate = $crl.NextUpdate
            [Numerics.BigInteger]$dcrlNumber = $crl.GetCRLNumber()
            Write-Debug "CRL number: $dcrlNumber"
            if ($DeltaCRL) {
                [Numerics.BigInteger]$bcrlNumber = $BaseCRL.GetCRLNumber()
                Write-Debug "Referenced Base CRL number: $bcrlNumber"
                $DeltaCrlIndicator = $crl.Extensions["2.5.29.27"]
                if ($DeltaCrlIndicator -ne $null) {
                    [UInt64]$indicator = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeInteger($DeltaCrlIndicator.RawData)
                    Write-Debug "Required minimum Base CRL number: $indicator"
                    [bool]$indicatorIsCritical = $DeltaCrlIndicator.Critical
                } else {
                    Write-Debug "Missing 'Delta CRL Indicator' CRL extension."
                }
            }
            $errorCode = if ($DeltaCRL -and ($crl.Type -ne "DeltaCrl")) {
                Write-Debug "Invalid CRL type. Expected Delta CRL, but received Base CRL."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
            } elseif (!$DeltaCRL -and ($crl.Type -ne "BaseCrl")) {
                Write-Debug "Invalid CRL type. Expected Base CRL, but received Delta CRL."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
            } elseif (!$crl.VerifySignature($cert.Certificate, $true)) {
                Write-Debug "CRL signature check failed."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidIssuer
            } elseif ($crl.ThisUpdate -gt [datetime]::Now) {
                Write-Debug "CRL is not yet valid."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
            } elseif ($crl.NextUpdate -lt [datetime]::Now) {
                Write-Debug "CRL is expired."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
            } elseif ($DeltaCRL -and !$indicatorIsCritical) {
                Write-Debug "'Delta CRL Indicator' is not critical."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NonCriticalDeltaIndicator
            } elseif ($DeltaCRL -and ($bcrlNumber -lt $indicator)) {
                Write-Debug "Base CRL number has lower version than version required by 'Delta CRL Indicator' extension."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidBase
            } elseif ($DeltaCRL -and ($dcrlNumber -lt $bcrlNumber)) {
                Write-Debug "Delta CRL is outdated. A new version of Base CRL is available that overlaps current Delta CRL."
                $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::StaleDelta
            } else {
                $dt = __getCrlNextPublish $crl
                if ($dt) {
                    if ((Get-Date) -gt $dt) {
                        Write-Debug "Scheduled CRL publish expired."
                        $urlElement.SetError($s_warning -bor [PKI.EnterprisePKI.UrlStatus]::ScheduleExpired)
                    }
                    $urlElement
                    return
                }
                $fullTime = ($crl.NextUpdate - $crl.ThisUpdate).TotalSeconds
                $elapsed = ((Get-Date) - $crl.ThisUpdate).TotalSeconds
                if ($DeltaCRL) {
                    if ($DeltaCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
                        Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                } else {
                    if ($BaseCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
                        Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                }
            }
            $urlElement.SetError($errorCode)
            $urlElement
        }
        # returns UrlElement
        function __verifyOCSP {
            param(
                [Security.Cryptography.X509Certificates.X509ChainElement]$cert,
                [PKI.EnterprisePKI.UrlElement]$urlElement
            )
            Write-Verbose "Entering OCSP validation routine..."
            Write-Debug "Entering OCSP validation routine..."
            Write-Debug "URL: $($urlElement.Url.AbsoluteUri)"
            $req = New-Object PKI.OCSP.OCSPRequest $cert.Certificate
            $req.URL = $urlElement.Url
            try {
                $resp = $req.SendRequest()
                $urlElement.SetObject($resp)
                $errorCode = if ($resp.ResponseStatus -ne [PKI.OCSP.OCSPResponseStatus]::Successful) {
                    Write-Debug "OCSP server failed: $($resp.ResponseStatus)"
                    $s_error -bor (150 + $resp.ResponseStatus)
                } elseif (!$resp.SignatureIsValid) {
                    Write-Debug "OCSP response signature validation failed."
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignature
                } elseif ([int]$resp.ResponseErrorInformation) {
                    Write-Debug "Response contains invalid data: $($resp.ResponseErrorInformation)"
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::ResponseInvalidData
                } elseif (!$resp.SignerCertificateIsValid) {
                    Write-Debug "Signer certificate has one or more issues."
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignerCert
                } else {
                    $totalValidity = ($resp.SignerCertificates[0].NotAfter - $resp.SignerCertificates[0].NotBefore).TotalSeconds
                    $elapsed = ((Get-Date) - $resp.SignerCertificates[0].NotBefore).TotalSeconds
                    if ($OcspCertExpirationThreshold -le $elapsed / $totalValidity * 100) {
                        Write-Debug "OCSP signing certificate is about to expire. Elapsed: $($elapsed / $totalValidity * 100)%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        Write-Debug "OCSP response passed all checks."
                        $urlElement.ExpirationDate = $resp.Responses[0].NextUpdate
                        Write-Debug "OCSP response expires: $($urlElement.ExpirationDate)"
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                }
                $urlElement.SetError($errorCode)
            } catch {
                $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::NetworkRetrievalError)
                $urlElement.ExtendedErrorInfo = $_.Error.Exception.Message
            }
            $urlElement
        }
        # returns CAObject
        function __processCerts ($CAObject, $projectedChain) {
            Write-Verbose "Processing Certification Authority Issuer URLs..."
            Write-Debug "Processing Certification Authority Issuer URLs..."
            for ($n = 0; $n -lt $urlPack.AIA.Length; $n++) {
                $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                    Name = "AIA Location #$($n + 1)";
                    Url = $urlPack.AIA[$n];
                    UrlType = [PKI.EnterprisePKI.UrlType]::Certificate;
                }
                $obj = __downloadCert $urlElement.Url
                if ($obj -is [Security.Cryptography.X509Certificates.X509Certificate2]) {
                    $urlElement.SetObject($obj)
                    $urlElement = __verifyAIA $urlElement $projectedChain[$i + 1]
                } else {
                    Write-Debug "Failed to download certificate."
                    $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                    $urlElement.ExtendedErrorInfo = $obj
                }
                $CAObject.URLs += $urlElement
            }
            $CAObject
        }
        # returns CAObject
        function __processOcsp ($CAObject, $projectedChain) {
            Write-Verbose "Processing On-line Certificate Status Protocol URLs..."
            Write-Debug "Processing On-line Certificate Status Protocol URLs..."
            for ($n = 0; $n -lt $urlPack.OCSP.Length; $n++) {
                $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                    Name = "OCSP Location #$($n + 1)";
                    Url = $urlPack.OCSP[$n];
                    UrlType = [PKI.EnterprisePKI.UrlType]::Ocsp;
                }
                $urlElement = __verifyOCSP $projectedChain[$i] $urlElement
                $CAObject.URLs += $urlElement
            }
            $CAObject
        }
        # returns X509HealthPath
        function __validateSinglePath {
            param(
                [Security.Cryptography.X509Certificates.X509Certificate2]$cert,
                # this parameter is not used
                [int]$keyIndex = -1
            )
            Write-Verbose "Entering certification path validation routine..."
            Write-Debug "Entering certification path validation routine..."
            if ([IntPtr]::Zero.Equals($cert.Handle)) {
                throw New-Object PKI.Exceptions.UninitializedObjectException "The certificate is not initialized."
                return
            }
            $projectedChain = __getChain $cert
            [void]($cert.Issuer -match "CN=([^,]+)")
            Write-Debug "CA name: $($matches[1])"
            $out = if ($keyIndex -lt 0) {
                New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = $matches[1]}
            } else {
                New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = "$($matches[1]) ($keyIndex)"}
            }
            for ($i = 0; $i -lt $projectedChain.Length; $i++) {
                Write-Debug "========================= $($projectedChain[$i].Certificate.Issuer) ========================="
                # skip self-signed certificate from checking
                if (!(
                    Compare-Object -ReferenceObject $projectedChain[$i].Certificate.SubjectName.RawData `
                        -DifferenceObject $projectedChain[$i].Certificate.IssuerName.RawData)) {
                    Write-Debug "Leaf certificate is self-signed, skip validation."
                    break
                }
                [void]($projectedChain[$i].Certificate.Issuer -match "CN=([^,]+)")
                $CAObject = if ($keyIndex -lt 0) {
                    New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $matches[1]}
                } else {
                    New-Object PKI.EnterprisePKI.CAObject -Property @{Name = "$($matches[1]) ($keyIndex)"}
                }
                $projectedChain | ForEach-Object {[int]$CAObject.ChainStatus += [int]$_.Status}
                $urlpack = __getUrl $projectedChain[$i].Certificate.RawData $true
                # process and validate certificate issuer in the AIA extension
                $CAObject = __processCerts $CAObject $projectedChain
                # process and validate CDP extensions
                for ($n = 0; $n -lt $urlPack.CDP.Length; $n++) {
                    $deltas = @()
                    $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                        Name = "CDP Location #$($n + 1)";
                        Url = $urlPack.CDP[$n];
                        UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
                    }
                    $obj = __downloadCrl $urlElement.Url
                    if ($obj -is [Security.Cryptography.X509Certificates.X509CRL2]) {
                        $urlElement.SetObject($obj)
                        $urlElement = __verifyCDP $urlElement $projectedChain[$i + 1]
                        $urlPack2 = __getUrl ($urlElement.GetObject()).RawData $false
                        # process and validate FreshestCRL extension if exist
                        for ($m = 0; $m -lt $urlPack2.FreshestCRL.Length; $m++) {
                            # skip duplicate
                            if ($deltas | Where-Object {$_.Url -eq $urlPack2.FreshestCRL[$m]}) {
                                return
                            }
                            $urlElement2 = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                                Name = "DeltaCRL Location #$($m + 1)";
                                Url = $urlPack2.FreshestCRL[$m];
                                UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
                            }
                            $obj2 = __downloadCrl $urlElement2.Url
                            if ($obj2 -is [Security.Cryptography.X509Certificates.X509CRL2]) {
                                $urlElement2.SetObject($obj2)
                                $urlElement2 = __verifyCDP $urlElement2 $projectedChain[$i + 1] $obj -DeltaCRL
                            } else {
                                Write-Debug "Failed to download CRL."
                                $urlElement2.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                                $urlElement2.ExtendedErrorInfo = $obj2
                            }
                            $deltas += $urlElement2
                        }
                    } else {
                        Write-Debug "Failed to download CRL."
                        $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                        $urlElement.ExtendedErrorInfo = $obj
                    }
                    $CAObject.URLs += $urlElement
                    $CAObject.URLs += $deltas
                }
                # process OCSP links in the AIA extension
                $CAObject = __processOcsp $CAObject $projectedChain
                $out.Childs += $CAObject
            }
            $out
        }
        #endregion
        Write-Debug "Initializing parameterset: $($PsCmdlet.ParameterSetName)."
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            '__CA' {
                foreach ($CA in $CertificateAuthority) {
                    if (!$CA.Ping()) {
                        Write-Debug "$($CA.DisplayName): ICertAdmin is down."
                        $retValue = New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $CA.DisplayName}
                        $retValue.Offline()
                        $retValue
                        return
                    }
                    if (!$CA.Type.StartsWith("Enterprise")) {
                        Write-Debug "$($CA.DisplayName): not supported edition. Current: $($CA.Type)."
                        throw "Only Enterprise CAs are supported by this parameterset."
                    }
                    Write-Verbose ("{0} {1} {0}" -f ('=' * 20), $CA.DisplayName)
                    Write-Debug ("{0} {1} {0}" -f ('=' * 20), $CA.DisplayName)
                    Write-Debug "$($CA.DisplayName): retrieving CA Exchange certificate."
                    $xchg = $CA.GetCAExchangeCertificate()
                    __validateSinglePath $xchg
                }
            }
            '__EndCerts' {
                $Certificate | ForEach-Object {__validateSinglePath $_}
            }
        }
    }
}
# SIG # Begin signature block
# MIIfhgYJKoZIhvcNAQcCoIIfdzCCH3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBCeiWmIrNwR/R6
# SZmVcem9oeyJvqy2DkpWL36KgfIZNaCCGYYwggX1MIID3aADAgECAhAdokgwb5sm
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCJxUJ6MfG+r11NPCR9VuUL7grxEcVOHpsJOsNk
# hwNwLjANBgkqhkiG9w0BAQEFAASCAgBCKYHDi2x2VTGEZnENOLzJ/fSNUwh6/95e
# kQ7GP9MSQ/i+Y2U1IM+2SotDlYCU7FdDHwWC5EboesXVNHlPZK/N1sL9ElGuVue1
# y9L8zjjB4fDZ76SkgAUlSTj6F25A6XbGq5T3MBB4UNvA90XQbcvpHsVOvxiEc24b
# eGw+xy0czCHbQKOfH0ixApmZeQlU3JSeHdpExU4fm+/fkOkc/OwXIrG0U0A1eBYU
# 8IrKEZUTxG7lQam2VBw/qsn8AXikIfOBWVb8d0QY0vpHQZkPiBijMUZKt/vpHN7C
# p9k9gURiOsibe+eG7if1SYbcY6qfz9B+GUUVljKP7N9L7dGwxH8tB8kTvsnuaEjS
# ZAsj1K9fjlBOUndwoQrlTlh2ZEJeh2YMXjSbtazQYqzUwV/dHprEgcLH1/+hwGnH
# GRBEii+iFCIqgXoItcwSzT1+mAL2AzwpVmx3Boy1akCJ+3y8D1MY2Cqoa+/rwZaw
# PzDw4JFPQ86T3pGxu7i7sYrqHNp1ndXwLDrbySXaHiRFDKMxnE3T+Ij8rSBB7ApP
# /o4mvDDVjg8s8oI7SH8CSiPiUtUrMcUFutHzVm9DjT69COlumSuIBck/F/WZPuYt
# Y3f+ypDe+oTazUDdSJoqMKk7HJeIrR9DeMG7MEGxvyG7oqJWdHdoJWHmaB8oo1TQ
# +oHwqTMnaKGCAg8wggILBgkqhkiG9w0BCQYxggH8MIIB+AIBATB2MGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQAwGa
# Ajr/WLFr1tXq5hfwZjAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwODAzMTUyNjE2WjAjBgkqhkiG9w0BCQQx
# FgQUxf0NsoLUgn4A3CvedlrABDfl1yYwDQYJKoZIhvcNAQEBBQAEggEALdAHsx2W
# bGrsPVOaKPyCUv4AZ2W12bm7jPuOqI+B5fLQLwQ+U2KSt7tINMAzJg+GSXN3M123
# /TwfGA2/6NlPin/q6nssTA9pNWH9Ohu4HDgYet6jJ2HGpACbUC8DUV+5XUK5yYHq
# WWrfL/hpRDcvCfGMkB9y8Hm6FBuxQjMxW4XMcQN9JJL9c2BWR1Q2FqqC4QznU6WK
# 1cxlEz8fGJsS7zqcLtaFSGNchWA1Z6lqw0zvRJ+SqMjNLS2Hp4HwHZftyqtL6tF5
# tEmPi2LPffF3r1R8mdop4eT9Mh4rR+DqaPq6V7E1lBRRqq1GG47CQuMNjoNigF6H
# LIygRhIdkw8QpQ==
# SIG # End signature block
