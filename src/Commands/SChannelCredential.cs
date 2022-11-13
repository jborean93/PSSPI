using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SchannelCredential"
)]
[OutputType(typeof(Credential))]
public class GetSchannelCredential : PSCmdlet
{
    [Parameter()]
    public CredentialUse CredentialUse { get; set; } = CredentialUse.SECPKG_CRED_OUTBOUND;

    [Parameter()]
    [ValidateNotNullOrEmpty]
    public X509Certificate[] Certificate { get; set; } = Array.Empty<X509Certificate>();

    [Parameter()]
    public X509Store? RootStore { get; set; }

    [Parameter()]
    public int SessionLifespanMS { get; set; } = 0;

    [Parameter()]
    public SchannelCredFlags Flags { get; set; } = SchannelCredFlags.None;

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    public AlgorithmId[] SupportedAlgs { get; set; } = Array.Empty<AlgorithmId>();

    [Parameter()]
    public SchannelProtocols Protocols { get; set; } = SchannelProtocols.SP_PROT_NONE;

    [Parameter()]
    public int MinimumCipherStrength { get; set; } = 0;

    [Parameter()]
    public int MaximumCipherStrength { get; set; } = 0;

    protected override void EndProcessing()
    {
        if ((CredentialUse & CredentialUse.SECPKG_CRED_INBOUND) != 0 && Certificate.Length == 0)
        {
            ErrorRecord err = new(
                new ArgumentException("At least one certificate must be specified when using SECPKG_CRED_INBOUND"),
                "SchannelCredentialInboundNoCertificate",
                ErrorCategory.InvalidData,
                null);
            WriteError(err);
            return;
        }

        const string package = "Microsoft Unified Security Protocol Provider";
        SchannelCred authData = new(
            certificates: Certificate,
            rootStore: RootStore,
            sessionLifespanMS: SessionLifespanMS,
            flags: Flags,
            supportedAlgs: SupportedAlgs,
            enabledProtocols: Protocols,
            minimumCipherStrength: MinimumCipherStrength,
            maximumCipherStrength: MaximumCipherStrength);

        try
        {
            WriteObject(SSPI.AcquireCredentialsHandle(null, package, CredentialUse, authData));
        }
        catch (SspiException e)
        {
            WriteError(new ErrorRecord(e, "NativeException", ErrorCategory.InvalidArgument, package));
        }
    }
}


[Cmdlet(
    VerbsCommon.Get, "SCHCredential"
)]
[OutputType(typeof(Credential))]
public class GetSCHCredential : PSCmdlet
{
    [Parameter()]
    public CredentialUse CredentialUse { get; set; } = CredentialUse.SECPKG_CRED_OUTBOUND;

    [Parameter()]
    [ValidateNotNullOrEmpty]
    public X509Certificate[] Certificate { get; set; } = Array.Empty<X509Certificate>();

    [Parameter()]
    public X509Store? RootStore { get; set; }

    [Parameter()]
    public int SessionLifespanMS { get; set; } = 0;

    [Parameter()]
    public SchannelCredFlags Flags { get; set; } = SchannelCredFlags.None;

    [Parameter()]
    [ValidateNotNullOrEmpty]
    public TlsParameter[] TlsParameter { get; set; } = Array.Empty<TlsParameter>();


    protected override void EndProcessing()
    {
        bool hadError = false;
        if (TlsParameter.Length > 16)  // SCH_CRED_MAX_SUPPORTED_PARAMETERS
        {
            ErrorRecord err = new(
                new ArgumentException("Schannel credential can not have more than 16 TLS Parameters"),
                "TooManyTlsParameters",
                ErrorCategory.InvalidArgument,
                TlsParameter
            );
            WriteError(err);
            hadError = true;
        }
        if ((CredentialUse & CredentialUse.SECPKG_CRED_INBOUND) != 0 && Certificate.Length == 0)
        {
            ErrorRecord err = new(
                new ArgumentException("At least one certificate must be specified when using SECPKG_CRED_INBOUND"),
                "SCHCredentialInboundNoCertificate",
                ErrorCategory.InvalidData,
                null);
            WriteError(err);
            hadError = true;
        }
        if (hadError)
        {
            return;
        }

        const string package = "Microsoft Unified Security Protocol Provider";
        SCHCredential authData = new(
            certificates: Certificate,
            rootStore: RootStore,
            sessionLifespanMS: SessionLifespanMS,
            flags: Flags,
            tlsParameters: TlsParameter);

        try
        {
            WriteObject(SSPI.AcquireCredentialsHandle(null, package, CredentialUse, authData));
        }
        catch (SspiException e)
        {
            WriteError(new ErrorRecord(e, "NativeException", ErrorCategory.InvalidArgument, package));
        }
    }
}
