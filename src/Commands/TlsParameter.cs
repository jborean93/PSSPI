using System;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.New, "TlsParameter"
)]
[OutputType(typeof(TlsParameter))]
public class NewTlsParameter : PSCmdlet
{
    [Parameter()]
    public string[] AlpnId { get; set; } = Array.Empty<string>();

    [Parameter()]
    public SchannelProtocols DisabledProtocol { get; set; }

    [Parameter()]
    public CryptoSetting[] DisabledCrypto { get; set; } = Array.Empty<CryptoSetting>();

    [Parameter()]
    public SwitchParameter Optional { get; set; }

    protected override void EndProcessing()
    {
        bool hadError = false;
        if (AlpnId.Length > 16)  // SCH_CRED_MAX_SUPPORTED_ALPN_IDS
        {
            ErrorRecord err = new(
                new ArgumentException("TLS Parameters can not have more than 16 ALPN Ids specified"),
                "TooManyAlpnIds",
                ErrorCategory.InvalidArgument,
                AlpnId
            );
            WriteError(err);
            hadError = true;
        }

        if (DisabledCrypto.Length > 16)  // SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS
        {
            ErrorRecord err = new(
                new ArgumentException("TLS Parameters can not have more than 16 crypto settings specified"),
                "TooManyCryptoSettings",
                ErrorCategory.InvalidArgument,
                DisabledCrypto
            );
            WriteError(err);
            hadError = true;
        }

        if (hadError)
        {
            return;
        }

        WriteObject(new TlsParameter(AlpnId, DisabledProtocol, DisabledCrypto, Optional));
    }
}
