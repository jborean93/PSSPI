using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.New, "CryptoSetting"
)]
[OutputType(typeof(CryptoSetting))]
public class NewCryptoSetting : PSCmdlet
{
    [Parameter(Mandatory = true)]
    public SchannelCryptoUsage Usage { get; set; }

    [Parameter(Mandatory = true)]
    [ArgumentCompleter(typeof(AlgorithmCompleter))]
    public string Algorithm { get; set; } = "";

    [Parameter()]
    [ArgumentCompleter(typeof(ChainingModeCompleter))]
    public string[] ChainingMode { get; set; } = Array.Empty<string>();

    [Parameter()]
    public int MinBitLength { get; set; }

    [Parameter()]
    public int MaxBitLength { get; set; }

    protected override void EndProcessing()
    {
        if (ChainingMode.Length > 16)  // SCH_CRED_MAX_SUPPORTED_CHAINING_MODES
        {
            ErrorRecord err = new(
                new ArgumentException("Crypto Settings can not have more than 16 chaining modes specified"),
                "TooManyChainingModes",
                ErrorCategory.InvalidArgument,
                ChainingMode
            );
            WriteError(err);
            return;
        }

        WriteObject(new CryptoSetting(Usage, Algorithm, ChainingMode, MinBitLength, MaxBitLength));
    }

    private class AlgorithmCompleter : IArgumentCompleter
    {
        public IEnumerable<CompletionResult>? CompleteArgument(string commandName, string parameterName,
                string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
        {
            if (String.IsNullOrWhiteSpace(wordToComplete))
                wordToComplete = "";

            SchannelCryptoUsage? usage = null;
            if (fakeBoundParameters.Contains("Usage"))
            {
                object? rawUsage = fakeBoundParameters["Usage"];
                if (rawUsage is SchannelCryptoUsage parsedUsage)
                {
                    usage = parsedUsage;
                }
                else if (Enum.TryParse<SchannelCryptoUsage>(rawUsage?.ToString() ?? "", true,
                    out var cryptoUsage))
                {
                    usage = cryptoUsage;
                }
            }

            // https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-crypto_settings
            // Most examples from the above but some are based on the list of TLS ciphers supported by MS.
            HashSet<string> kexchValues = new() { "DH", "ECDH", "PSK", "RSA" };
            HashSet<string> sigValues = new() { "DSA", "DSS", "ECDSA", "EXPORT", "EXPORT1024", "RSA" };
            HashSet<string> cipherValues = new() { "3DES", "AES", "DES", "CHACHA20_POLY1305", "RC4" };
            HashSet<string> digestValues = new() { "MD5", "SHA1", "SHA256", "SHA384" };
            HashSet<string> certSigValues = new() { "DSA", "ECDSA", "RSA", "SHA1", "SHA256" };

            HashSet<string> availableOptions = new();
            if (usage == null)
            {
                availableOptions.UnionWith(kexchValues);
                availableOptions.UnionWith(sigValues);
                availableOptions.UnionWith(cipherValues);
                availableOptions.UnionWith(digestValues);
                availableOptions.UnionWith(certSigValues);
            }
            else if (usage == SchannelCryptoUsage.KeyExchange)
            {
                availableOptions = kexchValues;
            }
            else if (usage == SchannelCryptoUsage.Signature)
            {
                availableOptions = sigValues;
            }
            else if (usage == SchannelCryptoUsage.Cipher)
            {
                availableOptions = cipherValues;
            }
            else if (usage == SchannelCryptoUsage.Digest)
            {
                availableOptions = digestValues;
            }
            else if (usage == SchannelCryptoUsage.CertSig)
            {
                availableOptions = certSigValues;
            }

            foreach (string option in availableOptions)
            {
                if (option.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
                {
                    yield return new CompletionResult(option);
                }
            }
        }
    }

    private class ChainingModeCompleter : IArgumentCompleter
    {
        public IEnumerable<CompletionResult>? CompleteArgument(string commandName, string parameterName,
                string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
        {
            if (String.IsNullOrWhiteSpace(wordToComplete))
                wordToComplete = "";

            // https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
            // BCRYPT_CHAINING_MODE
            HashSet<string> availableOptions = new() {
                "ChainingModeCBC",
                "ChainingModeCCM",
                "ChainingModeCFB",
                "ChainingModeECB",
                "ChainingModeGCM",
                "ChainingModeN/A",
            };

            foreach (string option in availableOptions)
            {
                if (option.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
                {
                    yield return new CompletionResult(option);
                }
            }
        }
    }
}
