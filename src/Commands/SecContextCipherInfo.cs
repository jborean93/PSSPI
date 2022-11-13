using System;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SecContextCipherInfo"
)]
[OutputType(typeof(CipherInfo))]
public class GetSecContextCipherInfo : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public SecurityContext[] Context { get; set; } = Array.Empty<SecurityContext>();

    protected override void ProcessRecord()
    {
        foreach (SecurityContext context in Context)
        {
            string cipherSuite;
            string cipher;

            Span<Helpers.SecPkgContext_CipherInfo> ci = new(new Helpers.SecPkgContext_CipherInfo[1]);
            unsafe
            {
                fixed (Helpers.SecPkgContext_CipherInfo* ciPtr = ci)
                {
                    SSPI.QueryContextAttributes(context.SafeHandle, SecPkgAttribute.SECPKG_ATTR_CIPHER_INFO, (void*)ciPtr);
                }

                fixed (char* cipherSuitePtr = ci[0].szCipherSuite)
                fixed (char* cipherPtr = ci[0].szCipher)
                {
                    cipherSuite = new(cipherSuitePtr);
                    cipher = new(cipherPtr);
                }
            }

            WriteObject(new CipherInfo(
                (TlsProtocol)ci[0].dwProtocol,
                cipherSuite,
                cipher,
                ci[0].dwCipherLen
                ));
        }
    }
}

public class CipherInfo
{
    public TlsProtocol Protocol { get; }
    public string CipherSuite { get; }
    public string Cipher { get; }
    public int CipherLength { get; }

    public CipherInfo(TlsProtocol protocol, string cipherSuite, string cipher, int cipherLength)
    {
        Protocol = protocol;
        CipherSuite = cipherSuite;
        Cipher = cipher;
        CipherLength = cipherLength;
    }
}

public enum TlsProtocol
{
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303,
    TLS1_3 = 0x0304,
}
