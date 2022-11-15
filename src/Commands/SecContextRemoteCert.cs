using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SecContextRemoteCert"
)]
[OutputType(typeof(X509Certificate2))]
public class GetSecContextRemoteCert : PSCmdlet
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
            IntPtr certContext = IntPtr.Zero;
            try
            {
                unsafe
                {
                    SSPI.QueryContextAttributes(context.SafeHandle, SecPkgAttribute.SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                        &certContext);
                }
            }
            catch (SspiException e)
            {
                WriteError(new ErrorRecord(e, "NativeException", ErrorCategory.InvalidOperation, context));
                continue;
            }

            try
            {
                // dotnet creates a copy of the context for us.
                WriteObject(new X509Certificate2(certContext));
            }
            finally
            {
                Crypt32.CertFreeCertificateContext(certContext);
            }
        }
    }
}
