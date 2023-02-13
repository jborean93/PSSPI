using System;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SecContextSizes"
)]
[OutputType(typeof(ContextSizes))]
public class GetSecContextSizes : PSCmdlet
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
            Span<Helpers.SecPkgContext_Sizes> sizes = new(new Helpers.SecPkgContext_Sizes[1]);
            unsafe
            {
                fixed (Helpers.SecPkgContext_Sizes* sizesPtr = sizes)
                {
                    SSPI.QueryContextAttributes(context.SafeHandle, SecPkgAttribute.SECPKG_ATTR_SIZES, (void*)sizesPtr);
                }

                WriteObject(new ContextSizes(sizes[0].cbMaxToken, sizes[0].cbMaxSignature, sizes[0].cbBlockSize,
                    sizes[0].cbSecurityTrailer));
            }
        }
    }
}

public sealed class ContextSizes
{
    public UInt32 MaxToken { get; }
    public UInt32 MaxSignature { get; }
    public UInt32 BlockSize { get; }
    public UInt32 SecurityTrailer { get; }

    public ContextSizes(uint maxToken, uint maxSignature, uint blockSize, uint securityTrailer)
    {
        MaxToken = maxToken;
        MaxSignature = maxSignature;
        BlockSize = blockSize;
        SecurityTrailer = securityTrailer;
    }
}
