using System;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SSPIPackage"
)]
[OutputType(typeof(SecPackageInfo))]
public class GetSSPIPackage : PSCmdlet
{
    [Parameter(
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [ArgumentCompleter(typeof(PackageCompletor))]
    public string[] Name { get; set; } = Array.Empty<string>();

    protected override void ProcessRecord()
    {
        if (Name.Length == 0)
        {
            try
            {
                WriteObject(SSPI.EnumerateSecurityPackages(), true);
            }
            catch (SspiException e)
            {
                WriteError(new ErrorRecord(e, "NativeError", ErrorCategory.InvalidOperation, null));
            }
        }
        else
        {
            foreach (string packageName in Name)
            {
                try
                {
                    WriteObject(SSPI.QuerySecurityPackageInfo(packageName));
                }
                catch (SspiException e)
                {
                    WriteError(new ErrorRecord(e, "InvalidPackage", ErrorCategory.InvalidArgument, packageName));
                }
            }
        }
    }
}
