using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Get, "SSPICredential"
)]
[OutputType(typeof(Credential))]
public class GetSSPICredential : PSCmdlet
{
    [Parameter(
        Mandatory = true
    )]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter(typeof(PackageCompletor))]
    public PackageOrString Package { get; set; } = new PackageOrString("");

    [Parameter()]
    public string? Principal { get; set; }

    [Parameter()]
    public CredentialUse CredentialUse { get; set; } = CredentialUse.SECPKG_CRED_OUTBOUND;

    [Parameter()]
    [System.Management.Automation.Credential()]
    [ValidateNotNull()]
    public PSCredential Credential { get; set; } = PSCredential.Empty;

    protected override void EndProcessing()
    {
        ICredentialIdentity? authData = null;
        if (Credential != PSCredential.Empty)
        {
            string username = Credential.UserName;
            string? domain = null;
            if (username.Contains("\\"))
            {
                string[] userSplit = username.Split("\\", 2);
                domain = userSplit[0];
                username = userSplit[1];
            }
            authData = new WinNTAuthIdentity(username, domain, Credential.Password);
        }

        try
        {
            WriteObject(SSPI.AcquireCredentialsHandle(Principal, Package.Name, CredentialUse, authData));
        }
        catch (SspiException e)
        {
            WriteError(new ErrorRecord(e, "NativeException", ErrorCategory.InvalidArgument, Package));
        }
    }
}
