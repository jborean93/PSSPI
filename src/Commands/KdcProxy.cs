using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.Set, "KdcProxy",
    SupportsShouldProcess = true
)]
public class SetKdcProxy : PSCmdlet
{
    [Parameter(
        Mandatory = true
    )]
    public Credential Credential { get; set; } = null!;

    [Parameter(
        Mandatory = true
    )]
    public string Server { get; set; } = "";

    [Parameter()]
    public SwitchParameter ForceProxy { get; set; }

    protected override void EndProcessing()
    {
        KDCProxyFlags flags = KDCProxyFlags.NONE;
        if (ForceProxy)
        {
            flags |= KDCProxyFlags.KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY;
        }

        int serverLength = Encoding.Unicode.GetByteCount(Server);
        int structLength = Marshal.SizeOf<Helpers.SecPkgCredentials_KdcProxySettingsW>();
        byte[] rawBuffer = new byte[structLength + serverLength];

        unsafe
        {
            fixed (byte* raw = rawBuffer)
            {
                Helpers.SecPkgCredentials_KdcProxySettingsW* settings = (Helpers.SecPkgCredentials_KdcProxySettingsW*)raw;
                settings->Version = 1;  // KDC_PROXY_SETTINGS_V1
                settings->Flags = flags;
                settings->ProxyServerOffset = (ushort)structLength;
                settings->ProxyServerLength = (ushort)Encoding.Unicode.GetByteCount(Server);
                settings->ClientTlsCredOffset = 0;
                settings->ClientTlsCredLength = 0;
            }
        }
        Encoding.Unicode.GetBytes(Server, new Span<byte>(rawBuffer).Slice(structLength));

        try
        {
            if (ShouldProcess("SSPI Credential", $"Set proxy to {Server}"))
            {
                SSPI.SetCredentialsAttributes(
                    Credential.SafeHandle,
                    CredentialAttribute.SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS,
                    rawBuffer);
            }
        }
        catch (SspiException e)
        {
            WriteError(new ErrorRecord(e, "NativeException", ErrorCategory.InvalidArgument, null));
        }
    }
}
