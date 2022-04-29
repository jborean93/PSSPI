using System;
using System.Runtime.InteropServices;
using System.Security;

namespace PSSPI;

/// <summary>Interface that is used to acquire a credential handle for certain auth types.</summary>
internal interface ICredentialIdentity
{
    int AcquireCredentialsHandle(
        string? principal,
        string package,
        CredentialUse usage,
        SafeSspiCredentialHandle credential,
        out Helpers.SECURITY_INTEGER expiry);
}

/// <summary>User identity information used to acquire a credential handle.</summary>
public class WinNTAuthIdentity : ICredentialIdentity
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public unsafe char* User;
        public UInt32 UserLength;
        public unsafe char* Domain;
        public UInt32 DomainLength;
        public unsafe void* Password;
        public UInt32 PasswordLength;
        public WinNTAuthIdentityFlags Flags;
    }

    /// <summary>The username of the identity.</summary>
    public string? Username { get; }

    /// <summary>The domain of the identity.</summary>
    public string? Domain { get; }

    /// <summary>The password of the identity.</summary>
    public SecureString? Password { get; }

    public WinNTAuthIdentity(string? username, string? domain, SecureString? password)
    {
        Username = username;
        Domain = domain;
        Password = password;
    }

    int ICredentialIdentity.AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
        SafeSspiCredentialHandle credential, out Helpers.SECURITY_INTEGER expiry)
    {
        IntPtr passwordPtr = IntPtr.Zero;
        try
        {
            if (Password != null)
            {
                passwordPtr = Marshal.SecureStringToGlobalAllocUnicode(Password);
            }

            unsafe
            {
                fixed (char* userPtr = Username, domainPtr = Domain)
                {
                    SEC_WINNT_AUTH_IDENTITY_W authData = new()
                    {
                        User = userPtr,
                        UserLength = (UInt16)(Username?.Length ?? 0),
                        Domain = domainPtr,
                        DomainLength = (UInt16)(Domain?.Length ?? 0),
                        Password = passwordPtr.ToPointer(),
                        PasswordLength = (UInt16)(Password?.Length ?? 0),
                        Flags = WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE,
                    };

                    return SSPI.AcquireCredentialsHandleW(
                        principal,
                        package,
                        usage,
                        IntPtr.Zero,
                        (void*)&authData,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        credential,
                        out expiry);
                }
            }
        }
        finally
        {
            if (passwordPtr != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(passwordPtr);
            }
        }
    }
}

internal enum WinNTAuthIdentityFlags : uint
{
    SEC_WINNT_AUTH_IDENTITY_ANSI = 1,
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 2,
}
