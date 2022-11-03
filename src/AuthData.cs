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
    private struct SEC_WINNT_AUTH_IDENTITY_EXW
    {
        public const int SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200;

        public UInt32 Version;
        public UInt32 Length;
        public unsafe char* User;
        public UInt32 UserLength;
        public unsafe char* Domain;
        public UInt32 DomainLength;
        public unsafe void* Password;
        public UInt32 PasswordLength;
        public WinNTAuthIdentityFlags Flags;
        public unsafe char* PackageList;
        public UInt32 PackageListLength;
    }

    /// <summary>The username of the identity.</summary>
    public string? Username { get; }

    /// <summary>The domain of the identity.</summary>
    public string? Domain { get; }

    /// <summary>The password of the identity.</summary>
    public SecureString? Password { get; }

    /// <summary>List of auth packages separated by commas the credential can use.</summary>
    public string? PackageList { get; }

    public WinNTAuthIdentity(string? username, string? domain, SecureString? password, string? packageList)
    {
        Username = username;
        Domain = domain;
        Password = password;
        PackageList = packageList;
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
                fixed (char* userPtr = Username, domainPtr = Domain, packageListPtr = PackageList)
                {
                    SEC_WINNT_AUTH_IDENTITY_EXW authData = new()
                    {
                        Version = SEC_WINNT_AUTH_IDENTITY_EXW.SEC_WINNT_AUTH_IDENTITY_VERSION,
                        Length = (uint)Marshal.SizeOf<SEC_WINNT_AUTH_IDENTITY_EXW>(),
                        User = userPtr,
                        UserLength = (uint)(Username?.Length ?? 0),
                        Domain = domainPtr,
                        DomainLength = (uint)(Domain?.Length ?? 0),
                        Password = passwordPtr.ToPointer(),
                        PasswordLength = (uint)(Password?.Length ?? 0),
                        Flags = WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE,
                        PackageList = packageListPtr,
                        PackageListLength = (uint)(PackageList?.Length ?? 0),
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

[Flags]
internal enum WinNTAuthIdentityFlags : uint
{
    NONE = 0x00000000,
    SEC_WINNT_AUTH_IDENTITY_ANSI = 0x00000001,
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x00000002,
    SEC_WINNT_AUTH_IDENTITY_MARSHALLED = 0x00000004,
    SEC_WINNT_AUTH_IDENTITY_ONLY = 0x00000008,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED = 0x00000010,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED = 0x00000020,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED = 0x00000040,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED = 0x00010000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER = 0x00020000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN = 0x00040000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER = 0x00080000,
}
