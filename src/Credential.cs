using System;

namespace PSSPI;

/// <summary>Result of <c>AcquireCredentialsHandle</c>.</summary>
public class Credential
{
    /// <summary>The handle to the SSPI credential.</summary>
    public SafeSspiCredentialHandle SafeHandle { get; }

    /// <summary>The number of ticks (100s of nanoseconds) since 1601-01-01 until the credential expires.</summary>
    public UInt64 Expiry { get; }

    internal Credential(SafeSspiCredentialHandle creds, UInt64 expiry)
    {
        SafeHandle = creds;
        Expiry = expiry;
    }
}
