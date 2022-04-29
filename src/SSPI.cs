using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;

namespace PSSPI;

internal static class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_CHANNEL_BINDINGS
    {
        public UInt32 dwInitiatorAddrType;
        public UInt32 cbInitiatorLength;
        public UInt32 dwInitiatorOffset;
        public UInt32 dwAcceptorAddrType;
        public UInt32 cbAcceptorLength;
        public UInt32 dwAcceptorOffset;
        public UInt32 cbApplicationDataLength;
        public UInt32 dwApplicationDataOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public UInt32 LowPart;
        public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc
    {
        public UInt32 ulVersion;
        public UInt32 cBuffers;
        public IntPtr pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer
    {
        public UInt32 cbBuffer;
        public UInt32 BufferType;
        public IntPtr pvBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public UIntPtr dwLower;
        public UIntPtr dwUpper;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SecPkgCredentials_KdcProxySettingsW
    {
        public UInt32 Version;
        public KDCProxyFlags Flags;
        public UInt16 ProxyServerOffset;
        public UInt16 ProxyServerLength;
        public UInt16 ClientTlsCredOffset;
        public UInt16 ClientTlsCredLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public UInt32 cbMaxToken;
        public UInt32 cbMaxSignature;
        public UInt32 cbBlockSize;
        public UInt32 cbSecurityTrailer;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SecPkgInfoW
    {
        public PackageCapabilities fCapabilities;
        public UInt16 wVersion;
        public UInt16 wRPCID;
        public UInt32 cbMaxToken;
        public unsafe char* Name;
        public unsafe char* Comment;
    }
}

internal static class SSPI
{
    internal const int SEC_E_OK = 0x00000000;
    internal const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    internal const int SEC_I_COMPLETE_NEEDED = 0x00090313;
    internal const int SEC_I_COMPLETE_AND_CONTINUE = 0x00090314;

    [DllImport("Secur32.dll", EntryPoint = "AcceptSecurityContext")]
    private static unsafe extern Int32 NativeAcceptSecurityContext(
        SafeSspiCredentialHandle? phCredential,
        SafeSspiContextHandle phContext,
        Helpers.SecBufferDesc* pInput,
        AcceptorContextRequestFlags fContextReq,
        TargetDataRep TargetDataRep,
        SafeSspiContextHandle phNewContext,
        Helpers.SecBufferDesc* pOutput,
        out AcceptorContextReturnFlags pfContextAttr,
        out Helpers.SECURITY_INTEGER ptsExpiry);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    internal static unsafe extern Int32 AcquireCredentialsHandleW(
        [MarshalAs(UnmanagedType.LPWStr)] string? pszPrincipal,
        [MarshalAs(UnmanagedType.LPWStr)] string pPackage,
        CredentialUse fCredentialUse,
        IntPtr pvLogonId,
        void* pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        SafeSspiCredentialHandle phCredential,
        out Helpers.SECURITY_INTEGER ptsExpiry);

    [DllImport("Secur32.dll", EntryPoint = "DecryptMessage")]
    private static extern Int32 DecryptMessageNative(
        SafeSspiContextHandle phContext,
        ref Helpers.SecBufferDesc pMessage,
        UInt32 MessageSeqNo,
        out UInt32 pfQOP);

    [DllImport("Secur32.dll")]
    public static extern Int32 DeleteSecurityContext(
        IntPtr phContext);

    [DllImport("Secur32.dll", EntryPoint = "EncryptMessage")]
    private static extern Int32 EncryptMessageNative(
        SafeSspiContextHandle phContext,
        UInt32 fQOP,
        ref Helpers.SecBufferDesc pMessage,
        UInt32 MessageSeqNo);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static extern Int32 EnumerateSecurityPackagesW(
        out UInt32 pcPackages,
        out IntPtr ppPackageInfo);

    [DllImport("Secur32.dll")]
    public static extern Int32 FreeContextBuffer(
        IntPtr pvContextBuffer);

    [DllImport("Secur32.dll")]
    public static extern Int32 FreeCredentialsHandle(
        IntPtr phCredential);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static unsafe extern Int32 InitializeSecurityContextW(
        SafeSspiCredentialHandle? phCredential,
        SafeSspiContextHandle phContext,
        [MarshalAs(UnmanagedType.LPWStr)] string pszTargetName,
        InitiatorContextRequestFlags fContextReq,
        UInt32 Reserved1,
        TargetDataRep TargetDataRep,
        Helpers.SecBufferDesc* pInput,
        UInt32 Reserved2,
        SafeSspiContextHandle phNewContext,
        Helpers.SecBufferDesc* pOutput,
        out InitiatorContextReturnFlags pfContextAttr,
        out Helpers.SECURITY_INTEGER ptsExpiry);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static extern Int32 SetCredentialsAttributesW(
        SafeSspiCredentialHandle phCredential,
        CredentialAttribute ulAttribute,
        IntPtr pBuffer,
        UInt32 cbBuffer);

    [DllImport("Secur32.dll", EntryPoint = "QueryContextAttributes")]
    private static extern Int32 QueryContextAttributesNative(
        SafeSspiContextHandle phContext,
        SecPkgAttribute ulAttribute,
        IntPtr pBuffer);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static extern Int32 QuerySecurityPackageInfoW(
        string pPakcageName,
        out IntPtr ppPackageInfo);

    /// <summary>Accepts a security context or processes a new token on an existing context.</summary>
    /// <param name="context">The security context to use.</param>
    /// <param name="contextReq">Request flags to set.</param>
    /// <param name="dataRep">The data representation on the target.</param>
    /// <param name="input">Optional token received from the initiator acceptor or null for the first call.</param>
    /// <param name="output">Output token buffers to receive from the caller.</param>
    /// <param name="contextAttr">Output context attributes from the context call.</param>
    /// <returns>The return value of the call.</returns>
    /// <exception cref="SspiException">Failure accepting the security context.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext">AcceptSecurityContext</see>
    public static int AcceptSecurityContext(SecurityContext context, AcceptorContextRequestFlags contextReq,
        TargetDataRep dataRep, ReadOnlySpan<Helpers.SecBuffer> input, ReadOnlySpan<Helpers.SecBuffer> output,
        out AcceptorContextReturnFlags contextAttr)
    {
        SafeSspiContextHandle inputContext = context.SafeHandle;
        SafeSspiContextHandle outputContext = inputContext == SafeSspiContextHandle.NULL_CONTEXT
            ? new SafeSspiContextHandle()
            : inputContext;

        unsafe
        {
            fixed (Helpers.SecBuffer* inputPtr = input, outputPtr = output)
            {
                Helpers.SecBufferDesc inputDesc = new();
                Helpers.SecBufferDesc* inputDescPtr = null;
                if (input.Length > 0)
                {
                    inputDesc.ulVersion = 0;
                    inputDesc.cBuffers = (UInt32)input.Length;
                    inputDesc.pBuffers = (IntPtr)inputPtr;
                    inputDescPtr = &inputDesc;
                }

                Helpers.SecBufferDesc outputDesc = new();
                Helpers.SecBufferDesc* outputDescPtr = null;
                if (output.Length > 0)
                {
                    outputDesc.ulVersion = 0;
                    outputDesc.cBuffers = (UInt32)output.Length;
                    outputDesc.pBuffers = (IntPtr)outputPtr;
                    outputDescPtr = &outputDesc;
                }

                int res = NativeAcceptSecurityContext(
                    context.Credential?.SafeHandle,
                    inputContext,
                    inputDescPtr,
                    contextReq,
                    dataRep,
                    outputContext,
                    outputDescPtr,
                    out contextAttr,
                    out var expiryStruct);

                if (
                    res != SEC_E_OK &&
                    res != SEC_I_CONTINUE_NEEDED &&
                    res != SEC_I_COMPLETE_NEEDED &&
                    res != SEC_I_COMPLETE_AND_CONTINUE
                )
                {
                    throw new SspiException(res, "AcceptSecurityContext");
                }

                context.SafeHandle = outputContext;
                context.Expiry = (UInt64)expiryStruct.HighPart << 32 | (UInt64)expiryStruct.LowPart;
                return res;
            }
        }
    }

    /// <summary>Acquire SSPI credential.</summary>
    /// <param name="principal">The name of the principal whose credentials the handle will reference.</param>
    /// <param name="package">The name of the SSPI security provide the credentials will be used for.</param>
    /// <param name="usage">How the credentials will be used.</param>
    /// <param name="authData">
    /// The credential logon information or <c>null</c> to use the current user's credentials.
    /// </param>
    /// <returns>Credential information including the handle to the credential itself.</returns>
    /// <exception href="SspiException">Error when retrieving the credential.</exception>
    /// <see cref="https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general">AcquireCredentialsHandle</see>
    public static Credential AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
        ICredentialIdentity? authData)
    {
        SafeSspiCredentialHandle cred = new();
        Helpers.SECURITY_INTEGER expiry;
        int res;

        if (authData == null)
        {
            unsafe
            {
                res = AcquireCredentialsHandleW(
                    principal,
                    package,
                    usage,
                    IntPtr.Zero,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    cred,
                    out expiry);
            }
        }
        else
        {
            res = authData.AcquireCredentialsHandle(principal, package, usage, cred, out expiry);
        }

        if (res != 0)
            throw new SspiException(res, "AcquireCredentialsHandle");

        UInt64 expiryValue = (UInt64)expiry.HighPart << 32 | (UInt64)expiry.LowPart;
        return new Credential(cred, expiryValue);
    }

    /// <summary>Decrypts the input message.</summary>
    /// <remarks>
    /// The message is decrypted in place, use the input message buffers to retrieve the decrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to decrypt the message.</param>
    /// <param name="message">The security buffers to decrypt.</param>
    /// <param name="seqNo">The expected sequence number of the encrypted message.</param>
    /// <returns>The quality of protection that had applied to the encrypted message.</returns>
    /// <exception cref="SspiException">Failure trying to decrypt the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general">DecryptMessage</see>
    public static UInt32 DecryptMessage(SafeSspiContextHandle context, Span<Helpers.SecBuffer> message, UInt32 seqNo)
    {
        unsafe
        {
            fixed (Helpers.SecBuffer* messagePtr = message)
            {
                Helpers.SecBufferDesc bufferDesc = new()
                {
                    ulVersion = 0,
                    cBuffers = (UInt32)message.Length,
                    pBuffers = (IntPtr)messagePtr,
                };

                int res = DecryptMessageNative(context, ref bufferDesc, seqNo, out var qop);
                if (res != 0)
                    throw new SspiException(res, "DecryptMessage");

                return qop;
            }
        }
    }

    /// <summary>Encrypts the input message.</summary>
    /// <remarks>
    /// The message is encrypted in place, use the input message buffers to retrieve the encrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to encrypt the message.</param>
    /// <param name="qop">The quality of protection to apply to the message.</param>
    /// <param name="message">The security buffers to encrypt.</param>
    /// <param name="seqNo">The sequence number to apply to the encrypted message.</param>
    /// <exception cref="SspiException">Failure trying to entry the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general">EncryptMessage</see>
    public static void EncryptMessage(SafeSspiContextHandle context, UInt32 qop, Span<Helpers.SecBuffer> message,
        UInt32 seqNo)
    {
        unsafe
        {
            fixed (Helpers.SecBuffer* messagePtr = message)
            {
                Helpers.SecBufferDesc bufferDesc = new()
                {
                    ulVersion = 0,
                    cBuffers = (UInt32)message.Length,
                    pBuffers = (IntPtr)messagePtr,
                };

                int res = EncryptMessageNative(context, qop, ref bufferDesc, seqNo);
                if (res != 0)
                    throw new SspiException(res, "EncryptMessage");
            }
        }
    }

    /// <summary>Retrieves all installed security packages.</summary>
    /// <returns>All installed security packages.</returns>
    /// <exception cref="SspiException">Failure trying to query the installed packages.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw">EnumerateSecurityPackagesW</see>
    public static SecPackageInfo[] EnumerateSecurityPackages()
    {
        int res = EnumerateSecurityPackagesW(out var count, out var info);
        if (res != 0)
            throw new SspiException(res, "EnumerateSecurityPackages");

        try
        {
            unsafe
            {
                ReadOnlySpan<Helpers.SecPkgInfoW> packages = new (info.ToPointer(), (int)count);
                return packages.ToArray().Select((p) => new SecPackageInfo(p)).ToArray();
            }
        }
        finally
        {
            FreeContextBuffer(info);
        }
    }

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <param name="context">The security context to use.</param>
    /// <param name="targetName">The target name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="contextReq">Request flags to set.</param>
    /// <param name="dataRep">The data representation on the target.</param>
    /// <param name="input">Optional token received from the acceptor or null for the first call.</param>
    /// <param name="output">Output token buffers to receive from the caller.</param>
    /// <param name="contextAttr">Output context attributes from the context call.</param>
    /// <returns>The result of the call containing the result code, output buffer, and context attributes.</returns>
    /// <exception cref="SspiException">Failure initiating/continuing the security context.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--general">InitializeSecurityContext</see>
    public static int InitializeSecurityContext(SecurityContext context, string targetName,
        InitiatorContextRequestFlags contextReq, TargetDataRep dataRep, ReadOnlySpan<Helpers.SecBuffer> input,
        ReadOnlySpan<Helpers.SecBuffer> output, out InitiatorContextReturnFlags contextAttr)
    {
        SafeSspiContextHandle inputContext = context.SafeHandle;
        SafeSspiContextHandle outputContext = inputContext == SafeSspiContextHandle.NULL_CONTEXT
            ? new SafeSspiContextHandle()
            : inputContext;

        unsafe
        {
            fixed (Helpers.SecBuffer* inputPtr = input, outputPtr = output)
            {
                Helpers.SecBufferDesc inputDesc = new();
                Helpers.SecBufferDesc* inputDescPtr = null;
                if (input.Length > 0)
                {
                    inputDesc.ulVersion = 0;
                    inputDesc.cBuffers = (UInt32)input.Length;
                    inputDesc.pBuffers = (IntPtr)inputPtr;
                    inputDescPtr = &inputDesc;
                }

                Helpers.SecBufferDesc outputDesc = new();
                Helpers.SecBufferDesc* outputDescPtr = null;
                if (output.Length > 0)
                {
                    outputDesc.ulVersion = 0;
                    outputDesc.cBuffers = (UInt32)output.Length;
                    outputDesc.pBuffers = (IntPtr)outputPtr;
                    outputDescPtr = &outputDesc;
                }

                int res = InitializeSecurityContextW(
                    context.Credential?.SafeHandle,
                    inputContext,
                    targetName,
                    contextReq,
                    0,
                    dataRep,
                    inputDescPtr,
                    0,
                    outputContext,
                    outputDescPtr,
                    out contextAttr,
                    out var expiryStruct);

                if (
                    res != SEC_E_OK &&
                    res != SEC_I_CONTINUE_NEEDED &&
                    res != SEC_I_COMPLETE_NEEDED &&
                    res != SEC_I_COMPLETE_AND_CONTINUE
                )
                {
                    throw new SspiException(res, "InitializeSecurityContextW");
                }

                context.SafeHandle = outputContext;
                context.Expiry = (UInt64)expiryStruct.HighPart << 32 | (UInt64)expiryStruct.LowPart;
                return res;
            }
        }
    }

    /// <summary>Sets the attributes of a credential.</summary>
    /// <remarks>The information is valid for any security context created with the specified credential.</remarks>
    /// <param name="credential">The credential to set the attribute on.</param>
    /// <param name="attribute">The type of value to set.</param>
    /// <param name="buffer">The raw value to set.</param>
    /// <exception cref="SspiException">Failure trying to set the requested value.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesw">SetCredentialsAttributesW</see>
    public static void SetCredentialsAttributes(SafeSspiCredentialHandle credential, CredentialAttribute attribute,
        byte[] buffer)
    {
        unsafe
        {
            fixed (byte* bufferPtr = buffer)
            {
                int res = SetCredentialsAttributesW(credential, attribute, (IntPtr)bufferPtr, (uint)buffer.Length);
                if (res != 0)
                {
                    throw new SspiException(res, "SetCredentialsAttributes");
                }
            }
        }
    }

    /// <summary>Query the security context for a specific value.</summary>
    /// <remarks>The buffer supplied must be large enough to fill the requested attribute value.</remarks>
    /// <param name="context">The security context to query.</param>
    /// <param name="attribute">The type of value to query.</param>
    /// <param name="buffer">The buffer that will store the queried value.</param>
    /// <exception cref="SspiException">Failure trying to query the requested value.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general">QueryContextAttributes</see>
    public static void QueryContextAttributes(SafeSspiContextHandle context, SecPkgAttribute attribute, IntPtr buffer)
    {
        int res = QueryContextAttributesNative(context, attribute, buffer);
        if (res != 0)
            throw new SspiException(res, "QueryContextAttributes");
    }

    /// <summary>Retrieves information about a specified security package.</summary>
    /// <param name="name">The name of the security package to query</param>
    /// <returns>Package information</returns>
    /// <exception cref="SspiException">Failure trying to query the requested package.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow">QuerySecurityPackageInfoW</see>
    public static SecPackageInfo QuerySecurityPackageInfo(string name)
    {
        int res = QuerySecurityPackageInfoW(name, out var info);
        if (res != 0)
            throw new SspiException(res, "QuerySecurityPackageInfo");

        try
        {
            unsafe
            {
                ReadOnlySpan<Helpers.SecPkgInfoW> packageInfo = new(info.ToPointer(), 1);
                return new SecPackageInfo(packageInfo[0]);
            }
        }
        finally
        {
            FreeContextBuffer(info);
        }
    }
}

public class SecPackageInfo
{
    public string Name { get; internal set; }
    public string Comment { get; internal set; }
    public PackageCapabilities Capabilities { get; internal set; }
    public UInt16 Version { get; internal set; }
    public UInt16 RPCID { get; internal set; }
    public UInt32 MaxTokenSize { get; internal set; }

    internal SecPackageInfo(Helpers.SecPkgInfoW raw)
    {
        unsafe
        {
            Name = new string(raw.Name);
            Comment = new string(raw.Comment);
        }
        Capabilities = raw.fCapabilities;
        Version = raw.wVersion;
        RPCID = raw.wRPCID;
        MaxTokenSize = raw.cbMaxToken;
    }
}

public class SspiException : AuthenticationException
{
    public int ErrorCode { get; } = -1;

    public SspiException() { }

    public SspiException(string message) : base(message) { }

    public SspiException(string message, Exception innerException) :
        base(message, innerException)
    { }

    public SspiException(int errorCode, string method)
        : base(GetExceptionMessage(errorCode, method))
    {
        ErrorCode = errorCode;
    }

    private static string GetExceptionMessage(int errorCode, string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "SSPI Call" : method;
        string errMsg = new Win32Exception(errorCode).Message;

        return String.Format("{0} failed ({1}, Win32ErrorCode {2} - 0x{2:X8})", method, errMsg, errorCode);
    }
}

[Flags]
public enum AcceptorContextRequestFlags : uint
{
    NONE = 0x00000000,
    ASC_REQ_DELEGATE = 0x00000001,
    ASC_REQ_MUTUAL_AUTH = 0x00000002,
    ASC_REQ_REPLAY_DETECT = 0x00000004,
    ASC_REQ_SEQUENCE_DETECT = 0x00000008,
    ASC_REQ_CONFIDENTIALITY = 0x00000010,
    ASC_REQ_USE_SESSION_KEY = 0x00000020,
    ASC_REQ_SESSION_TICKET = 0x00000040,
    ASC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ASC_REQ_USE_DCE_STYLE = 0x00000200,
    ASC_REQ_DATAGRAM = 0x00000400,
    ASC_REQ_CONNECTION = 0x00000800,
    ASC_REQ_CALL_LEVEL = 0x00001000,
    ASC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ASC_REQ_EXTENDED_ERROR = 0x00008000,
    ASC_REQ_STREAM = 0x00010000,
    ASC_REQ_INTEGRITY = 0x00020000,
    ASC_REQ_LICENSING = 0x00040000,
    ASC_REQ_IDENTIFY = 0x00080000,
    ASC_REQ_ALLOW_NULL_SESSION = 0x00100000,
    ASC_REQ_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_REQ_ALLOW_CONTEXT_REPLAY = 0x00400000,
    ASC_REQ_FRAGMENT_TO_FIT = 0x00800000,
    ASC_REQ_NO_TOKEN = 0x01000000,
    ASC_REQ_PROXY_BINDINGS = 0x04000000,
    ASC_REQ_ALLOW_MISSING_BINDINGS = 0x10000000,
}

[Flags]
public enum AcceptorContextReturnFlags : uint
{
    NONE = 0x00000000,
    ASC_RET_DELEGATE = 0x00000001,
    ASC_RET_MUTUAL_AUTH = 0x00000002,
    ASC_RET_REPLAY_DETECT = 0x00000004,
    ASC_RET_SEQUENCE_DETECT = 0x00000008,
    ASC_RET_CONFIDENTIALITY = 0x00000010,
    ASC_RET_USE_SESSION_KEY = 0x00000020,
    ASC_RET_SESSION_TICKET = 0x00000040,
    ASC_RET_ALLOCATED_MEMORY = 0x00000100,
    ASC_RET_USED_DCE_STYLE = 0x00000200,
    ASC_RET_DATAGRAM = 0x00000400,
    ASC_RET_CONNECTION = 0x00000800,
    ASC_RET_CALL_LEVEL = 0x00002000,
    ASC_RET_THIRD_LEG_FAILED = 0x00004000,
    ASC_RET_EXTENDED_ERROR = 0x00008000,
    ASC_RET_STREAM = 0x00010000,
    ASC_RET_INTEGRITY = 0x00020000,
    ASC_RET_LICENSING = 0x00040000,
    ASC_RET_IDENTIFY = 0x00080000,
    ASC_RET_NULL_SESSION = 0x00100000,
    ASC_RET_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_RET_ALLOW_CONTEXT_REPLAY = 0x00400000,
    ASC_RET_FRAGMENT_ONLY = 0x00800000,
    ASC_RET_NO_TOKEN = 0x01000000,
    ASC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
}

public enum CredentialAttribute : uint
{
    SECPKG_CRED_ATTR_NAMES = 1,
    SECPKG_CRED_ATTR_SSI_PROVIDER = 2,
    SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS = 3,
    SECPKG_CRED_ATTR_CERT = 4,
    SECPKG_CRED_ATTR_PAC_BYPASS = 5,
}

[Flags()]
public enum CredentialUse : uint
{
    SECPKG_CRED_INBOUND = 0x00000001,
    SECPKG_CRED_OUTBOUND = 0x00000002,
    SECPKG_CRED_BOTH = 0x00000003,
    SECPKG_CRED_DEFAULT = 0x00000004,
    SECPKG_CRED_AUTOLOGON_RESTRICTED = 0x00000010,
    SECPKG_CRED_PROCESS_POLICY_ONLY = 0x00000020,
}

[Flags]
public enum InitiatorContextRequestFlags : uint
{
    NONE = 0x00000000,
    ISC_REQ_DELEGATE = 0x00000001,
    ISC_REQ_MUTUAL_AUTH = 0x00000002,
    ISC_REQ_REPLAY_DETECT = 0x00000004,
    ISC_REQ_SEQUENCE_DETECT = 0x00000008,
    ISC_REQ_CONFIDENTIALITY = 0x00000010,
    ISC_REQ_USE_SESSION_KEY = 0x00000020,
    ISC_REQ_PROMPT_FOR_CREDS = 0x00000040,
    ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080,
    ISC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ISC_REQ_USE_DCE_STYLE = 0x00000200,
    ISC_REQ_DATAGRAM = 0x00000400,
    ISC_REQ_CONNECTION = 0x00000800,
    ISC_REQ_CALL_LEVEL = 0x00001000,
    ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ISC_REQ_EXTENDED_ERROR = 0x00004000,
    ISC_REQ_STREAM = 0x00008000,
    ISC_REQ_INTEGRITY = 0x00010000,
    ISC_REQ_IDENTIFY = 0x00020000,
    ISC_REQ_NULL_SESSION = 0x00040000,
    ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_REQ_RESERVED1 = 0x00100000,
    ISC_REQ_FRAGMENT_TO_FIT = 0x00200000,
    ISC_REQ_FORWARD_CREDENTIALS = 0x00400000,
    ISC_REQ_NO_INTEGRITY = 0x00800000,
    ISC_REQ_USE_HTTP_STYLE = 0x01000000,
    ISC_REQ_UNVERIFIED_TARGET_NAME = 0x20000000,
    ISC_REQ_CONFIDENTIALITY_ONLY = 0x40000000,
}

[Flags]
public enum InitiatorContextReturnFlags : uint
{
    NONE = 0x00000000,
    ISC_RET_DELEGATE = 0x00000001,
    ISC_RET_MUTUAL_AUTH = 0x00000002,
    ISC_RET_REPLAY_DETECT = 0x00000004,
    ISC_RET_SEQUENCE_DETECT = 0x00000008,
    ISC_RET_CONFIDENTIALITY = 0x00000010,
    ISC_RET_USE_SESSION_KEY = 0x00000020,
    ISC_RET_USED_COLLECTED_CREDS = 0x00000040,
    ISC_RET_USED_SUPPLIED_CREDS = 0x00000080,
    ISC_RET_ALLOCATED_MEMORY = 0x00000100,
    ISC_RET_USED_DCE_STYLE = 0x00000200,
    ISC_RET_DATAGRAM = 0x00000400,
    ISC_RET_CONNECTION = 0x00000800,
    ISC_RET_INTERMEDIATE_RETURN = 0x00001000,
    ISC_RET_CALL_LEVEL = 0x00002000,
    ISC_RET_EXTENDED_ERROR = 0x00004000,
    ISC_RET_STREAM = 0x00008000,
    ISC_RET_INTEGRITY = 0x00010000,
    ISC_RET_IDENTIFY = 0x00020000,
    ISC_RET_NULL_SESSION = 0x00040000,
    ISC_RET_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_RET_RESERVED1 = 0x00100000,
    ISC_RET_FRAGMENT_ONLY = 0x00200000,
    ISC_RET_FORWARD_CREDENTIALS = 0x00400000,
    ISC_RET_USED_HTTP_STYLE = 0x01000000,
    ISC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
    ISC_RET_REAUTHENTICATION = 0x08000000,
    ISC_RET_CONFIDENTIALITY_ONLY = 0x40000000,
}

[Flags()]
public enum KDCProxyFlags : uint
{
    NONE = 0x0,

    /// <summary>
    /// Force the use of the proxy specified and do not attempt to talk to the KDC directly.
    /// </summary>
    KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY = 0x1,
}

[Flags()]
public enum PackageCapabilities : uint
{
    /// <summary>
    /// The security package supports the MakeSignature and VerifySignature functions.
    /// </summary>
    SECPKG_FLAG_INTEGRITY = 0x00000001,

    /// <summary>
    /// The security package supports the EncryptMessage (General) and DecryptMessage (General) functions.
    /// </summary>
    SECPKG_FLAG_PRIVACY = 0x00000002,

    /// <summary>
    /// The package is interested only in the security-token portion of messages, and will ignore any other buffers.
    /// This is a performance-related issue.
    /// </summary>
    SECPKG_FLAG_TOKEN_ONLY = 0x00000004,

    /// <summary>
    /// Supports datagram-style authentication. For more information, see SSPI Context Semantics Important.
    /// The Microsoft Kerberos package does not support datagram contexts in user-to-user mode.
    /// </summary>
    SECPKG_FLAG_DATAGRAM = 0x00000008,

    /// <summary>
    /// Supports connection-oriented style authentication. For more information, see SSPI Context Semantics.
    /// </summary>
    SECPKG_FLAG_CONNECTION = 0x00000010,

    /// <summary>
    /// Multiple legs are required for authentication.
    /// </summary>
    SECPKG_FLAG_MULTI_REQUIRED = 0x00000020,

    /// <summary>
    /// Server authentication support is not provided.
    /// </summary>
    SECPKG_FLAG_CLIENT_ONLY = 0x00000040,

    /// <summary>
    /// Supports extended error handling. For more information, see Extended Error Information.
    /// </summary>
    SECPKG_FLAG_EXTENDED_ERROR = 0x00000080,

    /// <summary>
    /// Supports Windows impersonation in server contexts.
    /// </summary>
    SECPKG_FLAG_IMPERSONATION = 0x00000100,

    /// <summary>
    /// Understands Windows principal and target names.
    /// </summary>
    SECPKG_FLAG_ACCEPT_WIN32_NAME = 0x00000200,

    /// <summary>
    /// Supports stream semantics. For more information, see SSPI Context Semantics.
    /// </summary>
    SECPKG_FLAG_STREAM = 0x00000400,

    /// <summary>
    /// Can be used by the Microsoft Negotiate security package.
    /// </summary>
    SECPKG_FLAG_NEGOTIABLE = 0x00000800,

    /// <summary>
    /// Supports GSS compatibility.
    /// </summary>
    SECPKG_FLAG_GSS_COMPATIBLE = 0x00001000,

    /// <summary>
    /// Supports LsaLogonUser.
    /// </summary>
    SECPKG_FLAG_LOGON = 0x00002000,

    /// <summary>
    /// Token buffers are in ASCII characters format.
    /// </summary>
    SECPKG_FLAG_ASCII_BUFFERS = 0x00004000,

    /// <summary>
    /// Supports separating large tokens into smaller buffers so that applications can make repeated calls to
    /// InitializeSecurityContext (General) and AcceptSecurityContext (General) with the smaller buffers to complete
    /// authentication.
    /// </summary>
    SECPKG_FLAG_FRAGMENT = 0x00008000,

    /// <summary>
    /// Supports mutual authentication.
    /// </summary>
    SECPKG_FLAG_MUTUAL_AUTH = 0x00010000,

    /// <summary>
    /// Supports delegation.
    /// </summary>
    SECPKG_FLAG_DELEGATION = 0x00020000,

    /// <summary>
    /// The security package supports using a checksum instead of in-place encryption when calling the EncryptMessage
    /// function.
    /// </summary>
    SECPKG_FLAG_READONLY_WITH_CHECKSUM = 0x00040000,

    /// <summary>
    /// Supports callers with restricted tokens.
    /// </summary>
    SECPKG_FLAG_RESTRICTED_TOKENS = 0x00080000,

    /// <summary>
    /// The security package extends the Microsoft Negotiate security package. There can be at most one package of this
    /// type.
    /// </summary>
    SECPKG_FLAG_NEGO_EXTENDER = 0x00100000,

    /// <summary>
    /// This package is negotiated by the package of type SECPKG_FLAG_NEGO_EXTENDER.
    /// </summary>
    SECPKG_FLAG_NEGOTIABLE2 = 0x00200000,

    /// <summary>
    /// This package receives all calls from app container apps.
    /// </summary>
    SECPKG_FLAG_APPCONTAINER_PASSTHROUGH = 0x00400000,

    /// <summary>
    /// This package receives calls from app container apps if one of the following checks succeeds.
    /// Caller has default credentials capability.
    /// The target is a proxy server.
    /// The caller has supplied credentials.
    /// </summary>
    SECPKG_FLAG_APPCONTAINER_CHECKS = 0x00800000,

    /// <summary>
    /// This package is running with Credential Guard enabled.
    /// </summary>
    SECPKG_FLAG_CREDENTIAL_ISOLATION_ENABLED = 0x01000000,

    /// <summary>
    /// This package supports reliable detection of loopback
    /// 1. The client and server see the same sequence of tokens
    /// 2. The server enforces a unique exchange for each non-anonymous authentication. (Replay detection)
    /// </summary>
    SECPKG_FLAG_APPLY_LOOPBACK = 0x02000000,
}

public enum SecPkgAttribute : uint
{
    SECPKG_ATTR_SIZES = 0,
    SECPKG_ATTR_NAMES = 1,
    SECPKG_ATTR_LIFESPAN = 2,
    SECPKG_ATTR_DCE_INFO = 3,
    SECPKG_ATTR_STREAM_SIZES = 4,
    SECPKG_ATTR_KEY_INFO = 5,
    SECPKG_ATTR_AUTHORITY = 6,
    SECPKG_ATTR_PROTO_INFO = 7,
    SECPKG_ATTR_PASSWORD_EXPIRY = 8,
    SECPKG_ATTR_SESSION_KEY = 9,
    SECPKG_ATTR_PACKAGE_INFO = 10,
    SECPKG_ATTR_USER_FLAGS = 11,
    SECPKG_ATTR_NEGOTIATION_INFO = 12,
    SECPKG_ATTR_NATIVE_NAMES = 13,
    SECPKG_ATTR_FLAGS = 14,
    SECPKG_ATTR_USE_VALIDATED = 15,
    SECPKG_ATTR_CREDENTIAL_NAME = 16,
    SECPKG_ATTR_TARGET_INFORMATION = 17,
    SECPKG_ATTR_ACCESS_TOKEN = 18,
    SECPKG_ATTR_TARGET = 19,
    SECPKG_ATTR_AUTHENTICATION_ID = 20,
    SECPKG_ATTR_LOGOFF_TIME = 21,
    SECPKG_ATTR_NEGO_KEYS = 22,
    SECPKG_ATTR_PROMPTING_NEEDED = 24,
    SECPKG_ATTR_UNIQUE_BINDINGS = 25,
    SECPKG_ATTR_ENDPOINT_BINDINGS = 26,
    SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27,
    SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS = 30,
    SECPKG_ATTR_NEGO_PKG_INFO = 31,
    SECPKG_ATTR_NEGO_STATUS = 32,
    SECPKG_ATTR_CONTEXT_DELETED = 33,
    SECPKG_ATTR_DTLS_MTU = 34,
    SECPKG_ATTR_DATAGRAM_SIZES = SECPKG_ATTR_STREAM_SIZES,
    SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = 128,
    SECPKG_ATTR_APPLICATION_PROTOCOL = 35,
    SECPKG_ATTR_NEGOTIATED_TLS_EXTENSIONS = 36,
    SECPKG_ATTR_IS_LOOPBACK = 37,
}

public enum TargetDataRep : uint
{
    SECURITY_NETWORK_DREP = 0x00000000,
    SECURITY_NATIVE_DREP = 0x00000010,
}

public class SafeSspiCredentialHandle : SafeHandle
{
    internal SafeSspiCredentialHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SSPI.FreeCredentialsHandle(handle);
        Marshal.FreeHGlobal(handle);

        return true;
    }
}

public class SafeSspiContextHandle : SafeHandle
{
    public static readonly SafeSspiContextHandle NULL_CONTEXT = new(IntPtr.Zero, false);

    internal SafeSspiContextHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true) { }
    internal SafeSspiContextHandle(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SSPI.DeleteSecurityContext(handle);
        Marshal.FreeHGlobal(handle);

        return true;
    }
}
