using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace PSSPI;

public class SchannelCred : ICredentialIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SCHANNEL_CRED
    {
        public const int SCHANNEL_CRED_VERSION = 0x4;

        public int dwVersion;
        public int cCreds;
        public unsafe void* paCred;
        public IntPtr hRootStore;
        public int cMappers;
        public IntPtr aphMappers;
        public int cSupportedAlgs;
        public unsafe int* palgSupportedAlgs;
        public SchannelProtocols grbitEnabledProtocols;
        public int dwMinimumCipherStrength;
        public int dwMaximumCipherStream;
        public int dwSessionLifespan;
        public SchannelCredFlags dwFlags;
        public SchannelCredFormat dwCredFormat;
    }

    public X509Certificate[] Certificates { get; }
    public X509Store? RootStore { get; }
    public int SessionLifeSpanMS { get; }
    public SchannelCredFlags Flags { get; }
    public AlgorithmId[] SupportedAlgs { get; }
    public SchannelProtocols EnabledProtocols { get; }
    public int MinimumCipherStrength { get; }
    public int MaximumCipherStrength { get; }

    public SchannelCred(X509Certificate[]? certificates = null, X509Store? rootStore = null, int sessionLifespanMS = 0,
        SchannelCredFlags flags = SchannelCredFlags.None, AlgorithmId[]? supportedAlgs = null,
        SchannelProtocols enabledProtocols = SchannelProtocols.SP_PROT_NONE, int minimumCipherStrength = 0,
        int maximumCipherStrength = 0)
    {
        Certificates = certificates ?? Array.Empty<X509Certificate>();
        RootStore = rootStore;
        SessionLifeSpanMS = sessionLifespanMS;
        Flags = flags;
        SupportedAlgs = supportedAlgs ?? Array.Empty<AlgorithmId>();
        EnabledProtocols = enabledProtocols;
        MinimumCipherStrength = minimumCipherStrength;
        MaximumCipherStrength = maximumCipherStrength;
    }

    int ICredentialIdentity.AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
        SafeSspiCredentialHandle credential, out Helpers.SECURITY_INTEGER expiry)
    {
        unsafe
        {
            Span<IntPtr> certContexts = Certificates.Select(c => c.Handle).ToArray().AsSpan();

            fixed (void* certContextPtr = certContexts)
            fixed (AlgorithmId* algsPtr = SupportedAlgs)
            {
                SCHANNEL_CRED authData = new()
                {
                    dwVersion = SCHANNEL_CRED.SCHANNEL_CRED_VERSION,
                    cCreds = Certificates.Length,
                    paCred = certContextPtr,
                    hRootStore = RootStore?.StoreHandle ?? IntPtr.Zero,
                    cMappers = 0,
                    aphMappers = IntPtr.Zero,
                    cSupportedAlgs = SupportedAlgs?.Length ?? 0,
                    palgSupportedAlgs = (int*)algsPtr,
                    grbitEnabledProtocols = EnabledProtocols,
                    dwMinimumCipherStrength = MinimumCipherStrength,
                    dwMaximumCipherStream = MaximumCipherStrength,
                    dwSessionLifespan = SessionLifeSpanMS,
                    dwFlags = Flags,
                    dwCredFormat = SchannelCredFormat.SCH_CRED_FORMAT_CERT_CONTEXT,
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
}

public class SCHCredential : ICredentialIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SCH_CREDENTIALS
    {
        public const int SCH_CREDENTIALS_VERSION = 0x5;

        public int dwVersion;
        public SchannelCredFormat dwCredFormat;
        public int cCreds;
        public unsafe void* paCred;
        public IntPtr hRootStore;
        public int cMappers;
        public IntPtr aphMappers;
        public int dwSessionLifespan;
        public SchannelCredFlags dwFlags;
        public int cTlsParameters;
        public unsafe TLS_PARAMETERS* pTlsParameters;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPTO_SETTINGS
    {
        public SchannelCryptoUsage eAlgorithmUsage;
        public UNICODE_STRING strCngAlgId;
        public int cChainingModes;
        public unsafe UNICODE_STRING* rgstrChainingModes;
        public int dwMinBitLength;
        public int dwMaxBitLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TLS_PARAMETERS
    {
        public int cAlpnIds;
        public unsafe UNICODE_STRING* rgstrAlpnIds;
        public SchannelProtocols grbitDisabledProtocols;
        public int cDisabledCrypto;
        public unsafe CRYPTO_SETTINGS* pDisabledCrypto;
        public TLS_PARAMETERS.Flags dwFlags;

        [Flags]
        public enum Flags
        {
            None = 0x00000000,
            TLS_PARAMS_OPTIONAL = 0x00000001,
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    public X509Certificate[] Certificates { get; }
    public X509Store? RootStore { get; }
    public int SessionLifeSpanMS { get; }
    public SchannelCredFlags Flags { get; }
    public TlsParameter[] TlsParameters { get; }

    public SCHCredential(X509Certificate[]? certificates = null, X509Store? rootStore = null, int sessionLifespanMS = 0,
        SchannelCredFlags flags = SchannelCredFlags.None, TlsParameter[]? tlsParameters = null)
    {
        Certificates = certificates ?? Array.Empty<X509Certificate>();
        RootStore = rootStore;
        SessionLifeSpanMS = sessionLifespanMS;
        Flags = flags;
        TlsParameters = tlsParameters ?? Array.Empty<TlsParameter>();
    }

    int ICredentialIdentity.AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
        SafeSspiCredentialHandle credential, out Helpers.SECURITY_INTEGER expiry)
    {
        Span<TLS_PARAMETERS> tlsParameters = stackalloc TLS_PARAMETERS[TlsParameters.Length];

        List<IntPtr> buffers = new();
        try
        {
            unsafe
            {
                for (int i = 0; i < TlsParameters.Length; i++)
                {
                    TlsParameter param = TlsParameters[i];

                    int alpnLength = param.AlpnIds.Length;
                    if (alpnLength > 0)
                    {
                        tlsParameters[i].cAlpnIds = alpnLength;

                        buffers.Add(Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>() * alpnLength));
                        tlsParameters[i].rgstrAlpnIds = (UNICODE_STRING*)buffers[^1];

                        Span<UNICODE_STRING> alpnStructs = new(tlsParameters[i].rgstrAlpnIds, alpnLength);
                        for (int j = 0; j < alpnLength; j++)
                        {
                            PopulateUnicodeString(ref alpnStructs[j], param.AlpnIds[j], buffers);
                        }
                    }
                    else
                    {
                        tlsParameters[i].cAlpnIds = 0;
                        tlsParameters[i].rgstrAlpnIds = null;
                    }

                    tlsParameters[i].grbitDisabledProtocols = param.DisabledProtocols;

                    int cryptosLength = param.DisabledCryptos.Length;
                    if (cryptosLength > 0)
                    {
                        tlsParameters[i].cDisabledCrypto = cryptosLength;

                        buffers.Add(Marshal.AllocHGlobal(Marshal.SizeOf<CRYPTO_SETTINGS>() * cryptosLength));
                        tlsParameters[i].pDisabledCrypto = (CRYPTO_SETTINGS*)buffers[^1];

                        Span<CRYPTO_SETTINGS> cryptoStructs = new(tlsParameters[i].pDisabledCrypto, cryptosLength);
                        for (int j = 0; j < cryptosLength; j++)
                        {
                            PopulateCryptoSettings(ref cryptoStructs[j], param.DisabledCryptos[j], buffers);
                        }
                    }
                    else
                    {
                        tlsParameters[i].cDisabledCrypto = 0;
                        tlsParameters[i].pDisabledCrypto = null;
                    }

                    tlsParameters[i].dwFlags = param.Optional
                        ? TLS_PARAMETERS.Flags.TLS_PARAMS_OPTIONAL
                        : TLS_PARAMETERS.Flags.None;
                }

                Span<IntPtr> certContexts = Certificates.Select(c => c.Handle).ToArray().AsSpan();

                fixed (void* certContextPtr = certContexts)
                fixed (TLS_PARAMETERS* tlsParameterPtr = tlsParameters)
                {
                    SCH_CREDENTIALS authData = new()
                    {
                        dwVersion = SCH_CREDENTIALS.SCH_CREDENTIALS_VERSION,
                        dwCredFormat = SchannelCredFormat.SCH_CRED_FORMAT_CERT_CONTEXT,
                        cCreds = Certificates.Length,
                        paCred = certContextPtr,
                        hRootStore = RootStore?.StoreHandle ?? IntPtr.Zero,
                        cMappers = 0,
                        aphMappers = IntPtr.Zero,
                        dwSessionLifespan = SessionLifeSpanMS,
                        dwFlags = Flags,
                        cTlsParameters = tlsParameters.Length,
                        pTlsParameters = tlsParameterPtr,
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
            foreach (IntPtr buffer in buffers)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static void PopulateUnicodeString(ref UNICODE_STRING uniString, string value, List<IntPtr> buffers)
    {
        buffers.Add(Marshal.StringToHGlobalUni(value));
        uniString.Length = (UInt16)(value.Length * 2);
        uniString.MaximumLength = uniString.Length;
        uniString.Buffer = buffers[^1];
    }

    private unsafe static void PopulateCryptoSettings(ref CRYPTO_SETTINGS settings, CryptoSetting value, List<IntPtr> buffers)
    {
        settings.eAlgorithmUsage = value.Usage;
        PopulateUnicodeString(ref settings.strCngAlgId, value.Algorithm, buffers);

        int chainingLength = value.ChainingModes.Length;
        if (chainingLength > 0)
        {
            settings.cChainingModes = chainingLength;

            buffers.Add(Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>() * chainingLength));
            settings.rgstrChainingModes = (UNICODE_STRING*)buffers[^1];

            Span<UNICODE_STRING> chainingStructs = new(settings.rgstrChainingModes, chainingLength);
            for (int i = 0; i < chainingLength; i++)
            {
                PopulateUnicodeString(ref chainingStructs[i], value.ChainingModes[i], buffers);
            }
        }
        else
        {
            settings.cChainingModes = 0;
            settings.rgstrChainingModes = null;
        }

        settings.dwMinBitLength = value.MinBitLength;
        settings.dwMaxBitLength = value.MaxBitLength;
    }
}

public class CryptoSetting
{
    public SchannelCryptoUsage Usage { get; set; }

    public string Algorithm { get; set; }

    public string[] ChainingModes { get; set; } = Array.Empty<string>();

    public int MinBitLength { get; set; }

    public int MaxBitLength { get; set; }

    public CryptoSetting(SchannelCryptoUsage usage, string algorithm, string[] chainingModes, int minBitLength,
        int maxBitLength)
    {
        Usage = usage;
        Algorithm = algorithm;
        ChainingModes = chainingModes;
        MinBitLength = minBitLength;
        MaxBitLength = maxBitLength;
    }
}

public class TlsParameter
{
    public string[] AlpnIds { get; set; } = Array.Empty<string>();

    public SchannelProtocols DisabledProtocols { get; set; }

    public CryptoSetting[] DisabledCryptos { get; set; }

    public bool Optional { get; set; }

    public TlsParameter(string[] alpnIds, SchannelProtocols disabledProtocols, CryptoSetting[] disabledCryptos,
        bool optional)
    {
        AlpnIds = alpnIds;
        DisabledProtocols = disabledProtocols;
        DisabledCryptos = disabledCryptos;
        Optional = optional;
    }
}

public enum AlgorithmId
{
    // Algorithm Classes
    ALG_CLASS_ANY = 0,
    ALG_CLASS_SIGNATURE = 1 << 13,
    ALG_CLASS_MSG_ENCRYPT = 2 << 13,
    ALG_CLASS_DATA_ENCRYPT = 3 << 13,
    ALG_CLASS_HASH = 4 << 13,
    ALG_CLASS_KEY_EXCHANGE = 5 << 13,
    ALG_CLASS_ALL = 7 << 13,

    // Algorithm Types
    ALG_TYPE_ANY = 0,
    ALG_TYPE_DSS = 1 << 9,
    ALG_TYPE_RSA = 2 << 9,
    ALG_TYPE_BLOCK = 3 << 9,
    ALG_TYPE_STREAM = 4 << 9,
    ALG_TYPE_DH = 5 << 9,
    ALG_TYPE_SECURECHANNEL = 6 << 9,
    ALG_TYPE_ECDH = 7 << 9,
    ALG_TYPE_THIRDPARTY = 8 << 9,

    // Algorithm Sub Ids
    ALG_SID_ANY = 0,

    // Generic ThirdParty sub-ids
    ALG_SID_THIRDPARTY_ANY = 0,

    // Some RSA sub-ids
    ALG_SID_RSA_ANY = 0,
    ALG_SID_RSA_PKCS = 1,
    ALG_SID_RSA_MSATWORK = 2,
    ALG_SID_RSA_ENTRUST = 3,
    ALG_SID_RSA_PGP = 4,

    // Some DSS sub-ids
    ALG_SID_DSS_ANY = 0,
    ALG_SID_DSS_PKCS = 1,
    ALG_SID_DSS_DMS = 2,
    ALG_SID_ECDSA = 3,

    // Block cipher sub ids
    ALG_SID_DES = 1,
    ALG_SID_3DES = 3,
    ALG_SID_DESX = 4,
    ALG_SID_IDEA = 5,
    ALG_SID_CAST = 6,
    ALG_SID_SAFERSK64 = 7,
    ALG_SID_SAFERSK128 = 8,
    ALG_SID_3DES_112 = 9,
    ALG_SID_CYLINK_MEK = 12,
    ALG_SID_RC5 = 13,
    ALG_SID_AES_128 = 14,
    ALG_SID_AES_192 = 15,
    ALG_SID_AES_256 = 16,
    ALG_SID_AES = 17,

    // Fortezza sub-ids
    ALG_SID_SKIPJACK = 10,
    ALG_SID_TEK = 11,

    // RC2 sub-ids
    ALG_SID_RC2 = 2,

    // Stream cipher sub-ids
    ALG_SID_RC4 = 1,
    ALG_SID_SEAL = 2,

    // Diffie-Hellman sub-ids
    ALG_SID_DH_SANDF = 1,
    ALG_SID_DH_EPHEM = 2,
    ALG_SID_AGREED_KEY_ANY = 3,
    ALG_SID_KEA = 4,
    ALG_SID_ECDH = 5,
    ALG_SID_ECDH_EPHEM = 6,

    // Hash sub ids
    ALG_SID_MD2 = 1,
    ALG_SID_MD4 = 2,
    ALG_SID_MD5 = 3,
    ALG_SID_SHA = 4,
    ALG_SID_SHA1 = 4,
    ALG_SID_MAC = 5,
    ALG_SID_RIPEMD = 6,
    ALG_SID_RIPEMD160 = 7,
    ALG_SID_SSL3SHAMD5 = 8,
    ALG_SID_HMAC = 9,
    ALG_SID_TLS1PRF = 10,
    ALG_SID_HASH_REPLACE_OWF = 11,
    ALG_SID_SHA_256 = 12,
    ALG_SID_SHA_384 = 13,
    ALG_SID_SHA_512 = 14,
    ALG_SID_SSL3_MASTER = 1,
    ALG_SID_SCHANNEL_MASTER_HASH = 2,
    ALG_SID_SCHANNEL_MAC_KEY = 3,
    ALG_SID_PCT1_MASTER = 4,
    ALG_SID_SSL2_MASTER = 5,
    ALG_SID_TLS1_MASTER = 6,
    ALG_SID_SCHANNEL_ENC_KEY = 7,
    ALG_SID_ECMQV = 1,

    CALG_MD2 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2,
    CALG_MD4 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4,
    CALG_MD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5,
    CALG_SHA = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA,
    CALG_SHA1 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1,
    CALG_MAC = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MAC,
    CALG_RSA_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
    CALG_DSS_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY,
    CALG_NO_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY,
    CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
    CALG_DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES,
    CALG_3DES_112 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES_112,
    CALG_3DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES,
    CALG_DESX = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DESX,
    CALG_RC2 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC2,
    CALG_RC4 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4,
    CALG_SEAL = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_SEAL,
    CALG_DH_SF = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF,
    CALG_DH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM,
    CALG_AGREEDKEY_ANY = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_AGREED_KEY_ANY,
    CALG_KEA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_KEA,
    CALG_HUGHES_MD5 = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_MD5,
    CALG_SKIPJACK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SKIPJACK,
    CALG_TEK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_TEK,
    CALG_CYLINK_MEK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_CYLINK_MEK,
    CALG_SSL3_SHAMD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5,
    CALG_SSL3_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL3_MASTER,
    CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MASTER_HASH,
    CALG_SCHANNEL_MAC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY,
    CALG_SCHANNEL_ENC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY,
    CALG_PCT1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_PCT1_MASTER,
    CALG_SSL2_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL2_MASTER,
    CALG_TLS1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_TLS1_MASTER,
    CALG_RC5 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5,
    CALG_HMAC = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC,
    CALG_TLS1PRF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF,
    CALG_HASH_REPLACE_OWF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF,
    CALG_AES_128 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128,
    CALG_AES_192 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_192,
    CALG_AES_256 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
    CALG_AES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES,
    CALG_SHA_256 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
    CALG_SHA_384 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384,
    CALG_SHA_512 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512,
    CALG_ECDH = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH,
    CALG_ECDH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ECDH | ALG_SID_ECDH_EPHEM,
    CALG_ECMQV = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV,
    CALG_ECDSA = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA,
    CALG_NULLCIPHER = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ANY | 0,
    CALG_THIRDPARTY_KEY_EXCHANGE = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_SIGNATURE = ALG_CLASS_SIGNATURE | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_CIPHER = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_HASH = ALG_CLASS_HASH | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
}

public enum SchannelCryptoUsage
{
    KeyExchange,
    Signature,
    Cipher,
    Digest,
    CertSig,
}

[Flags]
public enum SchannelCredFlags : uint
{
    None = 0,
    SCH_CRED_NO_SYSTEM_MAPPER = 0x00000002,
    SCH_CRED_NO_SERVERNAME_CHECK = 0x00000004,
    SCH_CRED_MANUAL_CRED_VALIDATION = 0x00000008,
    SCH_CRED_NO_DEFAULT_CREDS = 0x00000010,
    SCH_CRED_AUTO_CRED_VALIDATION = 0x00000020,
    SCH_CRED_USE_DEFAULT_CREDS = 0x00000040,
    SCH_CRED_DISABLE_RECONNECTS = 0x00000080,
    SCH_CRED_REVOCATION_CHECK_END_CERT = 0x00000100,
    SCH_CRED_REVOCATION_CHECK_CHAIN = 0x00000200,
    SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400,
    SCH_CRED_IGNORE_NO_REVOCATION_CHECK = 0x00000800,
    SCH_CRED_IGNORE_REVOCATION_OFFLINE = 0x00001000,
    SCH_CRED_RESTRICTED_ROOTS = 0x00002000,
    SCH_CRED_REVOCATION_CHECK_CACHE_ONLY = 0x00004000,
    SCH_CRED_CACHE_ONLY_URL_RETRIEVAL = 0x00008000,
    SCH_CRED_MEMORY_STORE_CERT = 0x00010000,
    SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE = 0x00020000,
    SCH_SEND_ROOT_CERT = 0x00040000,
    SCH_CRED_SNI_CREDENTIAL = 0x0008000,
    SCH_CRED_SNI_ENABLE_OCSP = 0x00100000,
    SCH_SEND_AUX_RECORD = 0x00200000,
    SCH_USE_STRONG_CRYPTO = 0x00400000,
    SCH_USE_PRESHAREDKEY_ONLY = 0x00800000,
    SCH_USE_DTLS_ONLY = 0x01000000,
    SCH_ALLOW_NULL_ENCRYPTION = 0x02000000,
    SCH_CRED_DEFERRED_CRED_VALIDATION = 0x04000000,
}

public enum SchannelCredFormat
{
    SCH_CRED_FORMAT_CERT_CONTEXT = 0x00000000,
    SCH_CRED_FORMAT_CERT_HASH = 0x00000001,
    SCH_CRED_FORMAT_CERT_HASH_STORE = 0x00000002,
}

[Flags]
public enum SchannelProtocols : uint
{
    SP_PROT_NONE = 0,

    SP_PROT_PCT1_SERVER = 0x00000001,
    SP_PROT_PCT1_CLIENT = 0x00000002,
    SP_PROT_PCT1 = SP_PROT_PCT1_SERVER | SP_PROT_PCT1_CLIENT,

    SP_PROT_SSL2_SERVER = 0x00000004,
    SP_PROT_SSL2_CLIENT = 0x00000008,
    SP_PROT_SSL2 = SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT,

    SP_PROT_SSL3_SERVER = 0x00000010,
    SP_PROT_SSL3_CLIENT = 0x00000020,
    SP_PROT_SSL3 = SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT,

    SP_PROT_TLS1_SERVER = 0x00000040,
    SP_PROT_TLS1_CLIENT = 0x00000080,
    SP_PROT_TLS1 = SP_PROT_TLS1_SERVER | SP_PROT_TLS1_CLIENT,

    SP_PROT_SSL3TLS1_CLIENTS = SP_PROT_TLS1_CLIENT | SP_PROT_TLS1_CLIENT,
    SP_PROT_SSL3TLS1_SERVERS = SP_PROT_TLS1_SERVER | SP_PROT_SSL3_SERVER,
    SP_PROT_SSL3TLS1 = SP_PROT_SSL3 | SP_PROT_TLS1,

    SP_PROT_TLS1_0_SERVER = SP_PROT_TLS1_SERVER,
    SP_PROT_TLS1_0_CLIENT = SP_PROT_TLS1_CLIENT,
    SP_PROT_TLS1_0 = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_0_CLIENT,

    SP_PROT_TLS1_1_SERVER = 0x00000100,
    SP_PROT_TLS1_1_CLIENT = 0x00000200,
    SP_PROT_TLS1_1 = SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT,

    SP_PROT_TLS1_2_SERVER = 0x00000400,
    SP_PROT_TLS1_2_CLIENT = 0x00000800,
    SP_PROT_TLS1_2 = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT,

    SP_PROT_TLS1_3_SERVER = 0x00001000,
    SP_PROT_TLS1_3_CLIENT = 0x00002000,
    SP_PROT_TLS1_3 = SP_PROT_TLS1_3_SERVER | SP_PROT_TLS1_3_CLIENT,

    SP_PROT_DTLS_SERVER = 0x00010000,
    SP_PROT_DTLS_CLIENT = 0x00020000,
    SP_PROT_DTLS = SP_PROT_DTLS_SERVER | SP_PROT_DTLS_CLIENT,

    SP_PROT_DTLS1_0_SERVER = SP_PROT_DTLS_SERVER,
    SP_PROT_DTLS1_0_CLIENT = SP_PROT_DTLS_CLIENT,
    SP_PROT_DTLS1_0 = SP_PROT_DTLS1_0_SERVER | SP_PROT_DTLS1_0_CLIENT,

    SP_PROT_DTLS1_2_SERVER = 0x00040000,
    SP_PROT_DTLS1_2_CLIENT = 0x00080000,
    SP_PROT_DTLS1_2 = SP_PROT_DTLS1_2_SERVER | SP_PROT_DTLS1_2_CLIENT,

    SP_PROT_UNI_SERVER = 0x40000000,
    SP_PROT_UNI_CLIENT = 0x80000000,
    SP_PROT_UNI = SP_PROT_UNI_SERVER | SP_PROT_UNI_CLIENT,

    SP_PROT_ALL = 0xFFFFFFFF,
    SP_PROT_CLIENTS = SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_UNI_CLIENT | SP_PROT_TLS1_CLIENT,
    SP_PROT_SERVERS = SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_UNI_SERVER | SP_PROT_TLS1_SERVER,
}
