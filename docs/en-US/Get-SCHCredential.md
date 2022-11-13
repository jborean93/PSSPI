---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SCHCredential.md
schema: 2.0.0
---

# Get-SCHCredential

## SYNOPSIS
Creates an Schannel SSPI credential based on the newer SCH_CREDENTIALS structure.

## SYNTAX

```
Get-SCHCredential [-CredentialUse <CredentialUse>] [-Certificate <X509Certificate[]>] [-RootStore <X509Store>]
 [-SessionLifespanMS <Int32>] [-Flags <SchannelCredFlags>] [-TlsParameter <TlsParameter[]>]
 [<CommonParameters>]
```

## DESCRIPTION
Gets a Schannel SSPI credential for use with the `Microsoft Unified Security Protocol Provider` provider.
The credential is retrieved using the `SCH_CREDENTIALS` structure added in Windows 10 Build 1809 and supports all the modern protocols and ciphers like TLS 1.3.
The [Get-SchannelCredential](./Get-SchannelCredential.md) is the older Schannel credential structure that can be used for Windows versions older than Windows 10 Build 1809.

By default it allows all the system configured protocols and ciphers and utilises TLS Parameters to disable certain protocols and cipher suites.
Use [New-TlsParameter](./New-TlsParameter.md) to learn more about how to disable certain protocols and ciphers.

## EXAMPLES

### Example 1 - Get client Schannel credential with system defaults
```powershell
PS C:\> Get-SCHCredential
```

Gets a Schannel credential for a client to use with `New-SecContext`.
This Schannel credential is set to use the system defaults.

### Example 2 - Get client Schannel and disable weak protocols and ciphers
```powershell
PS C:\> Get-SCHCredential -Flags SCH_USE_STRONG_CRYPTO
```

Gets a Schannel credential with the `SCH_USE_STRONG_CRYPTO` flag specified which disables any weak protocols and cipher suites from being used.

### Example 3 - Get server Schannel with certificate
```powershell
PS C:\> $thumbprint = '...' # This is dependent on your environment
PS C:\> $cert = Get-Item Cert:\LocalMachine\My\$thumbprint
PS C:\> Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $cert
```

Gets a Schannel credential for use as a server that is backed by the certificate requested.

## PARAMETERS

### -Certificate
The certificate(s) to use when authenticating the caller.
When passing an empty list, the client will depend on Schannel to find an approriate certificatefor the authentication process.
For an inbound credential these are the certificates Schannel will use to present to the client.
The certificate selected is based on the capabilities offered by the client and what fits best.
At least one certificate must be specified when `-CredentialUse` has the `SECPKG_CRED_INBOUND` flag.

```yaml
Type: X509Certificate[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CredentialUse
How the credential is to be used.
Defaults to `SECPKG_CRED_OUTBOUND` which is used by a client.
Set to `SECPKG_CRED_INBOUND` to create a credential for use by a server/acceptor.

```yaml
Type: CredentialUse
Parameter Sets: (All)
Aliases:
Accepted values: SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND, SECPKG_CRED_BOTH, SECPKG_CRED_DEFAULT, SECPKG_CRED_AUTOLOGON_RESTRICTED, SECPKG_CRED_PROCESS_POLICY_ONLY

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Flags
Flags to set which control the behaviour of the Schannel operation.
These flags can control behaviour like how certificates are validated, client auth certificate lookups, and more.

```yaml
Type: SchannelCredFlags
Parameter Sets: (All)
Aliases:
Accepted values: None, SCH_CRED_NO_SYSTEM_MAPPER, SCH_CRED_NO_SERVERNAME_CHECK, SCH_CRED_MANUAL_CRED_VALIDATION, SCH_CRED_NO_DEFAULT_CREDS, SCH_CRED_AUTO_CRED_VALIDATION, SCH_CRED_USE_DEFAULT_CREDS, SCH_CRED_DISABLE_RECONNECTS, SCH_CRED_REVOCATION_CHECK_END_CERT, SCH_CRED_REVOCATION_CHECK_CHAIN, SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, SCH_CRED_IGNORE_NO_REVOCATION_CHECK, SCH_CRED_IGNORE_REVOCATION_OFFLINE, SCH_CRED_RESTRICTED_ROOTS, SCH_CRED_REVOCATION_CHECK_CACHE_ONLY, SCH_CRED_CACHE_ONLY_URL_RETRIEVAL, SCH_CRED_SNI_CREDENTIAL, SCH_CRED_MEMORY_STORE_CERT, SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE, SCH_SEND_ROOT_CERT, SCH_CRED_SNI_ENABLE_OCSP, SCH_SEND_AUX_RECORD, SCH_USE_STRONG_CRYPTO, SCH_USE_PRESHAREDKEY_ONLY, SCH_USE_DTLS_ONLY, SCH_ALLOW_NULL_ENCRYPTION, SCH_CRED_DEFERRED_CRED_VALIDATION

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RootStore
Used for inbound/acceptor credentials and is the X509 store that contains the self-signed root certificate for certification authorities trusted by the application.
This is used only be server-side applications that require client authentication.

```yaml
Type: X509Store
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SessionLifespanMS
The number of milliseconds that Schannel keeps the session in its session cache.
After this time has passed, any new connections between the client and server require a new Schannel session.
The default is `0` which is set to use the system wide configured default of 10 hours.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TlsParameter
A list of TLS parameters that indicate TLS parameter restrictions.
Use [New-TlsParameter](./New-TlsParameter.md) to build the parameters that can restrict the protocols and cipher suites this credential can use.

```yaml
Type: TlsParameter[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSSPI.Credential
The generated credential handle. This object has the following properties:

+ `SafeHandle`: The handle to the SSPI credentials generated.

+ `Expiry`: The expiry of the credentials.

## NOTES

## RELATED LINKS

[SCH_CREDENTIALS](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-sch_credentials)
