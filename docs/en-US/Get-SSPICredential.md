---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SSPICredential.md
schema: 2.0.0
---

# Get-SSPICredential

## SYNOPSIS
Get a SSPI credential handle.

## SYNTAX

```
Get-SSPICredential -Package <PackageOrString> [-Principal <String>] [-CredentialUse <CredentialUse>]
 [-Credential <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
Get a SSPI credential for use with a security context.
Currently a credential can be for the current user context or for an explicit credential.

## EXAMPLES

### Example 1: Get the Negotiate credentials for the current user
```powershell
PS C:\> Get-SSPICredential -Name Negotiate
```

Gets the SSPI credential for the current user for the `Negotiate` package.

### Example 2: Get the Kerberos credential with an explicit user
```powershell
PS C:\> $cred = Get-Credential
PS C:\> Get-SSPICredential -Name Kerberos -Credential $cred
```

Gets the SSPI credential with explicit credentials for the `Kerberos` package.

## PARAMETERS

### -Credential
Use the username/password of the credentials specified instead of the current user context.

```yaml
Type: PSCredential
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
Multiple values can be specified depending on the desired use.

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

### -Package
The SSPI package the credential is used for, like `Negotiate`, `Kerberos`, `NTLM`, and more.
See [Get-SSPIPackage](./Get-SSPIPackage.md) for more details.

```yaml
Type: PackageOrString
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Principal
The principal to use with the credential, the purpose of this value depends on the package being used.


```yaml
Type: String
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

### PSSPI.SspiCredential
The generated credential handle. This object has the following properties:

+ `SafeHandle`: The handle to the SSPI credentials generated.

+ `Expiry`: The expiry of the credentials.

## NOTES
Credentials aren't validated by SSPI when being generated.
It is verified when being used by `InitializeSecurityContext` or `AcceptSecurityContext`.

## RELATED LINKS

[AcquireCredentialsHandleW](https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general)
