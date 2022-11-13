---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SCHCredential.md
schema: 2.0.0
---

# Get-SecContextCipherInfo

## SYNOPSIS
Get TLS cipher information from a negotiated context.

## SYNTAX

```
Get-SecContextCipherInfo -Context <SecurityContext[]> [<CommonParameters>]
```

## DESCRIPTION
Gets the TLS protocol, cipher suite, and cipher algorithm information that was negotiated in a Schannel TLS context.

## EXAMPLES

### Example 1
```powershell
PS C:\> $cred = Get-SCHCredential
PS C:\> $ctx = New-SecContext -Credential $cred
PS C:\> ... # Set up the context
PS C:\> Get-SecContextCipherInfo -Context $ctx
```

Gets the cipher information of a negotiated TLS context.

## PARAMETERS

### -Context
The Schannel security context to query.
This context must have completed the authentication stage until it has been marked as Ok from `Step-InitSecContext`.

```yaml
Type: SecurityContext[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### PSSPI.SecurityContext[]
An array of security contexts can be piped into this cmdlet.

## OUTPUTS

### PSSPI.Commands.CipherInfo
The CipherInfo object contains the following properties

+ `Protocol` - The TLS protocol that was negotiated, e.g. `TLS1_3`

+ `CipherSuite` - The Cipher Suite negotiated as a string, e.g. `TLS_AES_256_GCM_SHA384`

+ `Cipher` - The cipher/auth algorithm that was used, e.g. `AES`

+ `CipherLength` - The length in bits of the cipher/auth algorithm that was used, e.g. `256

## NOTES

## RELATED LINKS

[SecPkgContext_CipherInfo](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_cipherinfo)
