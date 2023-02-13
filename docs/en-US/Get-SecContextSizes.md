---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SecContextSizes.md
schema: 2.0.0
---

# Get-SecContextSizes

## SYNOPSIS
Gets the sizes of important structures used in message support functions.

## SYNTAX

```
Get-SecContextSizes -Context <SecurityContext[]> [<CommonParameters>]
```

## DESCRIPTION
Gets the various message sizes of a security context, for example the size of a security token, header/trailer used in signatures/encryption, and more.

## EXAMPLES

### Example 1 - Get context sizes
```powershell
PS C:\> $ctx = New-SecContext
PS C:\> ... Complete auth
PS C:\> Get-SecContextSizes -Context $ctx
```

Gets the sizes associated with the negotiated security context.

## PARAMETERS

### -Context
The security context to query.
This context must have completed the authentication stage until it has been marked as Ok from `Step-InitSecContext` or `Step-AcceptSecContext`.

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

### PSSPI.Commands.ContextSizes
The ContextSizes object contains the following properties

+ `MaxToken` - Maximum size of the security token used in the authentication exchanges

+ `MaxSignature` - Maximum size of the signatures created by this security context, will be 0 if integrity services are not negotiated

+ `BlockSize` - Preferred integral size of the messages, e.g. 8 indicates messages should be of size zero mod eight for optimal performance

+ `SecurityTrailer` - Size of the security trailer to be appended to messages

## NOTES

## RELATED LINKS

[SecPkgContext_Sizes](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sizes)
