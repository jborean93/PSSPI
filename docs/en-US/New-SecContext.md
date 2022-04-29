---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/New-SecContext.md
schema: 2.0.0
---

# New-SecContext

## SYNOPSIS
Creates an SSPI context.

## SYNTAX

```
New-SecContext [-Credential <Credential>] [<CommonParameters>]
```

## DESCRIPTION
Creates the initial SSPI context using an optional credential.
This context needs to be stepped through to be usable and to produce the security tokens exchanged with a peer.

## EXAMPLES

### Example 1: Create a security context for the current user
```powershell
PS C:\> $cred = Get-SSPICredential -Package Negotiate
PS C:\> $ctx = New-SecContext -Credential $cred
```

Creates an SSPI context for the `Negotiate` provider using the user's current credentials.

## PARAMETERS

### -Credential
The SSPI credential created by [Get-SSPICredential](./Get-SSPICredential.md) to use for the context.
If omitted then the current user context will be used with the security context.

```yaml
Type: Credential
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

### PSSPI.SecurityContext
+ `Credential` - The credential associated with the context

+ `SafeHandle` - The handle to the SSPI security context

+ `Expiry` - The expiry of the security context

## NOTES

## RELATED LINKS
