---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SecContextRemoteCert.md
schema: 2.0.0
---

# Get-SecContextRemoteCert

## SYNOPSIS
Gets the certificate supplied by the peer.

## SYNTAX

```
Get-SecContextRemoteCert -Context <SecurityContext[]> [<CommonParameters>]
```

## DESCRIPTION
Gets the X509 certificate that was supplied by the peer.
For an outbound credential this is the server certificate.
For an inbound credential this is the client authentication certificate if it was requested with `ASC_REQ_MUTUAL_AUTH`.
If using an inbound credential andclient auth was not requested then the cmdlet will fail as there is no certificate from the peer to retrieve.

## EXAMPLES

### Example 1 - Get server certificate
```powershell
PS C:\> $ctx = Get-SCHCredential
PS C:\> ... Complete auth
PS C:\> Get-SecContextRemoteCert -Context $ctx
```

Gets the certificate given by the server.

## PARAMETERS

### -Context
The Schannel security context to query.
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

### System.Security.Cryptography.X509Certificates.X509Certificate2
The X509Certificate2 object that represents the certificate retrieved from the server.

## NOTES

## RELATED LINKS
