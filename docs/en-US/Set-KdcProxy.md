---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Set-KdcProxy.md
schema: 2.0.0
---

# Set-KdcProxy

## SYNOPSIS
Set the KDC proxy settings on an SSPI credential.

## SYNTAX

```
Set-KdcProxy -Credential <Credential> -Server <String> [-ForceProxy] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Sets the KDC proxy settings for a Kerberos exchange on the provided SSPI credential.
This is used to either set a new proxy or override global wide settings for Kerberos exchanges.
This cmdlet will fail if the credential was created for a security provider that was not `Kerberos` or `Negotiate`.

The proxy settings will be used anytime the credential it was set on was used with a security context.

## EXAMPLES

### Example 1: Set the proxy for an SSPI credential
```powershell
PS C:\> $cred = Get-SSPICredential -Package Kerberos
PS C:\> Set-KdcProxy -Credential $cred -Server proxy-host
```

Sets the KDC proxy to `proxy-host` for the provided SSPI credential.

## PARAMETERS

### -Credential
The SSPI credential to set the proxy settings on.

```yaml
Type: Credential
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ForceProxy
Set the `KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY` flag on the proxy settings.
This forces SSPI to always use the proxy provided instead of only when the configured KDC was unreachable through normal means.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
The proxy server to set.
This should be in the format `hostname` or `hostname:port:path`.
If only the hostname is set then Windows will automatically use the the `port:path` or `443:KdcProxy`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs. The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

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

### None
## NOTES

## RELATED LINKS

[SetCredentialsAttributesW](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesw)
[SecPkgCredentials_KdcProxySettingsW](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcredentials_kdcproxysettingsw)
