---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/New-TlsParameter.md
schema: 2.0.0
---

# New-TlsParameter

## SYNOPSIS
Creates a TLS parameter object for use with an SCH credential (Schannel).

## SYNTAX

```
New-TlsParameter [-AlpnId <String[]>] [-DisabledProtocol <SchannelProtocols>]
 [-DisabledCrypto <CryptoSetting[]>] [-Optional] [<CommonParameters>]
```

## DESCRIPTION
Builds a TLS Parameter object that represents TLS parameter restrictions.
It can be used to disable TLS protocols or with `New-CryptoSetting` to disable certain cipher suites.
It is based off the `TLS_PARMETERS` struct in `Schannel.h` and is used with the newer SCH style credential added in Windows 10 Build 1809.
Multiple TLS parmeter objects can be used with `Get-SCHCredential -TlsParameter`.

## EXAMPLES

### Example 1 - Create Parameter to only allow TLS 1.2 connections
```powershell
PS C:\> New-TlsParameter -DisableProtocol (-bnot [PSSPI.SchannelProtocols]::SP_PROT_TLS1_3)
```

Creates a TLS Parameter that disables all protocols except for TLS 1.3

### Example 2 - Create Parameter to disable TLS 1.0 and TLS 1.1
```powershell
PS C:\> New-TlsParameter -DisableProtocol SP_PROT_TLS1_0, SP_PROT_TLS1_1
```

Creates a TLS Parameter that disabled TLS 1.0 and TLS 1.1.

## PARAMETERS

### -AlpnId
The ALPN IDs the parameter applies to.
When omitted, the parameter applies to any negotiated protocols.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisabledCrypto
The crypto settings as created by [New-CryptoSetting](./New-CryptoSetting.md) to disable.
A maximum of 16 settings can be applied to a single TLS Parameter.
This is used to disable cipher suite algorithms that are used in the connection rather than the full TLS protocol.

```yaml
Type: CryptoSetting[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisabledProtocol
The TLS protocols to disable.
Any protocols specified here will not be available for the Schannel credential to use.
For example `-DisabledProtocol SP_PROT_TLS1_3` will disable TLS 1.3 on the handshake.
The `-bnot` operator can be used to inverse the selection so that all the protocols but the one specified are disabled, effectively making it an allow list of protocols.
For example `-DisableProtocol (-bnot ([PSSPI.Schannel]::SP_PROT_TLS1_3))` will disable all protocols but TLS 1.2.

Multiple protocols can be specified for this parameter.

```yaml
Type: SchannelProtocols
Parameter Sets: (All)
Aliases:
Accepted values: SP_PROT_NONE, SP_PROT_PCT1_SERVER, SP_PROT_PCT1_CLIENT, SP_PROT_PCT1, SP_PROT_SSL2_SERVER, SP_PROT_SSL2_CLIENT, SP_PROT_SSL2, SP_PROT_SSL3_SERVER, SP_PROT_SSL3_CLIENT, SP_PROT_SSL3, SP_PROT_TLS1_SERVER, SP_PROT_TLS1_0_SERVER, SP_PROT_SSL3TLS1_SERVERS, SP_PROT_TLS1_CLIENT, SP_PROT_SSL3TLS1_CLIENTS, SP_PROT_TLS1_0_CLIENT, SP_PROT_TLS1, SP_PROT_TLS1_0, SP_PROT_SSL3TLS1, SP_PROT_TLS1_1_SERVER, SP_PROT_TLS1_1_CLIENT, SP_PROT_TLS1_1, SP_PROT_TLS1_2_SERVER, SP_PROT_TLS1_2_CLIENT, SP_PROT_TLS1_2, SP_PROT_TLS1_3_SERVER, SP_PROT_TLS1_3_CLIENT, SP_PROT_TLS1_3, SP_PROT_DTLS_SERVER, SP_PROT_DTLS1_0_SERVER, SP_PROT_DTLS1_0_CLIENT, SP_PROT_DTLS_CLIENT, SP_PROT_DTLS1_0, SP_PROT_DTLS, SP_PROT_DTLS1_2_SERVER, SP_PROT_DTLS1_2_CLIENT, SP_PROT_DTLS1_2, SP_PROT_UNI_SERVER, SP_PROT_SERVERS, SP_PROT_UNI_CLIENT, SP_PROT_CLIENTS, SP_PROT_UNI, SP_PROT_ALL

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Optional
Marks the parameter as optional.
This is only used for the server/acceptor as a way to mark a parameter that can be ignored if it causes the handshake from the client to be rejected.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSSPI.TlsParameter
An object representing the TLS parameter requested. It contains the following properties

+ `AlpnIds`

+ `DisabledProtocols`

+ `DisabledCryptos`

+ `Optional`

## NOTES

## RELATED LINKS

[TLS_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-tls_parameters)
