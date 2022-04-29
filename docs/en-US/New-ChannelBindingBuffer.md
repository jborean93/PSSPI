---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/New-ChannelBindingBuffer.md
schema: 2.0.0
---

# New-ChannelBindingBuffer

## SYNOPSIS
Create channel binding structure for authentication.

## SYNTAX

```
New-ChannelBindingBuffer [-InitiatorAddrType <Int32>] [-Initiator <Byte[]>] [-AcceptorAddrType <Int32>]
 [-Acceptor <Byte[]>] [-ApplicationData <Byte[]>] [<CommonParameters>]
```

## DESCRIPTION
Creates a security buffer that can be supplied when stepping through an security context that contains the channel binding data for a context.

## EXAMPLES

### Example 1: Create channel binding with application data
```powershell
PS C:\> $cb = New-ChannelBindingBuffer -ApplicationData $byteArray
```

Creates the channel binding buffer with `ApplicationData` set to the byte array passed in.

## PARAMETERS

### -Acceptor
The acceptor address data.
This is typically unusued.

```yaml
Type: Byte[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AcceptorAddrType
The acceptor address type.
This is typically unused.

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

### -ApplicationData
The application data of the channel binding.
The value here depends on the channel binding being used.

```yaml
Type: Byte[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Initiator
The initiator address data.
This is typically unusued.

```yaml
Type: Byte[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InitiatorAddrType
The initiator address type.
This is typically unused.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### PSSPI.ChannelBindingBuffer
The generated channel binding buffer. This object has the following properties:

+ `InitiatorAddrType` - The initiator address type

+ `Initiator` - The initiator address data

+ `AcceptorAddrType` - The acceptor address type

+ `Acceptor` - The acceptor address data

+ `ApplicationData` - The application data

## NOTES

## RELATED LINKS

[SEC_CHANNEL_BINDINGS](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings)
