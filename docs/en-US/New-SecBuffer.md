---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/New-SecBuffer.md
schema: 2.0.0
---

# New-SecBuffer

## SYNOPSIS
Create an SSPI security buffer

## SYNTAX

```
New-SecBuffer -Type <SecBufferType> [-Flags <SecBufferFlags>] [-Data <Byte[]>] [<CommonParameters>]
```

## DESCRIPTION
Creates an SSPI security buffer that can be used for SSPI functions.
This buffer is typically used for stepping through a new security context or encrypting/decrypting a message.

## EXAMPLES

### Example 1: Create token security buffer
```powershell
PS C:\> New-SecBuffer -Type SECBUFFER_TOKEN -Data $byteArray
```

Creates a security buffer that stores a token used with authentication.
The `$byteArray` is a byte array from an external source.

### Example 2: Create token security buffer with no user value
```powershell
PS C:\> New-SecBuffer -Type SECBUFFER_TOKEN
```

Creates an empty security buffer without any data present.
This type of security buffer is useful when calling an API that will populate the data based on the operation it performs.

## PARAMETERS

### -Data
The raw byte array of the data the buffer represents or `$null` to use a buffer that should be populated by Windows during an SSPI call.

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

### -Flags
Custom flags to set on th security buffer.

```yaml
Type: SecBufferFlags
Parameter Sets: (All)
Aliases:
Accepted values: NONE, SECBUFFER_READONLY_WITH_CHECKSUM, SECBUFFER_RESERVED, SECBUFFER_READONLY

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Type
The security buffer type that the data represents.

```yaml
Type: SecBufferType
Parameter Sets: (All)
Aliases:
Accepted values: SECBUFFER_EMPTY, SECBUFFER_DATA, SECBUFFER_TOKEN, SECBUFFER_PKG_PARAMS, SECBUFFER_MISSING, SECBUFFER_EXTRA, SECBUFFER_STREAM_TRAILER, SECBUFFER_STREAM_HEADER, SECBUFFER_NEGOTIATION_INFO, SECBUFFER_PADDING, SECBUFFER_STREAM, SECBUFFER_MECHLIST, SECBUFFER_MECHLIST_SIGNATURE, SECBUFFER_TARGET, SECBUFFER_CHANNEL_BINDINGS, SECBUFFER_CHANGE_PASS_RESPONSE, SECBUFFER_TARGET_HOST, SECBUFFER_ALERT, SECBUFFER_APPLICATION_PROTOCOLS, SECBUFFER_SRTP_PROTECTION_PROFILES, SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER, SECBUFFER_TOKEN_BINDING, SECBUFFER_PRESHARED_KEY, SECBUFFER_PRESHARED_KEY_IDENTITY

Required: True
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

### PSSPI.SecurityBuffer
An SSPI security buffer. This contains the following properties:

+ `Type` - The security buffer type

+ `Flags` - Flags for the security buffer

+ `Length` - The length of populated data, will be the length of `Data` on creation but may be modified by a call to SSPI

+ `Data` - The raw bytes of the buffer, or `$null` if the data is to be set by SSPI

## NOTES

## RELATED LINKS

[SecBuffer](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer)
