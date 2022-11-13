---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/New-CryptoSetting.md
schema: 2.0.0
---

# New-CryptoSetting

## SYNOPSIS
Creates a Crypto Setting object for use as a TLS Parameter to disable certain cipher suites.

## SYNTAX

```
New-CryptoSetting -Usage <SchannelCryptoUsage> -Algorithm <String> [-ChainingMode <String[]>]
 [-MinBitLength <Int32>] [-MaxBitLength <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Builds a Crypto Setting object that represents a cipher suite cryptography algorithm.
It doesn't represent a single cipher suite but rather components of a cipher suite allowing you to disable weaker components by type rather than by name.
It is used in TLS Parameters to restrict the cipher suites used in a TLS handshake.
It is based off the `CRYPTO_SETTINGS` struct in `Schannel.h` and is used with the newer SCH style credentials added in Windows 10 Build 1809.
Use these crypto settings as a value for `New-TlsParameter -CryptoSetting ...` which is used with `Get-SCHCredential`.
Multiple crypto setting objects can be used with `-CryptoSetting` allowing the caller to block multiple algorithms.

## EXAMPLES

### Example 1 - Disable TLS_CHACHA20_POLY1305_SHA256
```powershell
PS C:\> New-CryptoSetting -Usage Cipher -Algorithm CHACHA20_POLY1305
```

Creates a crypto setting that applies to any cipher suites that use the CHACHA20_POLY1305 algorithm.
When used with `New-TlsParameter -DisableCrypto $cs` it will disable the usage of the TLS 1.3 cipher suite `TLS_CHACHA20_POLY1305_SHA256`

### Example 2 - Disable AES 256
```powershell
PS C:\> New-CryptoSetting -Usage Cipher -Algorithm AES -MaxBitLength 128
```

Creates a crypto setting that applies to any cipher suites that use the AES algorithm and has a bit length greater than 128.

### Example 3 - Disable AES 128
```powershell
PS C:\> New-CryptoSetting -Usage Cipher -Algorithm AES -MinBitLength 256
```

Creates a crypto setting that applies to any cipher suites that use the AES algorithm and has a bit length less than 256.

### Example 4 - Disable SHA256 hashing algorithm
```powershell
PS C:\> New-CryptoSetting -Usage Digest -Algorithm SHA256
```

Creates a crypto setting that applies to any cipher suites that use the SHA256 digest/signature hashing algorithm.
For TLS 1.3 this will disable `TLS_AES_128_GCM_SHA256 ` but not `TLS_AES_256_GCM_SHA384`

## PARAMETERS

### -Algorithm
The identifier of the algorithm to restrict.
The identifier is dependent on the `-Usage` option chosen and is used to identify a component of the TLS cipher suite to disable.
For example `-Usage Cipher -Algorithm RC4` will disable and TLS cipher suite that uses `RC4` as the session/encryption cipher.
This parameter supports tab completion for known algorithms.

While the TLS Cipher Suite string uses `ECDHE` and `DHE`, they are represented by `ECDH` and `DH` as an algorithm in SSPI.

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

### -ChainingMode
If the cipher algorithm specified is a block mode cipher this can be used to disable the algorithm when using a particular chaining/block mode.
For example `-Usage Cipher -Algorithm AES -Chaining Mode ChainingModeCBC` will disable cipher suites that use the AES cipher in CBC mode.
A maximum of 16 chaining modes can be specified for this parameter.
A list of known chaining modes can be found under `BCRYPT_CHAINING_MODE` at https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers.
This parameter supports tab completion for known algorithms.

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

### -MaxBitLength
Specifies the maximum bit length of a cipher that is excluded from the ciphers specified by the crypto settings object.
For example specifying `-MaxBitLength 128` will disable any ciphers that are greater than 128 bits, i.e. AES256.

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

### -MinBitLength
Specifies the minimum bit length of a cipher that is excluded from the ciphers specified by the crypto settings object.
For example specifying `-MinBitLength 256` will disable any ciphers that are less than 256 bites, i.e. AES128.

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

### -Usage
The algorithm type/usage that this crypto setting represents.
This can be set to the following values

+ `KeyExchange` - Algorithm in the key exchange to disable

+ `Signature` - Algorithm in the signature to disable

+ `Cipher` - Algorithm in the cipher/authentication method to disable

+ `Digest` - Algorithm in the cipher/authentication digest to disable

+ `CertSig` - Algorithm and/or hash used to sign the certificate to disable, this is the `signature_algorithms` extension type in the TLS client hello

The usage value and algorithm are used by the crypto settings object to define the cipher suites which are blocked from being used.

```yaml
Type: SchannelCryptoUsage
Parameter Sets: (All)
Aliases:
Accepted values: KeyExchange, Signature, Cipher, Digest, CertSig

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

### PSSPI.CryptoSetting
An object representing the crypto setting requested. It contains the following properties

+ `Usage`

+ `Algorithm`

+ `ChainingModes`

+ `MinBitLength`

+ `MaxBitLength`

## NOTES

## RELATED LINKS

[CRYPTO_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-crypto_settings)
[eTlsAlgorithmUsage](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ne-schannel-etlsalgorithmusage)
[Cipher Suites in TLS Schannel](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel)
