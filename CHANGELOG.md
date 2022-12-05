# Changelog for PSSPI

## v0.4.0 - 2022-12-06

+ Added the following cmdlets
  + `Get-SecContextRemoteCert` - Gets the certificate presented by the peer in a Schannel exchange

## v0.3.1 - 2022-11-14

+ Fix up memory access violation that occurs when the garbage collector tries to cleanup credential and security context handles that failed to be acquired

## v0.3.0 - 2022-11-13

+ Added the following cmdlets for Schannel security contexts
  + `Get-SchannelCredential` - Get a Schannel SSPI cipher using the legacy Schannel credential struct
  + `Get-SCHCredential` - Get a Schannel SSPI cipher using the new Schannel credential struct, allows TLS 1.3 (Win 10 1809+)
  + `Get-SecContextCipherInfo` - Get information about a negotiated TLS context such as the protocol and cipher suite
  + `New-CryptoSetting` - Build a crypto setting object for use with restricting SCH Credential cipher suite algorithms
  + `New-TlsParameter` - Build a TLS parameter object for use with restricting SCH Credential TLS options

## v0.2.0 - 2022-09-09

+ Added `AllowPackage` and `RejectPackage` for `New-SSPICredential` to specify what package a `Negotiate` credential can utilise

## v0.1.0 - 2022-06-13

+ Initial version of the `PSSPI` module
