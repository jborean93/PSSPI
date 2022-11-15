---
Module Name: PSSPI
Module Guid: dd030a76-0380-43c9-b842-d21a99dce2e0
Download Help Link: 
Help Version: 1.0.0.0
Locale: en-US
---

# PSSPI Module
## Description
PowerShell module for interacting with Security Support Provider Interface (SSPI). More information about the Schannel credentials can be found at about_TLSAuthentication .

## PSSPI Cmdlets
### [Get-SchannelCredential](Get-SchannelCredential.md)
Creates a Schannel SSPI credential based on the legacy SCHANNEL_CRED structure.

### [Get-SCHCredential](Get-SCHCredential.md)
Creates an Schannel SSPI credential based on the newer SCH_CREDENTIALS structure.

### [Get-SecContextCipherInfo](Get-SecContextCipherInfo.md)
Get TLS cipher information from a negotiated context.

### [Get-SecContextRemoteCert](Get-SecContextRemoteCert.md)
Gets the certificate supplied by the peer.

### [Get-SSPICredential](Get-SSPICredential.md)
Get a SSPI credential handle.

### [Get-SSPIPackage](Get-SSPIPackage.md)
Gets security package information.

### [New-ChannelBindingBuffer](New-ChannelBindingBuffer.md)
Create channel binding structure for authentication.

### [New-CryptoSetting](New-CryptoSetting.md)
Creates a Crypto Setting object for use as a TLS Parameter to disable certain cipher suites.

### [New-SecBuffer](New-SecBuffer.md)
Create an SSPI security buffer

### [New-SecContext](New-SecContext.md)
Creates an SSPI context.

### [New-TlsParameter](New-TlsParameter.md)
Creates a TLS parameter object for use with an SCH credential (Schannel).

### [Set-KdcProxy](Set-KdcProxy.md)
Set the KDC proxy settings on an SSPI credential.

### [Step-AcceptSecContext](Step-AcceptSecContext.md)
Steps through a clients security context exchange.

### [Step-InitSecContext](Step-InitSecContext.md)
Steps through a clients security context exchange.

