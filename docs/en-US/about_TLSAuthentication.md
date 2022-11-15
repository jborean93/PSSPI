# TLS Authentication
## about_TLSAuthentication

# SHORT DESCRIPTION
On Windows, SSPI is used to setup a TLS connection and provides the API that programs use to perform the handshake.
This is a similar role to OpenSSL, except the APIs follow a different format.
This doc aims to provide some examples of how to use PSSPI to test out TLS connections.

# CREDENTIAL TYPES
There are 2 Schannel credential types that can be used with SSPI:

+ `SCHANNEL_CRED` - Retrieved with `Get-SchannelCredential`

+ `SCH_CREDENTIALS` - Retrieved with `Get-SCHCredential`

The `SCHANNEL_CRED` is the legacy credential type and is deprecated in favour of `SCH_CREDENTIALS`.
It can only use TLS 1.2 or lower and provides a limited way of controlling the cipher suites that are used in the connection.
It operates on an allow list where the system defaults are used but when a protocols is specified it will only allow the ones specified to be used.

The `SCH_CREDENTIALS` is the new credential type added with Windows 10 Build 1809.
It must be used if the client or server wishes to negotiate with TLS 1.3.
The ability to restrict protocols and cipher suites is a lot more robust than `SCHANNEL_CRED` and operates on a deny mechanism.
This deny list is specified through TLS Parameters created by `New-TlsParameter` which each parameter can specify TLS protocols to restrict as well as crypto algorithms through the `-DisabledCrypto` parameter.

Both credential types support the `-Flags` field which can be set to various flags that control the handshake behaviour.
The `SCH_USE_STRONG_CRYPTO` can, and should, be specified so that Schannel restricts the default protocol and cipher suite list to stronger algorithms than what the default offers.

The `Get-SCHCredential` cmdlet should be used for Schannel authentication attempts on any host that runs with Windows 10 Build 1809 or newer.
The `Get-SchannelCredential` is only available for older hosts and support for it is limited.

# CLIENT AUTHENTICATION
TLS supports client authentication where the server requests the client to send an X.509 certificate to the server.
The server can then inspect this certificate and work through any authorisation rules it needs to do.
For the server to request the client to send a certificate it must be stepped through with the `ASC_REQ_MUTUAL_AUTH` ContextReq flag.

Once the handshake is complete, it can retrieve the certificate send by the client by calling `Get-SecContextRemoteCert -Context $serverContext`.
It is up to the server to then inspect the certificate and authorised the client identity.

# AUTHENTICATION EXAMPLE
The authentication phase is known as the TLS handshake and requires multiple calls to the SSPI API to complete.
The exchange is quite complex but hopefully this example helps to illustrate what is needed.

```powershell
# The client will get its credentials and build the security context.
# It is with Get-SCHCredential that restrictions can be placed on what TLS
# protocols are used and other authentication options.
$cCred = Get-SCHCredential
$cCtx = New-SecContext -Credential $cCred

# The server must provide a X509Certificate object when getting its
# credentials. The example here uses a hardcoded thumbprint but the
# cert provider can be used to scan the cert store and filter out the certs
# needed dynamically.
$thumbprint = '2B192AD47337A1DEEAFB087E51F6BB294F713671'
$cert = Get-Item Cert:\LocalMachine\My\$thumbprint
$sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $cert
$sCtx = New-SecContext -Credential $sCred

# There are multiple steps needed to complete the authentication phase. This
# example has been tested with TLS 1.3 where the client and server both produce
# two tokens that each other must process.
$sRes = $null
while ($true) {
    $stepParams = @{
        Context = $cCtx
        Target = "target-host"  # Used for SNI and cert CN verification
        ContextReq = 'ISC_REQ_SEQUENCE_DETECT, ISC_REQ_REPLAY_DETECT, ISC_REQ_CONFIDENTIALITY, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_STREAM'
    }

    if ($sRes) {
        # On subsequent calls the input buffer contains the SECBUFFER_TOKEN
        # from the server plus a SECBUFFER_EMPTY.
        $stepParams.InputBuffer = @(
            $sRes.Buffers[0]
            'SECBUFFER_EMPTY'
        )

        # The output buffer contains the token, an alert buffer and finally
        # an empty buffer.
        $stepParams.OutputBuffer = @(
            'SECBUFFER_TOKEN',
            'SECBUFFER_ALERT',
            'SECBUFFER_EMPTY'
        )
    }
    else {
        # On the first call the input buffer must not be set. The output buffer
        # must be a SECBUFFER_EMPTY which SSPI will fill.
        $stepParams.OutputBuffer = 'SECBUFFER_EMPTY'
    }

    $cRes = Step-InitSecContext @stepParams

    # First call will be ContinueNeeded. The second call will be Ok but the
    # client may still need to process more data from the server. Only exit
    # the authentication loop when there's no more data to send to the server
    if ($cRes.Buffers[0].Length -eq 0) {
        break
    }

    # The server's input buffer is the SECBUFFER_TOKEN from the client and a
    # SECBUFFER_EMPTY token. The output buffer is simply the SECBUFFER_TOKEN.
    $stepParams = @{
        Context = $sCtx
        ContextReq = 'ASC_REQ_ALLOCATE_MEMORY'
        InputBuffer = @(
            $cRes.Buffers[0]
            'SECBUFFER_EMPTY'
        )
        OutputBuffer = 'SECBUFFER_TOKEN'
    }
    $sRes = Step-AcceptSecContext @stepParams

    # Exit the loop if there's no more data to send to the server
    if ($sRes.Buffers[0].Length -eq 0) {
        break
    }
}

if ($cRes.Result -ne [PSSPI.SecContextStatus]::Ok) {
    throw "Client context is not complete and there's no more server data: $($cRes.Result)"
}
if ($sRes.Result -ne [PSSPI.SecContextStatus]::Ok) {
    throw "Server context is not complete and there's no more client data: $($sRes.Result)"
}
```
