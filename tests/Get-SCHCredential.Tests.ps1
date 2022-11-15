. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Schannel SCH_CREDENTIALS" {
    BeforeAll {
        $Target = "test-host.domain.com"

        $certParams = @{
            DnsName           = $Target
            CertStoreLocation = "Cert:\LocalMachine\My"
        }
        $ServerCert = New-SelfSignedCertificate @certParams
        Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($ServerCert.Thumbprint)" -Force -Confirm:$false

        $rootStore = Get-Item Cert:\LocalMachine\Root
        $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $rootStore.Add($ServerCert)
        }
        finally {
            $rootStore.Dispose()
        }

        $clientCertParams = @{
            Subject      = 'CN=test-user'
            KeyUsage     = 'DigitalSignature', 'KeyEncipherment'
            KeyAlgorithm = 'RSA'
            KeyLength    = 2048
            Type         = 'Custom'
        }
        $ClientCert = New-SelfSignedCertificate @clientCertParams
        Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($ClientCert.Thumbprint)" -Force -Confirm:$false
    }
    AfterAll {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($ServerCert.Thumbprint)" -Force -Confirm:$false
    }
    It "Authenticates with Defaults" {
        $cCred = Get-SCHCredential
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $cActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 256

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $sActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 256

        $serverCertActual = Get-SecContextRemoteCert -Context $cCtx
        $serverCertActual.Thumbprint | Should -Be $ServerCert.Thumbprint

        # Expected to be $null
        $out = Get-SecContextRemoteCert -Context $sCtx -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*QueryContextAttributes failed (No credentials are available in the security package*"
    }

    It "Authenticates with ALPN disabled" {
        $tlsParam = New-TlsParameter -AlpnId http/1.1 -DisabledProtocol (-bnot ([PSSPI.SchannelProtocols]::SP_PROT_TLS1_3))
        $cCred = Get-SCHCredential -TlsParameter $tlsParam
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $cActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 256

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $sActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 256

        $serverCertActual = Get-SecContextRemoteCert -Context $cCtx
        $serverCertActual.Thumbprint | Should -Be $ServerCert.Thumbprint
    }

    It "Authenticates with TLS 1.2" {
        $tlsParam = New-TlsParameter -DisabledProtocol (-bnot ([PSSPI.SchannelProtocols]::SP_PROT_TLS1_2))
        $cCred = Get-SCHCredential -TlsParameter $tlsParam
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $cActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 256

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $sActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 256
    }

    It "Authenticates disabling stronger cipher" {
        $cs = New-CryptoSetting -Usage Cipher -Algorithm AES -MaxBitLength 128
        $tlsParam = New-TlsParameter -DisabledProtocol (-bnot ([PSSPI.SchannelProtocols]::SP_PROT_TLS1_3)) -DisabledCrypto $cs
        $cCred = Get-SCHCredential -TlsParameter $tlsParam
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $cActual.CipherSuite | Should -Be TLS_AES_128_GCM_SHA256
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 128

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $sActual.CipherSuite | Should -Be TLS_AES_128_GCM_SHA256
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 128
    }

    It "Disables the CBC cipher mode" {
        $cs = New-CryptoSetting -Usage Cipher -Algorithm AES -ChainingMode ChainingModeGCM
        $tlsParam = New-TlsParameter -DisabledProtocol (-bnot ([PSSPI.SchannelProtocols]::SP_PROT_TLS1_2)) -DisabledCrypto $cs
        $cCred = Get-SCHCredential -TlsParameter $tlsParam
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $cActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 256

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $sActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 256
    }

    It "Authenticates with client auth" {
        $cCred = Get-SCHCredential -Certificate $ClientCert
        $sCred = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target -ClientAuth
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $cActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 256

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_3)
        $sActual.CipherSuite | Should -Be TLS_AES_256_GCM_SHA384
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 256

        $serverCertActual = Get-SecContextRemoteCert -Context $cCtx
        $serverCertActual.Thumbprint | Should -Be $ServerCert.Thumbprint

        $clientCertActual = Get-SecContextRemoteCert -Context $sCtx
        $clientCertActual.Thumbprint | Should -Be $ClientCert.Thumbprint
    }

    It "Doesn't provide cert with inbound credential" {
        $out = Get-SCHCredential -CredentialUse SECPKG_CRED_INBOUND -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*At least one certificate must be specified when using SECPKG_CRED_INBOUND*"
    }

    It "Tries to provide too many parameters" {
        $params = @(New-TlsParameter) * 17
        $out = Get-SCHCredential -TlsParameter $params -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*Schannel credential can not have more than 16 TLS Parameters*"
    }

    It "Fails to get credential for protocol not available" {
        $params = New-TlsParameter -DisabledProtocol (-bnot ([PSSPI.SchannelProtocols]::SP_PROT_SSL3))
        $out = Get-SCHCredential -TlsParameter $params -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*AcquireCredentialsHandle failed*"
    }
}
