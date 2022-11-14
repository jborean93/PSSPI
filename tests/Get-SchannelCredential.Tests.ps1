. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Schannel SCHANNEL_CRED" {
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
    }
    AfterAll {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($ServerCert.Thumbprint)" -Force -Confirm:$false
    }
    It "Authenticates with Defaults" {
        $cCred = Get-SchannelCredential
        $sCred = Get-SchannelCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

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

    It "Authenticates with explicit protocol" {
        $cCred = Get-SchannelCredential -Protocol SP_PROT_TLS1_2
        $sCred = Get-SchannelCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

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

    It "Authenticates with maximum cipher strength" {
        $cCred = Get-SchannelCredential -MaximumCipherStrength 128
        $sCred = Get-SchannelCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $cActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 128

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $sActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 128
    }

    It "Authenticates with explicit algorithms" {
        $cCred = Get-SchannelCredential -SupportedAlgs CALG_AES_128
        $sCred = Get-SchannelCredential -CredentialUse SECPKG_CRED_INBOUND -Certificate $ServerCert

        $cCtx, $sCtx = Complete-TlsAuth -Client $cCred -Server $sCred -Target $Target
        $cActual = Get-SecContextCipherInfo -Context $cCtx
        $sActual = Get-SecContextCipherInfo -Context $sCtx

        $cActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $cActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $cActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        $cActual.Cipher | Should -Be AES
        $cActual.CipherLength | Should -Be 128

        $sActual | Should -BeOfType ([PSSPI.Commands.CipherInfo])
        $sActual.Protocol | Should -Be ([PSSPI.Commands.TlsProtocol]::TLS1_2)
        $sActual.CipherSuite | Should -Be TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        $sActual.Cipher | Should -Be AES
        $sActual.CipherLength | Should -Be 128
    }

    It "Doesn't provide cert with inbound credential" {
        $out = Get-SchannelCredential -CredentialUse SECPKG_CRED_INBOUND -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*At least one certificate must be specified when using SECPKG_CRED_INBOUND*"
    }

    It "Fails to get credential for protocol not available" {
        $out = Get-SchannelCredential -Protocols SP_PROT_SSL3 -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*AcquireCredentialsHandle failed*"
    }
}
