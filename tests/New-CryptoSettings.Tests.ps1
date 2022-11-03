. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-CryptoSetting" {
    It "Tries to provide too many chaining modes" {
        $chainingModes = @("mode") * 17
        $out = New-CryptoSetting -Usage Digest -Algorithm test -ChainingMode $chainingModes -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*Crypto Settings can not have more than 16 chaining modes specified*"
    }

    It "Completes chaining mode" {
        $actual = Complete 'New-CryptoSetting -ChainingMode '
        $actual.Count | Should -Be 6
        $actual | ForEach-Object {
            $_.CompletionText | Should -BeIn @(
                "ChainingModeCBC"
                "ChainingModeCCM"
                "ChainingModeCFB"
                "ChainingModeECB"
                "ChainingModeGCM"
                "ChainingModeN/A"
            )
        }
    }

    It "Completes chaining mode with partial match" {
        $actual = Complete 'New-CryptoSetting -ChainingMode chainingmodee'
        $actual.Count | Should -Be 1
        $actual.CompletionText | Should -Be ChainingModeECB
    }

    It "Completes algorithm with no usage" {
        $actual = Complete "New-CryptoSetting -Algorithm "
        $actual.Count | Should -Be 18
        $actual | ForEach-Object {
            $_.CompletionText | Should -BeIn @(
                "3DES"
                "AES"
                "CHACHA20_POLY1305"
                "DES"
                "DH"
                "DSA"
                "DSS"
                "ECDH"
                "ECDSA"
                "EXPORT"
                "EXPORT1024"
                "MD5"
                "PSK"
                "RC4"
                "RSA"
                "SHA1"
                "SHA256"
                "SHA384"
            )
        }
    }

    It "Completes algorithm with partial match" {
        $actual = Complete "New-CryptoSetting -Algorithm ae"
        $actual.Count | Should -Be 1
        $actual.CompletionText | Should -Be AES
    }

    It "Completes algorithm with <Usage> usage" -TestCases @(
        @{ Usage = "KeyExchange"; Expected = @("DH", "ECDH", "PSK", "RSA") }
        @{ Usage = "Signature"; Expected = @("DSA", "DSS", "ECDSA", "EXPORT", "EXPORT1024", "RSA") }
        @{ Usage = "Cipher"; Expected = @("3DES", "AES", "DES", "CHACHA20_POLY1305", "RC4") }
        @{ Usage = "Digest"; Expected = @("MD5", "SHA1", "SHA256", "SHA384") }
        @{ Usage = "CertSig"; Expected = @("DSA", "ECDSA", "RSA", "SHA1", "SHA256") }
    ) {
        param($Usage, $Expected)

        $actual = Complete "New-CryptoSetting -Usage $Usage -Algorithm "
        $actual.Count | Should -Be $Expected.Count
        $actual | ForEach-Object {
            $_.CompletionText | Should -BeIn $Expected
        }
    }

    It "Completes algorithm with usage variable" {
        $actual = Complete "New-CryptoSetting -Usage ([PSSPI.SchannelCryptoUsage]::Cipher) -Algorithm ae"
        $actual.Count | Should -Be 1
        $actual.CompletionText | Should -Be AES
    }
}
