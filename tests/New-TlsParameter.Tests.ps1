. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-TlsParameter" {
    It "Tries to provide too many ALPN Ids" {
        $alpnIds = @("mode") * 17
        $out = New-TlsParameter -AlpnId $alpnIds -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*TLS Parameters can not have more than 16 ALPN Ids specified*"
    }

    It "Tries to provide too many crypto settings" {
        $cs = @(New-CryptoSetting -Usage Digest -Algorithm AES) * 17
        $out = New-TlsParameter -DisabledCrypto $cs -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*TLS Parameters can not have more than 16 crypto settings specified*"
    }
}
