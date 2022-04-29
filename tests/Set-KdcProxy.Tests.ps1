. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Set-KdcProxy" {
    It "Sets proxy on credential" {
        $cred = Get-SSPICredential -Package Kerberos
        Set-KdcProxy -Credential $cred -Server proxy
    }

    It "Sets proxy on credential with force flag" {
        $cred = Get-SSPICredential -Package Negotiate
        Set-KdcProxy -Credential $cred -Server proxy -ForceProxy
    }

    It "Sets proxy with WhatIf" {
        $cred = Get-SSPICredential -Package Kerberos
        Set-KdcProxy -Credential $cred -Server proxy -WhatIf
        # No way of really testing WhatIf wasn't applied
    }

    It "Fails to set proxy with invalid package" {
        $cred = Get-SSPICredential -Package NTLM

        $out = Set-KdcProxy -Credential $cred -Server proxy -ErrorAction SilentlyContinue -ErrorVariable err -WhatIf
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 0

        $out = Set-KdcProxy -Credential $cred -Server proxy -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*The handle specified is invalid*"
    }
}
