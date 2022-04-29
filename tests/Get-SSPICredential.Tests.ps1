. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-SSPICredential" {
    It "Gets outbound credential with default context" {
        $cred = Get-SSPICredential -Package Negotiate
        $cred | Should -BeOfType ([PSSPI.Credential])
        $cred.SafeHandle | Should -BeNullOrEmpty -Not
    }

    It "Gets inbound credential with default context" {
        $cred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $cred | Should -BeOfType ([PSSPI.Credential])
        $cred.SafeHandle | Should -BeNullOrEmpty -Not
    }

    It "Gets credential with package type" {
        $package = Get-SSPIPackage -Name NTLM
        $cred = Get-SSPICredential -Package $package
        $cred | Should -BeOfType ([PSSPI.Credential])
        $cred.SafeHandle | Should -BeNullOrEmpty -Not
    }

    It "Gets credential with explicit credentials - <UserName>" -TestCases @(
        @{UserName = 'username'},
        @{UserName = 'DOMAIN\username'},
        @{UserName = 'username@DOMAIN.COM'}
    ) {
        param ($UserName)
        $psCred = [PSCredential]::new($UserName, (ConvertTo-SecureString -AsPlainText -Force -String 'Password123!'))
        $cred = Get-SSPICredential -Package Negotiate -Credential $psCred
        $cred | Should -BeOfType ([PSSPI.Credential])
        $cred.SafeHandle | Should -BeNullOrEmpty -Not
    }

    It "Gets credential with principal" {
        $cred = Get-SSPICredential -Package NTLM -Principal test
        $cred | Should -BeOfType ([PSSPI.Credential])
        $cred.SafeHandle | Should -BeNullOrEmpty -Not
    }

    It "Fails to get credential with invalid package" {
        $out = Get-SSPICredential -Package invalid -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*The requested security package does not exist*"
    }

    It "Completes with partial package name" {
        $actual = Complete 'Get-SSPICredential -Package Negoti'
        $actual.Count | Should -Be 1
        $actual.CompletionText | Should -Be "Negotiate"
        $actual.ListItemText | Should -Be "Negotiate"
        $actual.ToolTip | Should -Be "Microsoft Package Negotiator"
    }
}
