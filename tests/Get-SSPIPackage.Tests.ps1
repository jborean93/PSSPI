. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-SSPIPackage" {
    BeforeAll {
        $allPackages = Get-SSPIPackage
    }

    It "Gets all installed packages" {
        $packages = Get-SSPIPackage
        foreach ($actual in $packages) {
            $actual | Should -BeOfType ([PSSPI.SecPackageInfo])
            $actual.Name | Should -BeOfType ([string])
            $actual.Comment | Should -BeOfType ([string])
        }
    }

    It "Gets individual package" {
        $actual = Get-SSPIPackage -Name $allPackages[0].Name
        $actual | Should -BeOfType ([PSSPI.SecPackageInfo])
        $actual.Name | Should -BeOfType ([string])
        $actual.Comment | Should -BeOfType ([string])
    }

    It "Gets individual package by pipeline value" {
        $actual = $allPackages[0].Name | Get-SSPIPackage
        $actual | Should -BeOfType ([PSSPI.SecPackageInfo])
        $actual.Name | Should -BeOfType ([string])
        $actual.Comment | Should -BeOfType ([string])
    }

    It "Gets individual package by pipeline name" {
        $actual = $allPackages[0] | Get-SSPIPackage
        $actual | Should -BeOfType ([PSSPI.SecPackageInfo])
        $actual.Name | Should -BeOfType ([string])
        $actual.Comment | Should -BeOfType ([string])
    }

    It "Gets multiple packages" {
        $packages = Get-SSPIPackage -Name $allPackages[0].Name, $allPackages[1].Name
        foreach ($actual in $packages) {
            $actual | Should -BeOfType ([PSSPI.SecPackageInfo])
            $actual.Name | Should -BeOfType ([string])
            $actual.Comment | Should -BeOfType ([string])
        }
    }

    It "Fails with invalid package" {
        $out = Get-SSPIPackage -Name invalid -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*The requested security package does not exist*"
    }

    It "Completes with no package name" {
        $actual = Complete 'Get-SSPIPackage -Name '
        $actual.Count | Should -Be $allPackages.Count
    }

    It "Completes with partial package name" {
        $actual = Complete 'Get-SSPIPackage -Name Negoti'
        $actual.Count | Should -Be 1
        $actual.CompletionText | Should -Be "Negotiate"
        $actual.ListItemText | Should -Be "Negotiate"
        $actual.ToolTip | Should -Be "Microsoft Package Negotiator"
    }
}
