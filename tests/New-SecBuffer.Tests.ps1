. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "New-SecBuffer" {
    It "Creates sec buffer with byte data" {
        $buffer = New-SecBuffer -Type SECBUFFER_TOKEN -Data ([byte[]]@(1, 2, 3, 4))
        $buffer.Flags | Should -Be ([PSSPI.SecBufferFlags]::NONE)
        $buffer.Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $buffer.Data | Should -Be ([byte[]]@(1, 2, 3, 4))
    }

    It "Creates sec buffer without byte data" {
        $buffer = New-SecBuffer -Type SECBUFFER_TOKEN
        $buffer.Flags | Should -Be ([PSSPI.SecBufferFlags]::NONE)
        $buffer.Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $buffer.Data | Should -Be $null
    }

    It "Creates sec buffer with null byte data" {
        $buffer = New-SecBuffer -Type SECBUFFER_TOKEN -Data $null
        $buffer.Flags | Should -Be ([PSSPI.SecBufferFlags]::NONE)
        $buffer.Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $buffer.Data | Should -Be $null
    }

    It "Creates sec buffer with empty byte data" {
        $buffer = New-SecBuffer -Type SECBUFFER_TOKEN -Data ([byte[]]@())
        $buffer.Flags | Should -Be ([PSSPI.SecBufferFlags]::NONE)
        $buffer.Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $buffer.Data | Should -Be ([byte[]]@())
    }

    It "Creates sec buffer with flags" {
        $buffer = New-SecBuffer -Type SECBUFFER_PADDING -Data ([byte[]]@(1, 2, 3, 4)) -Flags SECBUFFER_READONLY
        $buffer.Flags | Should -Be ([PSSPI.SecBufferFlags]::SECBUFFER_READONLY)
        $buffer.Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_PADDING)
        $buffer.Data | Should -Be ([byte[]]@(1, 2, 3, 4))
    }
}
