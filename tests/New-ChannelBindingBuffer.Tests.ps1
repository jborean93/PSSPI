. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "ChannelBindingBuffer" {
    It "Creates channel binding buffer with no data" {
        $buffer = New-ChannelBindingBuffer
        $buffer | Should -BeOfType ([PSSPI.ChannelBindingBuffer])
        $buffer.InitiatorAddrType | Should -Be 0
        $buffer.Initiator | Should -BeNullOrEmpty
        $buffer.AcceptorAddrType | Should -Be 0
        $buffer.Acceptor | Should -BeNullOrEmpty
        $buffer.ApplicationData | Should -BeNullOrEmpty
    }

    It "Creates channel binding buffer with application data" {
        $buffer = New-ChannelBindingBuffer -ApplicationData 1, 2, 3, 4
        $buffer | Should -BeOfType ([PSSPI.ChannelBindingBuffer])
        $buffer.InitiatorAddrType | Should -Be 0
        $buffer.Initiator | Should -BeNullOrEmpty
        $buffer.AcceptorAddrType | Should -Be 0
        $buffer.Acceptor | Should -BeNullOrEmpty
        $buffer.ApplicationData | Should -Be ([byte[]]@(1, 2, 3, 4))
    }
}
