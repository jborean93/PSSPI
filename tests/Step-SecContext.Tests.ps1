. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Step-*SecContext" {
    BeforeAll {
        $localSpn = "host/$([System.Net.Dns]::GetHostByName($env:computerName).HostName)"
    }

    It "Steps through NTLM exchange" {
        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer SECBUFFER_TOKEN -ContextReq ISC_REQ_ALLOCATE_MEMORY
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_ALLOCATED_MEMORY)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq ASC_REQ_ALLOCATE_MEMORY
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::ASC_RET_ALLOCATED_MEMORY)

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq ISC_REQ_ALLOCATE_MEMORY
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_ALLOCATED_MEMORY)

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq ASC_REQ_ALLOCATE_MEMORY
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Data | Should -Be $null
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)

        # NTLM has a fixed signature/header size of 16 and no block size
        $cSizes = Get-SecContextSizes -Context $cCtx
        $cSizes | Should -BeOfType ([PSSPI.Commands.ContextSizes])
        $cSizes.MaxToken | Should -BeOfType ([System.UInt32])
        $cSizes.MaxSignature | Should -Be 16
        $cSizes.BlockSize | Should -Be 0
        $cSizes.SecurityTrailer | Should -Be 16

        $sSizes = Get-SecContextSizes -Context $sCtx
        $sSizes | Should -BeOfType ([PSSPI.Commands.ContextSizes])
        $sSizes.MaxToken | Should -BeOfType ([System.UInt32])
        $sSizes.MaxSignature | Should -Be 16
        $sSizes.BlockSize | Should -Be 0
        $sSizes.SecurityTrailer | Should -Be 16
    }

    It "Steps through NTLM exchange with null transform buffer" {
        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $null -ContextReq ISC_REQ_ALLOCATE_MEMORY
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_ALLOCATED_MEMORY)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer $null -ContextReq ASC_REQ_ALLOCATE_MEMORY
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::ASC_RET_ALLOCATED_MEMORY)

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer $null -ContextReq ISC_REQ_ALLOCATE_MEMORY
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_ALLOCATED_MEMORY)

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer $null -ContextReq ASC_REQ_ALLOCATE_MEMORY
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Data | Should -Be $null
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)
    }

    It "Steps through exchange with pre-allocated memory" {
        $buffer = [byte[]]::new(4096)
        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer $buffer
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer $buffer
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer $buffer
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Length | Should -Be 0
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)
    }

    It "Steps through exchange with invalid credential" {
        $buffer = [byte[]]::new(4096)
        $cred = [PSCredential]::new('invalid', (ConvertTo-SecureString -AsPlainText -Force -String 'invalid'))

        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM -Credential $cred
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer $buffer
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer $buffer
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $out = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*The logon attempt failed*"
    }

    It "Steps through exchange with channel binding" {
        $buffer = [byte[]]::new(4096)
        $cb = New-ChannelBindingBuffer -ApplicationData ([Text.Encoding]::ASCII.GetBytes("test"))

        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $cb -OutputBuffer $buffer
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cb, $cRes1.Buffers -OutputBuffer $buffer
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $cb, $sRes1.Buffers -OutputBuffer $buffer
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::NONE)

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cb, $cRes2.Buffers -OutputBuffer $buffer
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Length | Should -Be 0
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]::NONE)
    }

    It "Steps through exchange with negotiate restricted credential AllowPackage" {
        $buffer = [byte[]]::new(4096)
        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package Negotiate -AllowPackage NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_INTERMEDIATE_RETURN)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer $buffer
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]'ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT')

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer $buffer
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]'ISC_RET_MUTUAL_AUTH, ISC_RET_REPLAY_DETECT, ISC_RET_SEQUENCE_DETECT, ISC_RET_INTEGRITY')

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer $buffer
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Length | Should -Be 0
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]'ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT, ASC_RET_INTEGRITY')
    }

    It "Steps through exchange with negotiate restricted credential RejectPackage" {
        $buffer = [byte[]]::new(4096)
        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        # Using Negotiate this way forces NTLM to be wrapped in SPNEGO causing an extra token
        # to be generated by the server
        $cCred = Get-SSPICredential -Package Negotiate -RejectPackage Kerberos
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]::ISC_RET_INTERMEDIATE_RETURN)

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer $buffer
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]'ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT')

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer $buffer
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]'ISC_RET_MUTUAL_AUTH, ISC_RET_REPLAY_DETECT, ISC_RET_SEQUENCE_DETECT, ISC_RET_INTEGRITY')

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer $buffer
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]'ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT, ASC_RET_INTEGRITY')

        $cRes3 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes2.Buffers -OutputBuffer $buffer
        $cRes3.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes3.Buffers.Count | Should -Be 1
        $cRes3.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes3.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]'ISC_RET_MUTUAL_AUTH, ISC_RET_REPLAY_DETECT, ISC_RET_SEQUENCE_DETECT, ISC_RET_INTEGRITY')
    }

    It "Fails to use Negotiate when no available sub packages are allowed" {
        $buffer = [byte[]]::new(4096)
        $cCred = Get-SSPICredential -Package Negotiate -AllowPackage NegoExtender
        $cCtx = New-SecContext -Credential $cCred

        $out = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*No credentials are available in the security package*"
    }

    It "Fails to use Negotiate when all available sub packages are rejected" {
        $buffer = [byte[]]::new(4096)
        $cCred = Get-SSPICredential -Package Negotiate -RejectPackage NTLM, Kerberos
        $cCtx = New-SecContext -Credential $cCred

        $out = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer $buffer -ErrorAction SilentlyContinue -ErrorVariable err
        $out | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "*No credentials are available in the security package*"
    }

    It "Fails to transform invalid type to secbuffer" {
        $cCred = Get-SSPICredential -Package Negotiate
        $cCtx = New-SecContext -Credential $cCred

        {
            Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer @{}
        } | Should -Throw "*Could not convert input 'System.Collections.Hashtable' to a valid SecurityBuffer object*"
    }

    It "Steps through exchange with custom flags" {
        $iscReq = "ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_INTEGRITY"
        $ascReq = "ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONFIDENTIALITY, ASC_REQ_INTEGRITY"

        $sCred = Get-SSPICredential -Package Negotiate -CredentialUse SECPKG_CRED_INBOUND
        $sCtx = New-SecContext -Credential $sCred

        $cCred = Get-SSPICredential -Package NTLM
        $cCtx = New-SecContext -Credential $cCred

        $cRes1 = Step-InitSecContext -Context $cCtx -Target $localSpn -OutputBuffer SECBUFFER_TOKEN -ContextReq $iscReq
        $cRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $cRes1.Buffers.Count | Should -Be 1
        $cRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes1.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]"ISC_RET_ALLOCATED_MEMORY, ISC_RET_CONFIDENTIALITY, ISC_RET_INTEGRITY")

        $sRes1 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes1.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq $ascReq
        $sRes1.Result | Should -Be ([PSSPI.SecContextStatus]::ContinueNeeded)
        $sRes1.Buffers.Count | Should -Be 1
        $sRes1.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes1.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]"ASC_RET_ALLOCATED_MEMORY, ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT, ASC_RET_CONFIDENTIALITY, ASC_RET_INTEGRITY")

        $cRes2 = Step-InitSecContext -Context $cCtx -Target $localSpn -InputBuffer $sRes1.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq $iscReq
        $cRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $cRes2.Buffers.Count | Should -Be 1
        $cRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $cRes2.Flags | Should -Be ([PSSPI.InitiatorContextReturnFlags]"ISC_RET_ALLOCATED_MEMORY, ISC_RET_REPLAY_DETECT, ISC_RET_SEQUENCE_DETECT, ISC_RET_CONFIDENTIALITY, ISC_RET_INTEGRITY")

        $sRes2 = Step-AcceptSecContext -Context $sCtx -InputBuffer $cRes2.Buffers -OutputBuffer SECBUFFER_TOKEN -ContextReq $ascReq
        $sRes2.Result | Should -Be ([PSSPI.SecContextStatus]::Ok)
        $sRes2.Buffers.Count | Should -Be 1
        $sRes2.Buffers[0].Type | Should -Be ([PSSPI.SecBufferType]::SECBUFFER_TOKEN)
        $sRes2.Buffers[0].Data | Should -Be $null
        $sRes2.Flags | Should -Be ([PSSPI.AcceptorContextReturnFlags]"ASC_RET_REPLAY_DETECT, ASC_RET_SEQUENCE_DETECT, ASC_RET_CONFIDENTIALITY, ASC_RET_INTEGRITY")
    }

    It "Completes sec buffer type" {
        $actual = Complete 'Step-InitSecContext -InputBuffer '
        $actual.Count | Should -Be 24
        $actual | ForEach-Object {
            $_.CompletionText | Should -BeIn @(
                "SECBUFFER_EMPTY"
                "SECBUFFER_DATA"
                "SECBUFFER_TOKEN"
                "SECBUFFER_PKG_PARAMS"
                "SECBUFFER_MISSING"
                "SECBUFFER_EXTRA"
                "SECBUFFER_STREAM_TRAILER"
                "SECBUFFER_STREAM_HEADER"
                "SECBUFFER_NEGOTIATION_INFO"
                "SECBUFFER_PADDING"
                "SECBUFFER_STREAM"
                "SECBUFFER_MECHLIST"
                "SECBUFFER_MECHLIST_SIGNATURE"
                "SECBUFFER_TARGET"
                "SECBUFFER_CHANNEL_BINDINGS"
                "SECBUFFER_CHANGE_PASS_RESPONSE"
                "SECBUFFER_TARGET_HOST"
                "SECBUFFER_ALERT"
                "SECBUFFER_APPLICATION_PROTOCOLS"
                "SECBUFFER_SRTP_PROTECTION_PROFILES"
                "SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER"
                "SECBUFFER_TOKEN_BINDING"
                "SECBUFFER_PRESHARED_KEY"
                "SECBUFFER_PRESHARED_KEY_IDENTITY"
            )
        }
    }

    It "Completes sec buffer type with partial" {
        $actual = Complete 'Step-InitSecContext -InputBuffer secBufFer_s'
        $actual.Count | Should -Be 5
        $actual | ForEach-Object {
            $_.CompletionText | Should -BeIn @(
                "SECBUFFER_STREAM_TRAILER"
                "SECBUFFER_STREAM_HEADER"
                "SECBUFFER_STREAM"
                "SECBUFFER_SRTP_PROTECTION_PROFILES"
                "SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER"
            )
        }
    }
}
