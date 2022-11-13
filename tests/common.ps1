$ErrorActionPreference = 'Stop'

$moduleName = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [IO.Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath -ErrorAction Stop
}

Function Global:Complete {
    [OutputType([System.Management.Automation.CompletionResult])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]
        $Expression
    )

    [System.Management.Automation.CommandCompletion]::CompleteInput(
        $Expression,
        $Expression.Length,
        $null).CompletionMatches
}

Function Global:Complete-TlsAuth {
    [OutputType([PSSPI.SecurityContext])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSSPI.Credential]$Client,

        [Parameter(Mandatory)]
        [PSSPI.Credential]$Server,

        [Parameter(Mandatory)]
        [string]$Target
    )

    $cCtx = New-SecContext -Credential $Client
    $sCtx = New-SecContext -Credential $Server

    $sRes = $null
    while ($true) {
        $stepParams = @{
            Context    = $cCtx
            Target     = $Target
            ContextReq = 'ISC_REQ_SEQUENCE_DETECT, ISC_REQ_REPLAY_DETECT, ISC_REQ_CONFIDENTIALITY, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_STREAM'
        }

        if ($sRes) {
            $stepParams.InputBuffer = @(
                $sRes.Buffers[0]
                'SECBUFFER_EMPTY'
            )
            $stepParams.OutputBuffer = @(
                'SECBUFFER_TOKEN',
                'SECBUFFER_ALERT',
                'SECBUFFER_EMPTY'
            )
        }
        else {
            $stepParams.OutputBuffer = 'SECBUFFER_EMPTY'
        }

        $cRes = Step-InitSecContext @stepParams
        if ($cRes.Buffers[0].Length -eq 0) {
            break
        }

        $stepParams = @{
            Context      = $sCtx
            ContextReq   = 'ASC_REQ_ALLOCATE_MEMORY'
            InputBuffer  = @(
                $cRes.Buffers[0]
                'SECBUFFER_EMPTY'
            )
            OutputBuffer = 'SECBUFFER_TOKEN'
        }

        $sRes = Step-AcceptSecContext @stepParams
        if ($sRes.Buffers[0].Length -eq 0) {
            break
        }
    }

    if ($cRes.Result -ne [PSSPI.SecContextStatus]::Ok) {
        throw "Client context is not complete and there's no more server data: $($cRes.Result)"
    }
    if ($sRes.Result -ne [PSSPI.SecContextStatus]::Ok) {
        throw "Server context is not complete and there's no more client data: $($sRes.Result)"
    }

    $cCtx, $sCtx
}
