using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.New, "SecContext"
)]
[OutputType(typeof(SecurityContext))]
public class NewSecContext : PSCmdlet
{
    [Parameter()]
    [AllowNull()]
    public Credential? Credential { get; set; }

    protected override void EndProcessing()
    {
        WriteObject(new SecurityContext(Credential));
    }
}


[Cmdlet(
    VerbsCommon.Step, "AcceptSecContext"
)]
[OutputType(typeof(AcceptResult))]
public class AcceptInitSecContext : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNull()]
    public SecurityContext Context { get; set; } = null!;

    [Parameter()]
    public AcceptorContextRequestFlags ContextReq { get; set; } = AcceptorContextRequestFlags.NONE;

    [Parameter()]
    public TargetDataRep TargetDataRep { get; set; } = TargetDataRep.SECURITY_NATIVE_DREP;

    [Parameter()]
    [AllowEmptyCollection()]
    [ArgumentCompleter(typeof(SecBufferCompletor))]
    [SecBufferTransformer()]
    public ISecBuffer[] InputBuffer { get; set; } = Array.Empty<ISecBuffer>();

    [Parameter()]
    [AllowEmptyCollection()]
    [ArgumentCompleter(typeof(SecBufferCompletor))]
    [SecBufferTransformer()]
    public ISecBuffer[] OutputBuffer { get; set; } = Array.Empty<ISecBuffer>();

    protected override void EndProcessing()
    {
        List<SafeSecBuffer> safeInput = InputBuffer.Select((b) => b.GetBuffer()).ToList();
        List<SafeSecBuffer> safeOutput = OutputBuffer.Select((b) => b.GetBuffer()).ToList();
        try
        {
            ReadOnlySpan<Helpers.SecBuffer> input = new(safeInput.Select((b) => (Helpers.SecBuffer)b).ToArray());
            ReadOnlySpan<Helpers.SecBuffer> output = new(safeOutput.Select((b) => (Helpers.SecBuffer)b).ToArray());

            int res;
            AcceptorContextReturnFlags contextAttr;
            try
            {
                res = SSPI.AcceptSecurityContext(
                    Context,
                    ContextReq,
                    TargetDataRep,
                    input,
                    output,
                    out contextAttr);
            }
            catch (SspiException e)
            {
                WriteError(new ErrorRecord(e, "AuthenticationFailure", ErrorCategory.NotSpecified, null));
                return;
            }

            bool allocateMem = (contextAttr & AcceptorContextReturnFlags.ASC_RET_ALLOCATED_MEMORY) != 0;
            try
            {
                SecurityBuffer[] parsedOutput;
                if (allocateMem)
                {
                    parsedOutput = output.ToArray()
                        .Select((b) => new SecurityBuffer(b))
                        .ToArray();
                }
                else
                {
                    // Ensure the output length is updated
                    for (int i = 0; i < safeOutput.Count; i++)
                    {
                        safeOutput[i].Length = (int)output[i].cbBuffer;
                    }

                    parsedOutput = safeOutput.ToArray()
                        .Select((b) => new SecurityBuffer(b))
                        .ToArray();
                }

                WriteObject(new AcceptResult(res, parsedOutput, contextAttr));
            }
            finally
            {
                if (allocateMem)
                {
                    foreach (Helpers.SecBuffer buffer in output)
                    {
                        SSPI.FreeContextBuffer(buffer.pvBuffer);
                    }
                }
            }
        }
        finally
        {
            foreach (SafeSecBuffer buffer in safeInput)
            {
                buffer.Dispose();
            }
            foreach (SafeSecBuffer buffer in safeOutput)
            {
                buffer.Dispose();
            }
        }
    }
}

[Cmdlet(
    VerbsCommon.Step, "InitSecContext"
)]
[OutputType(typeof(InitializeResult))]
public class StepInitSecContext : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNull()]
    public SecurityContext Context { get; set; } = null!;

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    [ValidateNotNullOrEmpty()]
    public string Target { get; set; } = "";

    [Parameter()]
    public InitiatorContextRequestFlags ContextReq { get; set; } = InitiatorContextRequestFlags.NONE;

    [Parameter()]
    public TargetDataRep TargetDataRep { get; set; } = TargetDataRep.SECURITY_NATIVE_DREP;

    [Parameter()]
    [AllowEmptyCollection()]
    [ArgumentCompleter(typeof(SecBufferCompletor))]
    [SecBufferTransformer()]
    public ISecBuffer[] InputBuffer { get; set; } = Array.Empty<ISecBuffer>();

    [Parameter()]
    [AllowEmptyCollection()]
    [ArgumentCompleter(typeof(SecBufferCompletor))]
    [SecBufferTransformer()]
    public ISecBuffer[] OutputBuffer { get; set; } = Array.Empty<ISecBuffer>();

    protected override void EndProcessing()
    {
        List<SafeSecBuffer> safeInput = InputBuffer.Select((b) => b.GetBuffer()).ToList();
        List<SafeSecBuffer> safeOutput = OutputBuffer.Select((b) => b.GetBuffer()).ToList();
        try
        {
            ReadOnlySpan<Helpers.SecBuffer> input = new(safeInput.Select((b) => (Helpers.SecBuffer)b).ToArray());
            ReadOnlySpan<Helpers.SecBuffer> output = new(safeOutput.Select((b) => (Helpers.SecBuffer)b).ToArray());

            int res;
            InitiatorContextReturnFlags contextAttr;
            try
            {
                res = SSPI.InitializeSecurityContext(
                    Context,
                    Target,
                    ContextReq,
                    TargetDataRep,
                    input,
                    output,
                    out contextAttr);
            }
            catch (SspiException e)
            {
                WriteError(new ErrorRecord(e, "AuthenticationFailure", ErrorCategory.NotSpecified, null));
                return;
            }

            bool allocateMem = (contextAttr & InitiatorContextReturnFlags.ISC_RET_ALLOCATED_MEMORY) != 0;
            try
            {
                SecurityBuffer[] parsedOutput;
                if (allocateMem)
                {
                    parsedOutput = output.ToArray()
                        .Select((b) => new SecurityBuffer(b))
                        .ToArray();
                }
                else
                {
                    // Ensure the output length is updated
                    for (int i = 0; i < safeOutput.Count; i++)
                    {
                        safeOutput[i].Length = (int)output[i].cbBuffer;
                    }

                    parsedOutput = safeOutput.ToArray()
                        .Select((b) => new SecurityBuffer(b))
                        .ToArray();
                }

                WriteObject(new InitializeResult(res, parsedOutput, contextAttr));
            }
            finally
            {
                if (allocateMem)
                {
                    foreach (Helpers.SecBuffer buffer in output)
                    {
                        SSPI.FreeContextBuffer(buffer.pvBuffer);
                    }
                }
            }
        }
        finally
        {
            foreach (SafeSecBuffer buffer in safeInput)
            {
                buffer.Dispose();
            }
            foreach (SafeSecBuffer buffer in safeOutput)
            {
                buffer.Dispose();
            }
        }
    }
}
