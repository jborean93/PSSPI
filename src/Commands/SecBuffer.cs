using System;
using System.Management.Automation;

namespace PSSPI.Commands;

[Cmdlet(
    VerbsCommon.New, "SecBuffer"
)]
[OutputType(typeof(SecurityBuffer))]
public class NewSecBuffer : PSCmdlet
{
    [Parameter(
        Mandatory = true
    )]
    public SecBufferType Type { get; set; }

    [Parameter()]
    public SecBufferFlags Flags { get; set; } = SecBufferFlags.NONE;

    [Parameter()]
    [AllowNull()]
    public byte[]? Data { get; set; }

    protected override void EndProcessing()
    {
        WriteObject(new SecurityBuffer(Type, Flags, Data));
    }
}


[Cmdlet(
    VerbsCommon.New, "ChannelBindingBuffer"
)]
[OutputType(typeof(ChannelBindingBuffer))]
public class NewChannelBindingBuffer : PSCmdlet
{
    [Parameter()]
    public int InitiatorAddrType { get; set; } = 0;

    [Parameter()]
    [AllowEmptyCollection()]
    public byte[] Initiator { get; set; } = Array.Empty<byte>();

    [Parameter()]
    public int AcceptorAddrType { get; set; } = 0;

    [Parameter()]
    [AllowEmptyCollection()]
    public byte[] Acceptor { get; set; } = Array.Empty<byte>();

    [Parameter()]
    [AllowEmptyCollection()]
    public byte[] ApplicationData { get; set; } = Array.Empty<byte>();

    protected override void EndProcessing()
    {
        WriteObject(new ChannelBindingBuffer()
        {
            InitiatorAddrType = InitiatorAddrType,
            Initiator = Initiator,
            AcceptorAddrType = AcceptorAddrType,
            Acceptor = Acceptor,
            ApplicationData = ApplicationData,
        });
    }
}
