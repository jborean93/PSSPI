using System;
using System.Runtime.InteropServices;

namespace PSSPI;

public interface ISecBuffer
{
    internal SafeSecBuffer GetBuffer();
}

internal class SafeSecBuffer : IDisposable
{
    public int Type { get; }
    public int Length { get; set; }
    public byte[]? Data { get; }

    internal GCHandle? Handle { get; }

    internal SafeSecBuffer(int type, int length, byte[]? data)
    {
        Type = type;
        Length = length;
        Data = data;
        if (data != null)
        {
            Handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        }
    }

    public static explicit operator Helpers.SecBuffer(SafeSecBuffer buffer)
    {
        return new()
        {
            cbBuffer = (uint)(buffer.Length),
            BufferType = (uint)buffer.Type,
            pvBuffer = buffer.Handle?.AddrOfPinnedObject() ?? IntPtr.Zero,
        };
    }

    public void Dispose()
    {
        Handle?.Free();
    }
    ~SafeSecBuffer() { Dispose(); }
}

public class SecurityBuffer : ISecBuffer
{
    private int? _length;

    public SecBufferType Type { get; set; }
    public SecBufferFlags Flags { get; set; }
    public int Length => _length ?? Data?.Length ?? 0;
    public byte[]? Data { get; set; }

    public SecurityBuffer(SecBufferType type, SecBufferFlags flags, byte[]? buffer)
    {
        Type = type;
        Flags = flags;
        Data = buffer;
    }

    internal SecurityBuffer(Helpers.SecBuffer buffer)
    {
        Data = new byte[buffer.cbBuffer];
        Marshal.Copy(buffer.pvBuffer, Data, 0, Data.Length);
        Type = (SecBufferType)(buffer.BufferType & ~0xF0000000);
        Flags = (SecBufferFlags)(buffer.BufferType & 0xF0000000);
    }

    internal SecurityBuffer(SafeSecBuffer buffer)
    {
        Data = buffer.Data;
        Type = (SecBufferType)(buffer.Type & ~0xF0000000);
        Flags = (SecBufferFlags)(buffer.Type & 0xF0000000);
        _length = buffer.Length;
    }

    SafeSecBuffer ISecBuffer.GetBuffer() => new SafeSecBuffer((int)Type | (int)Flags, Length, Data);
}

public class ChannelBindingBuffer : ISecBuffer
{
    public int InitiatorAddrType { get; set; } = 0;
    public byte[] Initiator { get; set; } = Array.Empty<byte>();
    public int AcceptorAddrType { get; set; } = 0;
    public byte[] Acceptor { get; set; } = Array.Empty<byte>();
    public byte[] ApplicationData { get; set; } = Array.Empty<byte>();

    SafeSecBuffer ISecBuffer.GetBuffer()
    {
        int structOffset = Marshal.SizeOf<Helpers.SEC_CHANNEL_BINDINGS>();
        int binaryLength = Initiator.Length + Acceptor.Length + ApplicationData.Length;
        byte[] bindingData = new byte[structOffset + binaryLength];
        unsafe
        {
            fixed (byte* bindingPtr = bindingData)
            {
                Helpers.SEC_CHANNEL_BINDINGS* bindingStruct = (Helpers.SEC_CHANNEL_BINDINGS*)bindingPtr;

                bindingStruct->dwInitiatorAddrType = (UInt32)InitiatorAddrType;
                if (Initiator.Length > 0)
                {
                    bindingStruct->cbInitiatorLength = (UInt32)Initiator.Length;
                    bindingStruct->dwInitiatorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(Initiator, 0, bindingData, structOffset, Initiator.Length);
                    structOffset += Initiator.Length;
                }

                bindingStruct->dwAcceptorAddrType = (UInt32)AcceptorAddrType;
                if (Acceptor.Length > 0)
                {
                    bindingStruct->cbAcceptorLength = (UInt32)Acceptor.Length;
                    bindingStruct->dwAcceptorOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(Acceptor, 0, bindingData, structOffset, Acceptor.Length);
                    structOffset += Acceptor.Length;
                }

                if (ApplicationData != null)
                {
                    bindingStruct->cbApplicationDataLength = (UInt32)ApplicationData.Length;
                    bindingStruct->dwApplicationDataOffset = (UInt32)structOffset;
                    Buffer.BlockCopy(ApplicationData, 0, bindingData, structOffset, ApplicationData.Length);
                }
            }
        }

        return new SafeSecBuffer((int)SecBufferType.SECBUFFER_CHANNEL_BINDINGS, bindingData.Length, bindingData);
    }
}

public enum SecBufferFlags : uint
{
    NONE = 0x00000000,
    SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000,
    SECBUFFER_RESERVED = 0x60000000,
    SECBUFFER_READONLY = 0x80000000,
}

public enum SecBufferType : uint
{
    SECBUFFER_EMPTY = 0,
    SECBUFFER_DATA = 1,
    SECBUFFER_TOKEN = 2,
    SECBUFFER_PKG_PARAMS = 3,
    SECBUFFER_MISSING = 4,
    SECBUFFER_EXTRA = 5,
    SECBUFFER_STREAM_TRAILER = 6,
    SECBUFFER_STREAM_HEADER = 7,
    SECBUFFER_NEGOTIATION_INFO = 8,
    SECBUFFER_PADDING = 9,
    SECBUFFER_STREAM = 10,
    SECBUFFER_MECHLIST = 11,
    SECBUFFER_MECHLIST_SIGNATURE = 12,
    SECBUFFER_TARGET = 13,
    SECBUFFER_CHANNEL_BINDINGS = 14,
    SECBUFFER_CHANGE_PASS_RESPONSE = 15,
    SECBUFFER_TARGET_HOST = 16,
    SECBUFFER_ALERT = 17,
    SECBUFFER_APPLICATION_PROTOCOLS = 18,
    SECBUFFER_SRTP_PROTECTION_PROFILES = 19,
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20,
    SECBUFFER_TOKEN_BINDING = 21,
    SECBUFFER_PRESHARED_KEY = 22,
    SECBUFFER_PRESHARED_KEY_IDENTITY = 23,
}
