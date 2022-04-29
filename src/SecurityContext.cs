using System;

namespace PSSPI;

public class SecurityContext
{
    /// <summary>Credential to use with the SSPI context.</summary>
    public Credential? Credential { get; internal set; }

    /// <summary>The handle to the SSPI security context.</summary>
    public SafeSspiContextHandle SafeHandle { get; internal set; } = SafeSspiContextHandle.NULL_CONTEXT;

    /// <summary>The number of ticks (100s of nanoseconds) since 1601-01-01 until the context expires.</summary>
    public UInt64 Expiry { get; internal set; } = 0;

    internal SecurityContext(Credential? credential)
    {
        Credential = credential;
    }
}

public class AcceptResult
{
    public SecContextStatus Result { get; internal set; }
    public SecurityBuffer[] Buffers { get; internal set; } = Array.Empty<SecurityBuffer>();
    public AcceptorContextReturnFlags Flags { get; internal set; }

    internal AcceptResult(Int32 result, SecurityBuffer[] buffers, AcceptorContextReturnFlags flags)
    {
        Result = result switch
        {
            SSPI.SEC_E_OK => SecContextStatus.Ok,
            SSPI.SEC_I_CONTINUE_NEEDED => SecContextStatus.ContinueNeeded,
            SSPI.SEC_I_COMPLETE_NEEDED => SecContextStatus.CompleteNeeded,
            SSPI.SEC_I_COMPLETE_AND_CONTINUE => SecContextStatus.CompleteAndContinue,
            _ => SecContextStatus.Unknown,
        };
        Buffers = buffers;
        Flags = flags;
    }
}

public class InitializeResult
{
    public SecContextStatus Result { get; internal set; }
    public SecurityBuffer[] Buffers { get; internal set; } = Array.Empty<SecurityBuffer>();
    public InitiatorContextReturnFlags Flags { get; internal set; }

    internal InitializeResult(Int32 result, SecurityBuffer[] buffers, InitiatorContextReturnFlags flags)
    {
        Result = result switch
        {
            SSPI.SEC_E_OK => SecContextStatus.Ok,
            SSPI.SEC_I_CONTINUE_NEEDED => SecContextStatus.ContinueNeeded,
            SSPI.SEC_I_COMPLETE_NEEDED => SecContextStatus.CompleteNeeded,
            SSPI.SEC_I_COMPLETE_AND_CONTINUE => SecContextStatus.CompleteAndContinue,
            _ => SecContextStatus.Unknown,
        };
        Buffers = buffers;
        Flags = flags;
    }
}

public enum SecContextStatus
{
    /// <summary>
    /// The security context was successfully initialized. There is no need for another InitializeSecurityContext
    /// call. If the function returns an output token, that is, if the SECBUFFER_TOKEN in pOutput is of nonzero length,
    /// that token must be sent to the server.
    /// </summary>
    Ok,

    /// <summary>
    /// The client must call CompleteAuthToken and then pass the output to the server. The client then waits for a
    /// returned token and passes it, in another call, to InitializeSecurityContext.
    /// </summary>
    CompleteAndContinue,

    /// <summary>
    /// The client must finish building the message and then call the CompleteAuthToken function.
    /// </summary>
    CompleteNeeded,

    /// <summary>
    /// The client must send the output token to the server and wait for a return token. The returned token is then
    /// passed in another call to InitializeSecurityContext. The output token can be empty.
    /// </summary>
    ContinueNeeded,

    /// <summary>
    /// Unknown status from the server.
    /// </summary>
    Unknown,
}
