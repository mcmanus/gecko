/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_SDTSession_h
#define mozilla_net_SDTSession_h

#include "ASpdySession.h"
#include "mozilla/Attributes.h"
#include "mozilla/UniquePtr.h"
#include "nsAHttpConnection.h"
#include "nsClassHashtable.h"
#include "nsDataHashtable.h"
#include "nsDeque.h"
#include "nsHashKeys.h"

#include "Http2Compression.h"

class nsISocketTransport;

namespace mozilla {
namespace net {

//class Http2PushedStream;
class SDTStream;
class nsHttpTransaction;

class SDTSession final : public ASpdySession
                        , public nsAHttpConnection
                        , public nsAHttpSegmentReader
                        , public nsAHttpSegmentWriter
{
  ~SDTSession();

public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSAHTTPTRANSACTION
  NS_DECL_NSAHTTPCONNECTION(mConnection)
  NS_DECL_NSAHTTPSEGMENTREADER
  NS_DECL_NSAHTTPSEGMENTWRITER

 SDTSession(nsISocketTransport *, uint32_t version);

  bool AddStream(nsAHttpTransaction *, int32_t,
                 bool, nsIInterfaceRequestor *) override;
  bool CanReuse() override { return !mShouldGoAway && !mClosed; }
  bool RoomForMoreStreams() override;
  uint32_t WireVersion() override;
  bool TestJoinConnection(const nsACString &hostname, int32_t port) override;
  bool JoinConnection(const nsACString &hostname, int32_t port) override;
  void ThrottleResponse(bool aThrottle) override;

  // When the connection is active this is called up to once every 1 second
  // return the interval (in seconds) that the connection next wants to
  // have this invoked. It might happen sooner depending on the needs of
  // other connections.
  uint32_t  ReadTimeoutTick(PRIntervalTime now) override;

  // Idle time represents time since "goodput".. e.g. a data or header frame
  PRIntervalTime IdleTime() override;

  // Registering with a newID of 0 means pick the next available odd ID
  uint32_t RegisterStreamID(SDTStream *, uint32_t aNewID = 0);

/*
  HTTP/2 framing

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Length (16)           |   Type (8)    |   Flags (8)   |
  +-+-------------+---------------+-------------------------------+
  |R|                 Stream Identifier (31)                      |
  +-+-------------------------------------------------------------+
  |                     Frame Data (0...)                       ...
  +---------------------------------------------------------------+
*/

  enum FrameType {
    FRAME_TYPE_HEADERS       = 0x1,
    FRAME_TYPE_PRIORITY      = 0x2,
    FRAME_TYPE_SETTINGS      = 0x4,
    FRAME_TYPE_PUSH_PROMISE  = 0x5,
    FRAME_TYPE_CONTINUATION  = 0x9,
    FRAME_TYPE_ALTSVC        = 0xA,
    FRAME_TYPE_LAST          = 0xB
  };

  // NO_ERROR is a macro defined on windows, so we'll name the HTTP2 goaway
  // code NO_ERROR to be NO_HTTP_ERROR
  enum errorType {
    NO_HTTP_ERROR = 0,
    PROTOCOL_ERROR = 1,
    INTERNAL_ERROR = 2,
    FLOW_CONTROL_ERROR = 3,
    SETTINGS_TIMEOUT_ERROR = 4,
    STREAM_CLOSED_ERROR = 5,
    FRAME_SIZE_ERROR = 6,
    REFUSED_STREAM_ERROR = 7,
    CANCEL_ERROR = 8,
    COMPRESSION_ERROR = 9,
    CONNECT_ERROR = 10,
    ENHANCE_YOUR_CALM = 11,
    INADEQUATE_SECURITY = 12,
    HTTP_1_1_REQUIRED = 13,
    UNASSIGNED = 31
  };

  // These are frame flags. If they, or other undefined flags, are
  // used on frames other than the comments indicate they MUST be ignored.
  const static uint8_t kFlag_END_HEADERS = 0x04; // headers, continuation
//  const static uint8_t kFlag_END_PUSH_PROMISE = 0x04; // push promise

  enum {
    SETTINGS_TYPE_HEADER_TABLE_SIZE = 1, // compression table size
    SETTINGS_TYPE_ENABLE_PUSH = 2,     // can be used to disable push
  };

  // This should be big enough to hold all of your control packets,
  // but if it needs to grow for huge headers it can do so dynamically.
  const static uint32_t kDefaultBufferSize = 2048;

  // kDefaultQueueSize must be >= other queue size constants
  const static uint32_t kDefaultQueueSize =  32768;
  const static uint32_t kQueueMinimumCleanup = 24576;
  const static uint32_t kQueueTailRoom    =  4096;
  const static uint32_t kQueueReserved    =  1024;

  const static uint32_t kMaxStreamID = 0x7800000;

  // This is a sentinel for a deleted stream. It is not a valid
  // 31 bit stream ID.
  const static uint32_t kDeadStreamID = 0xffffdead;

  // We limit frames to 2^14 bytes of length in order to preserve responsiveness
  // This is the smallest allowed value for SETTINGS_MAX_FRAME_SIZE
  const static uint32_t kMaxFrameData = 0x4000;

  const static uint8_t kFrameLengthBytes = 3;
  const static uint8_t kFrameStreamIDBytes = 4;
  const static uint8_t kFrameFlagBytes = 1;
  const static uint8_t kFrameTypeBytes = 1;
  const static uint8_t kFrameHeaderBytes = kFrameLengthBytes + kFrameFlagBytes +
    kFrameTypeBytes + kFrameStreamIDBytes;

  enum {
    kLeaderGroupID =     0x3,
    kOtherGroupID =       0x5,
    kBackgroundGroupID =  0x7,
    kSpeculativeGroupID = 0x9,
    kFollowerGroupID =    0xB
  };

  static nsresult RecvHeaders(SDTSession *);
  static nsresult RecvPriority(SDTSession *);
  static nsresult RecvSettings(SDTSession *);
  static nsresult RecvPushPromise(SDTSession *);
  static nsresult RecvContinuation(SDTSession *);
  static nsresult RecvAltSvc(SDTSession *);

  char       *EnsureOutputBuffer(uint32_t needed);

  template<typename charType>
  void CreateFrameHeader(charType dest, uint16_t frameLength,
                         uint8_t frameType, uint8_t frameFlags,
                         uint32_t streamID);

  // For writing the data stream to LOG4
  static void LogIO(SDTSession *, SDTStream *, const char *,
                    const char *, uint32_t);

  // overload of nsAHttpConnection
  void TransactionHasDataToWrite(nsAHttpTransaction *) override;
  void TransactionHasDataToRecv(nsAHttpTransaction *) override;

  // a similar version for SDTStream
  void TransactionHasDataToWrite(SDTStream *);

  // an overload of nsAHttpSegementReader
  virtual nsresult CommitToSegmentSize(uint32_t size, bool forceCommitment) override;
  nsresult BufferOutput(const char *, uint32_t, uint32_t *);
  void     FlushOutputQueue();
  uint32_t AmountOfOutputBuffered() { return mOutputQueueUsed - mOutputQueueSent; }

  bool TryToActivate(SDTStream *stream);
  void ConnectPushedStream(SDTStream *stream);

  nsresult ConfirmTLSProfile();
  static bool ALPNCallback(nsISupports *securityInfo);

  uint64_t Serial() { return mSerial; }

  void PrintDiagnostics (nsCString &log) override;

  // Streams need access to these
  uint32_t SendingChunkSize() { return mSendingChunkSize; }
  uint32_t PushAllowance() { return mPushAllowance; }
  Http2Compressor *Compressor() { return &mCompressor; }
  nsISocketTransport *SocketTransport() { return mSocketTransport; }

  void SendPing() override;
  bool MaybeReTunnel(nsAHttpTransaction *) override;
  bool UseH2Deps() { return mUseH2Deps; }

  // overload of nsAHttpTransaction
  nsresult ReadSegmentsAgain(nsAHttpSegmentReader *, uint32_t, uint32_t *, bool *) override final;
  nsresult WriteSegmentsAgain(nsAHttpSegmentWriter *, uint32_t , uint32_t *, bool *) override final;

  nsresult SetNextStreamToWrite(uint32_t aStreamId, int32_t *aStatus);

  void ResetStream();
  nsresult CloseStream(uint32_t aStreamId);
  bool StreamCanWrite(uint32_t aStreamId);
private:

  // These internal states do not correspond to the states of the HTTP/2 specification
  enum internalStateType {
    BUFFERING_OPENING_SETTINGS,
    BUFFERING_FRAME_HEADER,
    BUFFERING_CONTROL_FRAME,
    PROCESSING_COMPLETE_HEADERS,
    NOT_USING_NETWORK
  };

  static const uint8_t kMagicHello[24];

  nsresult    ResponseHeadersComplete();
  uint32_t    GetWriteQueueSize();
  void        ChangeDownstreamState(enum internalStateType);
  void        ResetDownstreamState();
  nsresult    ReadyToProcessDataFrame(enum internalStateType);
  nsresult    UncompressAndDiscard(bool);
  void        GeneratePriority(uint32_t, uint8_t);
  void        CleanupStream(SDTStream *, nsresult, errorType);
  void        CleanupStream(uint32_t, nsresult, errorType);
  void        CloseStream(SDTStream *, nsresult);
  void        SendHello();
  void        RemoveStreamFromQueues(SDTStream *);

  void        SetWriteCallbacks();
  void        RealignOutputQueue();

  void        ProcessPending();
//  nsresult    ProcessConnectedPush(SDTStream *, nsAHttpSegmentWriter *,
//                                   uint32_t, uint32_t *);

  nsresult    SetInputFrameDataStream(uint32_t);
  void        CreatePriorityNode(uint32_t, uint32_t, uint8_t, const char *);
  bool        VerifyStream(SDTStream *, uint32_t);
  void        SetNeedsCleanup(SDTStream *);

  // TODO!!!!!
  bool        RoomForMoreConcurrent();
  void        QueueStream(SDTStream *stream);

  // a wrapper for all calls to the nshttpconnection level segment writer. Used
  // to track network I/O for timeout purposes
  nsresult   NetworkRead(nsAHttpSegmentWriter *, char *, uint32_t, uint32_t *);

  nsresult ReadControlStream(nsAHttpSegmentWriter *writer, uint32_t count,
                             uint32_t *countWritten, bool *again);
  nsresult ReadStream(uint32_t streamId, nsAHttpSegmentWriter *writer,
                      uint32_t count, uint32_t *countWritten, bool *again);

  void Shutdown();

  // This is intended to be nsHttpConnectionMgr:nsConnectionHandle taken
  // from the first transaction on this session. That object contains the
  // pointer to the real network-level nsHttpConnection object.
  RefPtr<nsAHttpConnection> mConnection;

  // The underlying socket transport object is needed to propogate some events
  nsISocketTransport         *mSocketTransport;

  // These are temporary state variables to hold the argument to
  // Read/WriteSegments so it can be accessed by On(read/write)segment
  // further up the stack.
  nsAHttpSegmentReader       *mSegmentReader;
  nsAHttpSegmentWriter       *mSegmentWriter;

  uint32_t          mSendingChunkSize;        /* the transmission chunk size */
  uint32_t          mNextStreamID;            /* 24 bits */
//  uint32_t          mLastPushedID;
  uint32_t          mPushAllowance;           /* rwin for unmatched pushes */

  internalStateType mDownstreamState; /* in frame, between frames, etc..  */

  // Maintain 2 indexes - one by stream ID, one by transaction pointer.
  // There are also several lists of streams: ready to write, queued due to
  // max parallelism, streams that need to force a read for push, and the full
  // set of pushed streams.
  // The objects are not ref counted - they get destroyed
  // by the nsClassHashtable implementation when they are removed from
  // the transaction hash.
  nsDataHashtable<nsUint32HashKey, SDTStream *>     mStreamIDHash;
  nsClassHashtable<nsPtrHashKey<nsAHttpTransaction>,
    SDTStream>                                      mStreamTransactionHash;

  nsDeque                                             mReadyForWrite;
  nsDeque                                             mQueuedStreams;
  nsDeque                                             mPushesReadyForRead;
//  nsTArray<Http2PushedStream *>                       mPushedStreams;

  // Compression contexts for header transport.
  // HTTP/2 compresses only HTTP headers and does not reset the context in between
  // frames. Even data that is not associated with a stream (e.g invalid
  // stream ID) is passed through these contexts to keep the compression
  // context correct.
  Http2Compressor     mCompressor;
  Http2Decompressor   mDecompressor;
  nsCString           mDecompressBuffer;

  // mInputFrameBuffer is used to store received control packets and the 8 bytes
  // of header on data packets
  uint32_t             mInputFrameBufferSize; // buffer allocation
  uint32_t             mInputFrameBufferUsed; // amt of allocation used
  UniquePtr<char[]>    mInputFrameBuffer;

  // mInputFrameDataSize/Read are used for tracking the amount of data consumed
  // in a frame after the 8 byte header. Control frames are always fully buffered
  // and the fixed 8 byte leading header is at mInputFrameBuffer + 0, the first
  // data byte (i.e. the first settings/goaway/etc.. specific byte) is at
  // mInputFrameBuffer + 8
  // The frame size is mInputFrameDataSize + the constant 8 byte header
  uint32_t             mInputFrameDataSize;
  uint32_t             mInputFrameDataRead;
  uint8_t              mInputFrameType;
  uint8_t              mInputFrameFlags;
  uint32_t             mInputFrameID;

  // When a frame has been received that is addressed to a particular stream
  // (e.g. a data frame after the stream-id has been decoded), this points
  // to the stream.
  SDTStream          *mInputFrameDataStream;

  SDTStream          *mReadStreamData;

  // mNeedsCleanup is a state variable to defer cleanup of a closed stream
  // If needed, It is set in session::OnWriteSegments() and acted on and
  // cleared when the stack returns to session::WriteSegments(). The stream
  // cannot be destroyed directly out of OnWriteSegments because
  // stream::writeSegments() is on the stack at that time.
  SDTStream          *mNeedsCleanup;

  // This reason code in the last processed RESET frame
  uint32_t             mDownstreamRstReason;

  // When HEADERS/PROMISE are chained together, this is the expected ID of the next
  // recvd frame which must be the same type
  uint32_t             mExpectedHeaderID;
  uint32_t             mExpectedPushPromiseID;
  uint32_t             mContinuedPromiseStream;

  // for the conversion of downstream http headers into http/2 formatted headers
  // The data here does not persist between frames
  nsCString            mFlatHTTPResponseHeaders;
  uint32_t             mFlatHTTPResponseHeadersOut;

  // when set, the session will go away when it reaches 0 streams. This flag
  // is set when: the stream IDs are running out (at either the client or the
  // server), when DontReuse() is called, a RST that is not specific to a
  // particular stream is received, a GOAWAY frame has been received from
  // the server.
  bool                 mShouldGoAway;

  // the session has received a nsAHttpTransaction::Close()  call
  bool                 mClosed;

  // the session received a GoAway frame with a valid GoAwayID
  bool                 mCleanShutdown;

  // The TLS comlpiance checks are not done in the ctor beacuse of bad
  // exception handling - so we do them at IO time and cache the result
  bool                 mTLSProfileConfirmed;

  // A specifc reason code for the eventual GoAway frame. If set to NO_HTTP_ERROR
  // only NO_HTTP_ERROR, PROTOCOL_ERROR, or INTERNAL_ERROR will be sent.
  errorType            mGoAwayReason;

  // The error code sent/received on the session goaway frame. UNASSIGNED/31
  // if not transmitted.
  int32_t             mClientGoAwayReason;
  int32_t             mPeerGoAwayReason;

  // If a GoAway message was received this is the ID of the last valid
  // stream. 0 otherwise. (0 is never a valid stream id.)
  uint32_t             mGoAwayID;

  // The last stream processed ID we will send in our GoAway frame.
  uint32_t             mOutgoingGoAwayID;

  // The number of server initiated promises, tracked for telemetry
  uint32_t             mServerPushedResources;

  // This is a output queue of bytes ready to be written to the SSL stream.
  // When that streams returns WOULD_BLOCK on direct write the bytes get
  // coalesced together here. This results in larger writes to the SSL layer.
  // The buffer is not dynamically grown to accomodate stream writes, but
  // does expand to accept infallible session wide frames like GoAway and RST.
  uint32_t             mOutputQueueSize;
  uint32_t             mOutputQueueUsed;
  uint32_t             mOutputQueueSent;
  UniquePtr<char[]>    mOutputQueueBuffer;

  // TODO !!!!
  PRIntervalTime       mLastReadEpoch;     // used for ping timeouts
  PRIntervalTime       mLastDataReadEpoch; // used for IdleTime()

  // used as a temporary buffer while enumerating the stream hash during GoAway
  nsDeque  mGoAwayStreamsToRestart;

  // Each session gets a unique serial number because the push cache is correlated
  // by the load group and the serial number can be used as part of the cache key
  // to make sure streams aren't shared across sessions.
  uint64_t        mSerial;

  // If push is disabled, we want to be able to send PROTOCOL_ERRORs if we
  // receive a PUSH_PROMISE, but we have to wait for the SETTINGS ACK before
  // we can actually tell the other end to go away. These help us keep track
  // of that state so we can behave appropriately.
  bool mWaitingForSettingsAck;
  bool mGoAwayOnPush;

  bool mUseH2Deps;

private:
/// connect tunnels
  void DispatchOnTunnel(nsAHttpTransaction *, nsIInterfaceRequestor *);
  void CreateTunnel(nsHttpTransaction *, nsHttpConnectionInfo *, nsIInterfaceRequestor *);
  void RegisterTunnel(SDTStream *);
  void UnRegisterTunnel(SDTStream *);
  uint32_t FindTunnelCount(nsHttpConnectionInfo *);
  nsDataHashtable<nsCStringHashKey, uint32_t> mTunnelHash;
};

} // namespace net
} // namespace mozilla

#endif // mozilla_net_SDTSession_h
