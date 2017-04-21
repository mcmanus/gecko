/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// HttpLog.h should generally be included first
#include "HttpLog.h"

// Log on level :5, instead of default :4.
#undef LOG
#define LOG(args) LOG5(args)
#undef LOG_ENABLED
#define LOG_ENABLED() LOG5_ENABLED()

#include <algorithm>

#include "SDTSession.h"
#include "SDTStream.h"
//#include "Http2Push.h"

#include "mozilla/EndianUtils.h"
#include "mozilla/Telemetry.h"
#include "mozilla/Preferences.h"
#include "nsHttp.h"
#include "nsHttpHandler.h"
#include "nsHttpConnection.h"
#include "nsIRequestContext.h"
#include "nsISSLSocketControl.h"
#include "nsISSLStatus.h"
#include "nsISSLStatusProvider.h"
#include "nsISupportsPriority.h"
#include "nsISocketTransportSDT.h"
#include "nsStandardURL.h"
#include "nsURLHelper.h"
#include "prnetdb.h"
#include "sslt.h"
#include "mozilla/Sprintf.h"
#include "nsSocketTransportService2.h"
#include "nsNetUtil.h"

#include "sdt.h"

namespace mozilla {
namespace net {

// SDTSession has multiple inheritance of things that implement
// nsISupports, so this magic is taken from nsHttpPipeline that
// implements some of the same abstract classes.
NS_IMPL_ADDREF(SDTSession)
NS_IMPL_RELEASE(SDTSession)
NS_INTERFACE_MAP_BEGIN(SDTSession)
NS_INTERFACE_MAP_ENTRY_AMBIGUOUS(nsISupports, nsAHttpConnection)
NS_INTERFACE_MAP_END

#define RETURN_SESSION_ERROR(o,x)  \
do {                             \
  (o)->mGoAwayReason = (x);      \
  return NS_ERROR_ILLEGAL_VALUE; \
  } while (0)

SDTSession::SDTSession(nsISocketTransport *aSocketTransport, uint32_t version)
  : mSocketTransport(aSocketTransport)
  , mSegmentReader(nullptr)
  , mSegmentWriter(nullptr)
  , mNextStreamID(5) // 1 is reserved for Updgrade handshakes
//  , mLastPushedID(0)
  , mDownstreamState(BUFFERING_OPENING_SETTINGS)
  , mInputFrameBufferSize(kDefaultBufferSize)
  , mInputFrameBufferUsed(0)
  , mInputFrameDataSize(0)
  , mInputFrameDataRead(0)
  , mInputFrameType(0)
  , mInputFrameFlags(0)
  , mInputFrameID(0)
  , mInputFrameDataStream(nullptr)
  , mNeedsCleanup(nullptr)
  , mDownstreamRstReason(NO_HTTP_ERROR)
  , mExpectedHeaderID(0)
  , mExpectedPushPromiseID(0)
  , mContinuedPromiseStream(0)
  , mFlatHTTPResponseHeadersOut(0)
  , mShouldGoAway(false)
  , mClosed(false)
  , mCleanShutdown(false)
  , mTLSProfileConfirmed(false)
  , mGoAwayReason(NO_HTTP_ERROR)
  , mClientGoAwayReason(UNASSIGNED)
  , mPeerGoAwayReason(UNASSIGNED)
  , mGoAwayID(0)
  , mOutgoingGoAwayID(0)
  , mServerPushedResources(0)
  , mOutputQueueSize(kDefaultQueueSize)
  , mOutputQueueUsed(0)
  , mOutputQueueSent(0)
  , mLastReadEpoch(PR_IntervalNow())
  , mGoAwayOnPush(false)
  , mUseH2Deps(false)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  nsCOMPtr<nsISocketTransportSDT> sdtTrans = do_QueryInterface(mSocketTransport);
  MOZ_ASSERT(sdtTrans);
  uint32_t newStreamId;
  // TODO be sure to always get them both!!! This needs to be fixed in sdt.
  MOZ_ASSERT(NS_SUCCEEDED(sdtTrans->OpenStream(&newStreamId)));
  MOZ_ASSERT(newStreamId == 3);

  static uint64_t sSerial;
  mSerial = ++sSerial;

  LOG3(("SDTSession::SDTSession %p serial=0x%X\n", this, mSerial));

  mInputFrameBuffer = MakeUnique<char[]>(mInputFrameBufferSize);
  mOutputQueueBuffer = MakeUnique<char[]>(mOutputQueueSize);
  mDecompressBuffer.SetCapacity(kDefaultBufferSize);

  mPushAllowance = gHttpHandler->SpdyPushAllowance();
  mSendingChunkSize = gHttpHandler->SpdySendingChunkSize();
  // Set transport parameter and send sdt connection parameter
//  SendHello();

  mLastDataReadEpoch = mLastReadEpoch;
}

void
SDTSession::Shutdown()
{
  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    nsAutoPtr<SDTStream> &stream = iter.Data();

    // On a clean server hangup the server sets the GoAwayID to be the ID of
    // the last transaction it processed. If the ID of stream in the
    // local stream is greater than that it can safely be restarted because the
    // server guarantees it was not partially processed. Streams that have not
    // registered an ID haven't actually been sent yet so they can always be
    // restarted.
    if (mCleanShutdown &&
        (stream->StreamID() > mGoAwayID || !stream->HasRegisteredID())) {
      CloseStream(stream, NS_ERROR_NET_RESET);  // can be restarted
    } else if (stream->RecvdData()) {
      CloseStream(stream, NS_ERROR_NET_PARTIAL_TRANSFER);
    } else if (mGoAwayReason == INADEQUATE_SECURITY) {
      CloseStream(stream, NS_ERROR_NET_INADEQUATE_SECURITY);
    } else {
      CloseStream(stream, NS_ERROR_ABORT);
    }
  }
}

SDTSession::~SDTSession()
{
  LOG3(("SDTSession::~SDTSession %p mDownstreamState=%X",
        this, mDownstreamState));

  Shutdown();
/*
  Telemetry::Accumulate(Telemetry::SPDY_PARALLEL_STREAMS, mConcurrentHighWater);
  Telemetry::Accumulate(Telemetry::SPDY_REQUEST_PER_CONN, (mNextStreamID - 1) / 2);
  Telemetry::Accumulate(Telemetry::SPDY_SERVER_INITIATED_STREAMS,
                        mServerPushedResources);
  Telemetry::Accumulate(Telemetry::SPDY_GOAWAY_LOCAL, mClientGoAwayReason);
  Telemetry::Accumulate(Telemetry::SPDY_GOAWAY_PEER, mPeerGoAwayReason);*/
}

void
SDTSession::LogIO(SDTSession *self, SDTStream *stream,
                    const char *label,
                    const char *data, uint32_t datalen)
{
  if (!LOG5_ENABLED())
    return;

  LOG5(("SDTSession::LogIO %p stream=%p id=0x%X [%s]",
        self, stream, stream ? stream->StreamID() : 0, label));

  // Max line is (16 * 3) + 10(prefix) + newline + null
  char linebuf[128];
  uint32_t index;
  char *line = linebuf;

  linebuf[127] = 0;

  for (index = 0; index < datalen; ++index) {
    if (!(index % 16)) {
      if (index) {
        *line = 0;
        LOG5(("%s", linebuf));
      }
      line = linebuf;
      snprintf(line, 128, "%08X: ", index);
      line += 10;
    }
    snprintf(line, 128 - (line - linebuf), "%02X ", (reinterpret_cast<const uint8_t *>(data))[index]);
    line += 3;
  }
  if (index) {
    *line = 0;
    LOG5(("%s", linebuf));
  }
}

typedef nsresult (*SDTControlFx) (SDTSession *self);
static SDTControlFx sControlFunctions[] = {
  nullptr, // type 0 data is not a control function
  SDTSession::RecvHeaders,
  SDTSession::RecvPriority,
  SDTSession::RecvSettings,
  SDTSession::RecvPushPromise,
  SDTSession::RecvContinuation,
  SDTSession::RecvAltSvc // extension for type 0x0A
};

bool
SDTSession::RoomForMoreConcurrent()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  return true;
}

bool
SDTSession::RoomForMoreStreams()
{
  if (mNextStreamID + mStreamTransactionHash.Count() * 2 > kMaxStreamID)
    return false;

  return !mShouldGoAway;
}

PRIntervalTime
SDTSession::IdleTime()
{
  return PR_IntervalNow() - mLastDataReadEpoch;
}

uint32_t
SDTSession::ReadTimeoutTick(PRIntervalTime now)
{
  return UINT32_MAX;
}

uint32_t
SDTSession::RegisterStreamID(SDTStream *stream, uint32_t aNewID)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(mNextStreamID < 0xfffffff0,
             "should have stopped admitting streams");
  MOZ_ASSERT(!(aNewID & 1),
             "0 for autoassign pull, otherwise explicit even push assignment");

  if (!aNewID) {
    // auto generate a new pull stream ID
    aNewID = mNextStreamID;
    MOZ_ASSERT(aNewID & 1, "pull ID must be odd.");
    mNextStreamID += 4;
  }

  LOG3(("SDTSession::RegisterStreamID session=%p stream=%p id=0x%X ",
        this, stream, aNewID));

  // We've used up plenty of ID's on this session. Start
  // moving to a new one before there is a crunch involving
  // server push streams or concurrent non-registered submits
  if (aNewID >= kMaxStreamID)
    mShouldGoAway = true;

  // integrity check
  if (mStreamIDHash.Get(aNewID)) {
    LOG3(("   New ID already present\n"));
    MOZ_ASSERT(false, "New ID already present in mStreamIDHash");
    mShouldGoAway = true;
    return kDeadStreamID;
  }

  nsCOMPtr<nsISocketTransportSDT> sdtTrans = do_QueryInterface(mSocketTransport);
  MOZ_ASSERT(sdtTrans);
  uint32_t newStreamId;
  // TODO be sure to always get them both!!! This needs to be fixed in sdt. 
  if (NS_FAILED(sdtTrans->OpenStream(&newStreamId))) {
      mNextStreamID -= 4;
      return kDeadStreamID;
  }
  MOZ_ASSERT(newStreamId == (mNextStreamID - 4));
  if (NS_FAILED(sdtTrans->OpenStream(&newStreamId))) {
    mNextStreamID -= 4;
    return kDeadStreamID;
  }
  MOZ_ASSERT(newStreamId == (mNextStreamID - 2));

  mStreamIDHash.Put(aNewID, stream);
  return aNewID;
}

bool
SDTSession::AddStream(nsAHttpTransaction *aHttpTransaction,
                        int32_t aPriority,
                        bool aUseTunnel,
                        nsIInterfaceRequestor *aCallbacks)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  // integrity check
  if (mStreamTransactionHash.Get(aHttpTransaction)) {
    LOG3(("   New transaction already present\n"));
    MOZ_ASSERT(false, "AddStream duplicate transaction pointer");
    return false;
  }

  if (!mConnection) {
    mConnection = aHttpTransaction->Connection();
  }

  if (mClosed || mShouldGoAway) {
    nsHttpTransaction *trans = aHttpTransaction->QueryHttpTransaction();
    if (trans && !trans->GetPushedStream()) {
      LOG3(("SDTSession::AddStream %p atrans=%p trans=%p session unusable - resched.\n",
            this, aHttpTransaction, trans));
      aHttpTransaction->SetConnection(nullptr);
      gHttpHandler->InitiateTransaction(trans, trans->Priority());
      return true;
    }
  }

  aHttpTransaction->SetConnection(this);

  if (aUseTunnel) {
    LOG3(("SDTSession::AddStream session=%p trans=%p OnTunnel",
          this, aHttpTransaction));
    DispatchOnTunnel(aHttpTransaction, aCallbacks);
    return true;
  }

  SDTStream *stream = new SDTStream(aHttpTransaction, this, aPriority);

  LOG3(("SDTSession::AddStream session=%p stream=%p serial=%u "
        "NextID=0x%X (tentative)", this, stream, mSerial, mNextStreamID));

  mStreamTransactionHash.Put(aHttpTransaction, stream);

  mReadyForWrite.Push(stream);
  SetWriteCallbacks();

  // Kick off the SYN transmit without waiting for the poll loop
  // This won't work for the first stream because there is no segment reader
  // yet.
  if (mSegmentReader) {
    uint32_t countRead;
    ReadSegments(nullptr, kDefaultBufferSize, &countRead);
  }

  if (!(aHttpTransaction->Caps() & NS_HTTP_ALLOW_KEEPALIVE) &&
      !aHttpTransaction->IsNullTransaction()) {
    LOG3(("SDTSession::AddStream %p transaction %p forces keep-alive off.\n",
          this, aHttpTransaction));
    DontReuse();
  }

  return true;
}

void
SDTSession::QueueStream(SDTStream *stream)
{
  // will be removed via processpending or a shutdown path
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(!stream->CountAsActive());
  MOZ_ASSERT(!stream->Queued());

  LOG3(("SDTSession::QueueStream %p stream %p queued.", this, stream));

#ifdef DEBUG
  int32_t qsize = mQueuedStreams.GetSize();
  for (int32_t i = 0; i < qsize; i++) {
    SDTStream *qStream = static_cast<SDTStream *>(mQueuedStreams.ObjectAt(i));
    MOZ_ASSERT(qStream != stream);
    MOZ_ASSERT(qStream->Queued());
  }
#endif

  stream->SetQueued(true);
  mQueuedStreams.Push(stream);
}

void
SDTSession::ProcessPending()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  SDTStream*stream;
  while (RoomForMoreConcurrent() &&
         (stream = static_cast<SDTStream *>(mQueuedStreams.PopFront()))) {

    LOG3(("SDTSession::ProcessPending %p stream %p woken from queue.",
          this, stream));
    MOZ_ASSERT(!stream->CountAsActive());
    MOZ_ASSERT(stream->Queued());
    stream->SetQueued(false);
    mReadyForWrite.Push(stream);
    SetWriteCallbacks();
  }
}

nsresult
SDTSession::NetworkRead(nsAHttpSegmentWriter *writer, char *buf,
                          uint32_t count, uint32_t *countWritten)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  if (!count) {
    *countWritten = 0;
    return NS_OK;
  }

  nsresult rv = writer->OnWriteSegment(buf, count, countWritten);
  if (NS_SUCCEEDED(rv) && *countWritten > 0)
    mLastReadEpoch = PR_IntervalNow();
  return rv;
}

void
SDTSession::SetWriteCallbacks()
{
  if (mConnection && (GetWriteQueueSize() || mOutputQueueUsed))
    mConnection->ResumeSend();
}

void
SDTSession::RealignOutputQueue()
{
  mOutputQueueUsed -= mOutputQueueSent;
  memmove(mOutputQueueBuffer.get(),
          mOutputQueueBuffer.get() + mOutputQueueSent,
          mOutputQueueUsed);
  mOutputQueueSent = 0;
}

void
SDTSession::FlushOutputQueue()
{
  if (!mSegmentReader || !mOutputQueueUsed)
    return;

  nsresult rv;
  uint32_t countRead;
  uint32_t avail = mOutputQueueUsed - mOutputQueueSent;

  nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
  MOZ_ASSERT(sock);
  int32_t sdtStatus;
  sock->SetNextStreamToWrite(3, &sdtStatus);
  MOZ_ASSERT(sdtStatus == SDTE_OK);

  rv = mSegmentReader->
    OnReadSegment(mOutputQueueBuffer.get() + mOutputQueueSent, avail,
                  &countRead);
  sock->SetNextStreamToWrite(0, &sdtStatus);
  MOZ_ASSERT(sdtStatus == SDTE_OK);

  LOG3(("SDTSession::FlushOutputQueue %p sz=%d rv=%x actual=%d",
        this, avail, rv, countRead));

  // Dont worry about errors on write, we will pick this up as a read error too
  if (NS_FAILED(rv))
    return;

  if (countRead == avail) {
    mOutputQueueUsed = 0;
    mOutputQueueSent = 0;
    return;
  }

  mOutputQueueSent += countRead;

  // If the output queue is close to filling up and we have sent out a good
  // chunk of data from the beginning then realign it.

  if ((mOutputQueueSent >= kQueueMinimumCleanup) &&
      ((mOutputQueueSize - mOutputQueueUsed) < kQueueTailRoom)) {
    RealignOutputQueue();
  }
}

void
SDTSession::DontReuse()
{
  LOG3(("SDTSession::DontReuse %p\n", this));
  mShouldGoAway = true;
  if (!mStreamTransactionHash.Count())
    Close(NS_OK);
}

uint32_t
SDTSession::SpdyVersion()
{
  return QUIC_EXPERIMENT_0;
}

bool
SDTSession::TestJoinConnection(const nsACString &hostname, int32_t port)
{
  return false;
  // todo
}

bool
SDTSession::JoinConnection(const nsACString &hostname, int32_t port)
{
  return false;
  // todo
}

already_AddRefed<nsHttpConnection>
SDTSession::HttpConnection()
{
  if (mConnection) {
    return mConnection->HttpConnection();
  }
  return nullptr;
}

uint32_t
SDTSession::GetWriteQueueSize()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  return mReadyForWrite.GetSize();
}

void
SDTSession::ChangeDownstreamState(enum internalStateType newState)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  LOG3(("SDTSession::ChangeDownstreamState() %p from %X to %X",
        this, mDownstreamState, newState));
  mDownstreamState = newState;
}

void
SDTSession::ResetDownstreamState()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  LOG3(("SDTSession::ResetDownstreamState() %p", this));
  ChangeDownstreamState(BUFFERING_FRAME_HEADER);

  mInputFrameBufferUsed = 0;
  mInputFrameDataStream = nullptr;
}

// return true if activated (and counted against max)
// otherwise return false and queue
bool
SDTSession::TryToActivate(SDTStream *aStream)
{
  if (aStream->Queued()) {
    LOG3(("SDTSession::TryToActivate %p stream=%p already queued.\n", this, aStream));
    return false;
  }

  if (!RoomForMoreConcurrent()) {
    LOG3(("SDTSession::TryToActivate %p stream=%p no room for more concurrent "
          "streams %d\n", this, aStream));
    QueueStream(aStream);
    return false;
  }

  LOG3(("SDTSession::TryToActivate %p stream=%p\n", this, aStream));
  nsAHttpTransaction *trans = aStream->Transaction();
  if (!trans || !trans->IsNullTransaction() || trans->QuerySpdyConnectTransaction()) {
    MOZ_ASSERT(!aStream->CountAsActive());
    aStream->SetCountAsActive(true);
  }
  return true;
}

// call with data length (i.e. 0 for 0 data bytes - ignore 9 byte header)
// dest must have 9 bytes of allocated space
template<typename charType> void
SDTSession::CreateFrameHeader(charType dest, uint16_t frameLength,
                              uint8_t frameType, uint8_t frameFlags,
                              uint32_t streamID)
{
  MOZ_ASSERT(frameLength <= kMaxFrameData, "framelength too large");
  MOZ_ASSERT(!(streamID & 0x80000000));
  MOZ_ASSERT(!frameFlags ||
             (frameType != FRAME_TYPE_PRIORITY));

  dest[0] = 0x00;
  NetworkEndian::writeUint16(dest + 1, frameLength);
  dest[3] = frameType;
  dest[4] = frameFlags;
  NetworkEndian::writeUint32(dest + 5, streamID);
}

char *
SDTSession::EnsureOutputBuffer(uint32_t spaceNeeded)
{
  // this is an infallible allocation (if an allocation is
  // needed, which is probably isn't)
  EnsureBuffer(mOutputQueueBuffer, mOutputQueueUsed + spaceNeeded,
               mOutputQueueUsed, mOutputQueueSize);
  return mOutputQueueBuffer.get() + mOutputQueueUsed;
}

template void
SDTSession::CreateFrameHeader(char *dest, uint16_t frameLength,
                              uint8_t frameType, uint8_t frameFlags,
                              uint32_t streamID);

template void
SDTSession::CreateFrameHeader(uint8_t *dest, uint16_t frameLength,
                              uint8_t frameType, uint8_t frameFlags,
                              uint32_t streamID);

// Need to decompress some data in order to keep the compression
// context correct, but we really don't care what the result is
nsresult
SDTSession::UncompressAndDiscard(bool isPush)
{
  nsresult rv;
  nsAutoCString trash;

  rv = mDecompressor.DecodeHeaderBlock(reinterpret_cast<const uint8_t *>(mDecompressBuffer.BeginReading()),
                                       mDecompressBuffer.Length(), trash, isPush);
  mDecompressBuffer.Truncate();
  if (NS_FAILED(rv)) {
    LOG3(("SDTSession::UncompressAndDiscard %p Compression Error\n",
          this));
    mGoAwayReason = COMPRESSION_ERROR;
    return rv;
  }
  return NS_OK;
}

void
SDTSession::GeneratePriority(uint32_t aID, uint8_t aPriorityWeight)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::GeneratePriority %p %X %X\n",
        this, aID, aPriorityWeight));

  uint32_t frameSize = kFrameHeaderBytes + 5;
  char *packet = EnsureOutputBuffer(frameSize);
  mOutputQueueUsed += frameSize;

  CreateFrameHeader(packet, 5, FRAME_TYPE_PRIORITY, 0, aID);
  NetworkEndian::writeUint32(packet + kFrameHeaderBytes, 0);
  memcpy(packet + frameSize - 1, &aPriorityWeight, 1);
  LogIO(this, nullptr, "Generate Priority", packet, frameSize);
  FlushOutputQueue();
}

// The Hello is comprised of
// 1] 24 octets of magic, which are designed to
// flush out silent but broken intermediaries
// 2] a settings frame which sets a small flow control window for pushes
// 3] a window update frame which creates a large session flow control window
// 4] 5 priority frames for streams which will never be opened with headers
//    these streams (3, 5, 7, 9, b) build a dependency tree that all other
//    streams will be direct leaves of.
void
SDTSession::SendHello()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::SendHello %p\n", this));

  // sized for magic + 5 settings and a session window update and 5 priority frames
  // 24 magic, 33 for settings (9 header + 4 settings @6), 13 for window update,
  // 5 priority frames at 14 (9 + 5) each
  static const uint32_t maxSettings = 5;
  static const uint32_t prioritySize = 5 * (kFrameHeaderBytes + 5);
  static const uint32_t maxDataLen = kFrameHeaderBytes + maxSettings * 6 + 13 + prioritySize;
  char *packet = EnsureOutputBuffer(maxDataLen);

  packet = mOutputQueueBuffer.get() + mOutputQueueUsed;
  memset(packet, 0, maxDataLen);

  // frame header will be filled in after we know how long the frame is
  uint8_t numberOfEntries = 0;

  // entries need to be listed in order by ID
  // 1st entry is bytes 9 to 14
  // 2nd entry is bytes 15 to 20
  // 3rd entry is bytes 21 to 26
  // 4th entry is bytes 27 to 32
  // 5th entry is bytes 33 to 38

  // Let the other endpoint know about our default HPACK decompress table size
  uint32_t maxHpackBufferSize = gHttpHandler->DefaultHpackBuffer();
  mDecompressor.SetInitialMaxBufferSize(maxHpackBufferSize);
  NetworkEndian::writeUint16(packet + kFrameHeaderBytes + (6 * numberOfEntries), SETTINGS_TYPE_HEADER_TABLE_SIZE);
  NetworkEndian::writeUint32(packet + kFrameHeaderBytes + (6 * numberOfEntries) + 2, maxHpackBufferSize);
  numberOfEntries++;

  if (!gHttpHandler->AllowPush()) {
    // If we don't support push then set ENABLE_PUSH to 0
    NetworkEndian::writeUint16(packet + kFrameHeaderBytes + (6 * numberOfEntries), SETTINGS_TYPE_ENABLE_PUSH);
    // The value portion of the setting pair is already initialized to 0
    numberOfEntries++;

  }

  MOZ_ASSERT(numberOfEntries <= maxSettings);
  uint32_t dataLen = 6 * numberOfEntries;
  CreateFrameHeader(packet, dataLen, FRAME_TYPE_SETTINGS, 0, 0);
  mOutputQueueUsed += kFrameHeaderBytes + dataLen;

  LogIO(this, nullptr, "Generate Settings", packet, kFrameHeaderBytes + dataLen);

/*  if (gHttpHandler->UseH2Deps() && gHttpHandler->CriticalRequestPrioritization()) {
    mUseH2Deps = true;
    MOZ_ASSERT(mNextStreamID == kLeaderGroupID);
    CreatePriorityNode(kLeaderGroupID, 0, 200, "leader");
    mNextStreamID += 2;
    MOZ_ASSERT(mNextStreamID == kOtherGroupID);
    CreatePriorityNode(kOtherGroupID, 0, 100, "other");
    mNextStreamID += 2;
    MOZ_ASSERT(mNextStreamID == kBackgroundGroupID);
    CreatePriorityNode(kBackgroundGroupID, 0, 0, "background");
    mNextStreamID += 2;
    MOZ_ASSERT(mNextStreamID == kSpeculativeGroupID);
    CreatePriorityNode(kSpeculativeGroupID, kBackgroundGroupID, 0, "speculative");
    mNextStreamID += 2;
    MOZ_ASSERT(mNextStreamID == kFollowerGroupID);
    CreatePriorityNode(kFollowerGroupID, kLeaderGroupID, 0, "follower");
    mNextStreamID += 2;
  }*/

  FlushOutputQueue();
}

void
SDTSession::CreatePriorityNode(uint32_t streamID, uint32_t dependsOn, uint8_t weight,
                                 const char *label)
{
  char *packet = mOutputQueueBuffer.get() + mOutputQueueUsed;
  CreateFrameHeader(packet, 5, FRAME_TYPE_PRIORITY, 0, streamID);
  mOutputQueueUsed += kFrameHeaderBytes + 5;
  NetworkEndian::writeUint32(packet + kFrameHeaderBytes, dependsOn); // depends on
  packet[kFrameHeaderBytes + 4] = weight; // weight

  LOG3(("SDTSession %p generate Priority Frame 0x%X depends on 0x%X "
        "weight %d for %s class\n", this, streamID, dependsOn, weight, label));
  LogIO(this, nullptr, "Priority dep node", packet, kFrameHeaderBytes + 5);
}

// perform a bunch of integrity checks on the stream.
// returns true if passed, false (plus LOG and ABORT) if failed.
bool
SDTSession::VerifyStream(SDTStream *aStream, uint32_t aOptionalID = 0)
{
  // This is annoying, but at least it is O(1)
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

#ifndef DEBUG
  // Only do the real verification in debug builds
  return true;
#endif

  if (!aStream)
    return true;

  uint32_t test = 0;

  do {
    if (aStream->StreamID() == kDeadStreamID)
      break;

    nsAHttpTransaction *trans = aStream->Transaction();

    test++;
    if (!trans)
      break;

    test++;
    if (mStreamTransactionHash.Get(trans) != aStream)
      break;

    if (aStream->StreamID()) {
      SDTStream *idStream = mStreamIDHash.Get(aStream->StreamID());

      test++;
      if (idStream != aStream)
        break;

      if (aOptionalID) {
        test++;
        if (idStream->StreamID() != aOptionalID)
          break;
      }
    }

    // tests passed
    return true;
  } while (0);

  LOG3(("SDTSession %p VerifyStream Failure %p stream->id=0x%X "
       "optionalID=0x%X trans=%p test=%d\n",
       this, aStream, aStream->StreamID(),
       aOptionalID, aStream->Transaction(), test));

  MOZ_ASSERT(false, "VerifyStream");
  return false;
}

void
SDTSession::CleanupStream(SDTStream *aStream, nsresult aResult,
                          errorType aResetCode)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::CleanupStream %p %p 0x%X %X\n",
        this, aStream, aStream ? aStream->StreamID() : 0, aResult));
  if (!aStream) {
    return;
  }

  if (aStream->DeferCleanup(aResult)) {
    LOG3(("SDTSession::CleanupStream 0x%X deferred\n", aStream->StreamID()));
    return;
  }

  if (!VerifyStream(aStream)) {
    LOG3(("SDTSession::CleanupStream failed to verify stream\n"));
    return;
  }

//  Http2PushedStream *pushSource = aStream->PushSource();
/*  if (pushSource) {
    // aStream is a synthetic  attached to an even push
    MOZ_ASSERT(pushSource->GetConsumerStream() == aStream);
    MOZ_ASSERT(!aStream->StreamID());
    MOZ_ASSERT(!(pushSource->StreamID() & 0x1));
    pushSource->SetConsumerStream(nullptr);
  }
*/
  // don't reset a stream that has recevied a fin or rst
/*  if (!aStream->RecvdFin() && !aStream->RecvdReset() && aStream->StreamID() &&
      !(mInputFrameFinal && (aStream == mInputFrameDataStream))) { // !(recvdfin with mark pending)
    LOG3(("Stream 0x%X had not processed recv FIN, sending RST code %X\n", aStream->StreamID(), aResetCode));
    GenerateRstStream(aResetCode, aStream->StreamID());
  }*/

  CloseStream(aStream, aResult);

  // Remove the stream from the ID hash table and, if an even id, the pushed
  // table too.
  uint32_t id = aStream->StreamID();
  if (id > 0) {
    mStreamIDHash.Remove(id);
    if (!(id & 1)) {
      //mPushedStreams.RemoveElement(aStream);
      //Http2PushedStream *pushStream = static_cast<Http2PushedStream *>(aStream);
      //nsAutoCString hashKey;
      //pushStream->GetHashKey(hashKey);
      //nsIRequestContext *requestContext = aStream->RequestContext();
      //if (requestContext) {
        //SpdyPushCache *cache = nullptr;
        //requestContext->GetSpdyPushCache(&cache);
        //if (cache) {
          //Http2PushedStream *trash = cache->RemovePushedStreamHttp2(hashKey);
          //LOG3(("Http2Session::CleanupStream %p aStream=%p pushStream=%p trash=%p",
          //      this, aStream, pushStream, trash));
        //}
      //}
    }
  }

  RemoveStreamFromQueues(aStream);

  // removing from the stream transaction hash will
  // delete the SDTStream and drop the reference to
  // its transaction
  mStreamTransactionHash.Remove(aStream->Transaction());

  if (mShouldGoAway && !mStreamTransactionHash.Count())
    Close(NS_OK);

/*  if (pushSource) {
    pushSource->SetDeferCleanupOnSuccess(false);
    CleanupStream(pushSource, aResult, aResetCode);
  }
*/
}

void
SDTSession::CleanupStream(uint32_t aID, nsresult aResult, errorType aResetCode)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  SDTStream *stream = mStreamIDHash.Get(aID);
  LOG3(("SDTSession::CleanupStream %p by ID 0x%X to stream %p\n",
        this, aID, stream));
  if (!stream) {
    return;
  }
  CleanupStream(stream, aResult, aResetCode);
}

static void RemoveStreamFromQueue(SDTStream *aStream, nsDeque &queue)
{
  size_t size = queue.GetSize();
  for (size_t count = 0; count < size; ++count) {
    SDTStream *stream = static_cast<SDTStream *>(queue.PopFront());
    if (stream != aStream)
      queue.Push(stream);
  }
}

void
SDTSession::RemoveStreamFromQueues(SDTStream *aStream)
{
  RemoveStreamFromQueue(aStream, mReadyForWrite);
  RemoveStreamFromQueue(aStream, mQueuedStreams);
  RemoveStreamFromQueue(aStream, mPushesReadyForRead);
}

void
SDTSession::CloseStream(SDTStream *aStream, nsresult aResult)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::CloseStream %p %p 0x%x %X\n",
        this, aStream, aStream->StreamID(), aResult));

  aStream->SetCountAsActive(true);

  RemoveStreamFromQueues(aStream);

  if (aStream->IsTunnel()) {
    UnRegisterTunnel(aStream);
  }

  // Send the stream the close() indication
  aStream->Close(aResult);
}

nsresult
SDTSession::SetInputFrameDataStream(uint32_t streamID)
{
  mInputFrameDataStream = mStreamIDHash.Get(streamID);
  if (VerifyStream(mInputFrameDataStream, streamID))
    return NS_OK;

  LOG3(("SDTSession::SetInputFrameDataStream failed to verify 0x%X\n",
       streamID));
  mInputFrameDataStream = nullptr;
  return NS_ERROR_UNEXPECTED;
}

nsresult
SDTSession::RecvHeaders(SDTSession *self)
{
  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_HEADERS ||
             self->mInputFrameType == FRAME_TYPE_CONTINUATION);

  bool isContinuation = self->mExpectedHeaderID != 0;

  // If this doesn't have END_HEADERS set on it then require the next
  // frame to be HEADERS of the same ID
  bool endHeadersFlag = self->mInputFrameFlags & kFlag_END_HEADERS;

  if (endHeadersFlag)
    self->mExpectedHeaderID = 0;
  else
    self->mExpectedHeaderID = self->mInputFrameID;

  self->SetInputFrameDataStream(self->mInputFrameID);

  nsresult rv;

  if (!isContinuation) {
    self->mDecompressBuffer.Truncate();
  }

  LOG3(("SDTSession::RecvHeaders %p stream 0x%X stream=%p "
        "end_headers=%d\n",
        self, self->mInputFrameID, self->mInputFrameDataStream,
        self->mInputFrameFlags & kFlag_END_HEADERS));

  if (!self->mInputFrameDataStream) {
    // Cannot find stream. We can continue the session, but we need to
    // uncompress the header block to maintain the correct compression context

    LOG3(("SDTSession::RecvHeaders %p lookup mInputFrameID stream "
          "0x%X failed. NextStreamID = 0x%X\n",
          self, self->mInputFrameID, self->mNextStreamID));

    if (self->mInputFrameID >= self->mNextStreamID) {
      nsCOMPtr<nsISocketTransportSDT> trans = do_QueryInterface(self->mSocketTransport);
      trans->ResetStream(self->mInputFrameID);
    }

    self->mDecompressBuffer.Append(&self->mInputFrameBuffer[kFrameHeaderBytes],
                                   self->mInputFrameDataSize);

    if (self->mInputFrameFlags & kFlag_END_HEADERS) {
      rv = self->UncompressAndDiscard(false);
      if (NS_FAILED(rv)) {
        LOG3(("SDTSession::RecvHeaders uncompress failed\n"));
        // this is fatal to the session
        self->mGoAwayReason = COMPRESSION_ERROR;
        return rv;
      }
    }

    self->ResetDownstreamState();
    return NS_OK;
  }

  // queue up any compression bytes
  self->mDecompressBuffer.Append(&self->mInputFrameBuffer[kFrameHeaderBytes],
                                 self->mInputFrameDataSize);

  self->mInputFrameDataStream->UpdateTransportReadEvents(self->mInputFrameDataSize);
  self->mLastDataReadEpoch = self->mLastReadEpoch;

  if (!endHeadersFlag) { // more are coming - don't process yet
    self->ResetDownstreamState();
    return NS_OK;
  }

  rv = self->ResponseHeadersComplete();
  if (rv == NS_ERROR_ILLEGAL_VALUE) {
    LOG3(("SDTSession::RecvHeaders %p PROTOCOL_ERROR detected stream 0x%X\n",
          self, self->mInputFrameID));
    self->CleanupStream(self->mInputFrameDataStream, rv, PROTOCOL_ERROR);
    self->ResetDownstreamState();
    rv = NS_OK;
  } else if (NS_FAILED(rv)) {
    // This is fatal to the session.
    self->mGoAwayReason = COMPRESSION_ERROR;
  }
  return rv;
}

// ResponseHeadersComplete() returns NS_ERROR_ILLEGAL_VALUE when the stream
// should be reset with a PROTOCOL_ERROR, NS_OK when the response headers were
// fine, and any other error is fatal to the session.
nsresult
SDTSession::ResponseHeadersComplete()
{
  LOG3(("SDTSession::ResponseHeadersComplete %p for 0x%X",
        this, mInputFrameDataStream->StreamID()));

  // only interpret headers once, afterwards ignore as trailers
  if (mInputFrameDataStream->AllHeadersReceived()) {
    LOG3(("SDTSession::ResponseHeadersComplete extra headers"));
    nsresult rv = UncompressAndDiscard(false);
    if (NS_FAILED(rv)) {
      LOG3(("SDTSession::ResponseHeadersComplete extra uncompress failed\n"));
      return rv;
    }
    mFlatHTTPResponseHeadersOut = 0;
    mFlatHTTPResponseHeaders.Truncate();
    ResetDownstreamState();
    return NS_OK;
  }

  // if this turns out to be a 1xx response code we have to
  // undo the headers received bit that we are setting here.
  bool didFirstSetAllRecvd = !mInputFrameDataStream->AllHeadersReceived();
  mInputFrameDataStream->SetAllHeadersReceived();

  // The stream needs to see flattened http headers
  // Uncompressed http/2 format headers currently live in
  // SDTStream::mDecompressBuffer - convert that to HTTP format in
  // mFlatHTTPResponseHeaders via ConvertHeaders()

  nsresult rv;
  int32_t httpResponseCode; // out param to ConvertResponseHeaders
  mFlatHTTPResponseHeadersOut = 0;
  rv = mInputFrameDataStream->ConvertResponseHeaders(&mDecompressor,
                                                     mDecompressBuffer,
                                                     mFlatHTTPResponseHeaders,
                                                     httpResponseCode);
  if (rv == NS_ERROR_ABORT) {
    LOG(("SDTSession::ResponseHeadersComplete ConvertResponseHeaders aborted\n"));
    if (mInputFrameDataStream->IsTunnel()) {
      gHttpHandler->ConnMgr()->CancelTransactions(
        mInputFrameDataStream->Transaction()->ConnectionInfo(),
        NS_ERROR_CONNECTION_REFUSED);
    }
    CleanupStream(mInputFrameDataStream, rv, CANCEL_ERROR);
    ResetDownstreamState();
    return NS_OK;
  } else if (NS_FAILED(rv)) {
    return rv;
  }

  // allow more headers in the case of 1xx
  if (((httpResponseCode / 100) == 1) && didFirstSetAllRecvd) {
    mInputFrameDataStream->UnsetAllHeadersReceived();
  }

  ChangeDownstreamState(PROCESSING_COMPLETE_HEADERS);
  return NS_OK;
}

nsresult
SDTSession::RecvPriority(SDTSession *self)
{
  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_PRIORITY);

  if (self->mInputFrameDataSize != 5) {
    LOG3(("SDTSession::RecvPriority %p wrong length data=%d\n",
          self, self->mInputFrameDataSize));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  if (!self->mInputFrameID) {
    LOG3(("SDTSession::RecvPriority %p stream ID of 0.\n", self));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  nsresult rv = self->SetInputFrameDataStream(self->mInputFrameID);
  if (NS_FAILED(rv))
    return rv;

  uint32_t newPriorityDependency = NetworkEndian::readUint32(
      self->mInputFrameBuffer.get() + kFrameHeaderBytes);
  bool exclusive = !!(newPriorityDependency & 0x80000000);
  newPriorityDependency &= 0x7fffffff;
  uint8_t newPriorityWeight = *(self->mInputFrameBuffer.get() + kFrameHeaderBytes + 4);
  if (self->mInputFrameDataStream) {
    self->mInputFrameDataStream->SetPriorityDependency(newPriorityDependency,
                                                       newPriorityWeight,
                                                       exclusive);
  }

  self->ResetDownstreamState();
  return NS_OK;
}

nsresult
SDTSession::RecvSettings(SDTSession *self)
{
  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_SETTINGS);

  if (self->mInputFrameID) {
    LOG3(("SDTSession::RecvSettings %p needs stream ID of 0. 0x%X\n",
          self, self->mInputFrameID));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  if (self->mInputFrameDataSize % 6) {
    // Number of Settings is determined by dividing by each 6 byte setting
    // entry. So the payload must be a multiple of 6.
    LOG3(("SDTSession::RecvSettings %p SETTINGS wrong length data=%d",
          self, self->mInputFrameDataSize));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  uint32_t numEntries = self->mInputFrameDataSize / 6;
  LOG3(("SDTSession::RecvSettings %p SETTINGS Control Frame "
        "with %d", self, numEntries));

  for (uint32_t index = 0; index < numEntries; ++index) {
    uint8_t *setting = reinterpret_cast<uint8_t *>
      (self->mInputFrameBuffer.get()) + kFrameHeaderBytes + index * 6;

    uint16_t id = NetworkEndian::readUint16(setting);
    uint32_t value = NetworkEndian::readUint32(setting + 2);
    LOG3(("Settings ID %u, Value %u", id, value));

    switch (id)
    {
    case SETTINGS_TYPE_HEADER_TABLE_SIZE:
      LOG3(("Compression header table setting received: %d\n", value));
      self->mCompressor.SetMaxBufferSize(value);
      break;

    case SETTINGS_TYPE_ENABLE_PUSH:
      LOG3(("Client received an ENABLE Push SETTING. Odd.\n"));
      // nop
      break;

    default:
      break;
    }
  }

  self->ResetDownstreamState();

  return NS_OK;
}

nsresult
SDTSession::RecvPushPromise(SDTSession *self)
{
/*  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_PUSH_PROMISE ||
             self->mInputFrameType == FRAME_TYPE_CONTINUATION);

  // If this doesn't have END_PUSH_PROMISE set on it then require the next
  // frame to be PUSH_PROMISE of the same ID
  uint32_t promiseLen;
  uint32_t promisedID;

  if (self->mExpectedPushPromiseID) {
    promiseLen = 0; // really a continuation frame
    promisedID = self->mContinuedPromiseStream;
  } else {
    self->mDecompressBuffer.Truncate();

    promiseLen = 4;
    promisedID = NetworkEndian::readUint32(
        self->mInputFrameBuffer.get() + kFrameHeaderBytes);
    promisedID &= 0x7fffffff;
    if (promisedID <= self->mLastPushedID) {
      LOG3(("SDTSession::RecvPushPromise %p ID too low %u expected > %u.\n",
            self, promisedID, self->mLastPushedID));
      RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
    }
    self->mLastPushedID = promisedID;
  }

  uint32_t associatedID = self->mInputFrameID;

  if (self->mInputFrameFlags & kFlag_END_PUSH_PROMISE) {
    self->mExpectedPushPromiseID = 0;
    self->mContinuedPromiseStream = 0;
  } else {
    self->mExpectedPushPromiseID = self->mInputFrameID;
    self->mContinuedPromiseStream = promisedID;
  }

  if (promiseLen > self->mInputFrameDataSize) {
    // This is fatal to the session
    LOG3(("SDTSession::RecvPushPromise %p ID 0x%X assoc ID 0x%X "
          "PROTOCOL_ERROR extra %d > frame size %d\n",
          self, promisedID, associatedID, promiseLen,
          self->mInputFrameDataSize));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  LOG3(("SDTSession::RecvPushPromise %p ID 0x%X assoc ID 0x%X \n",
        self, promisedID, associatedID));

  if (!associatedID || !promisedID || (promisedID & 1)) {
    LOG3(("SDTSession::RecvPushPromise %p ID invalid.\n", self));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  // confirm associated-to
  nsresult rv = self->SetInputFrameDataStream(associatedID);
  if (NS_FAILED(rv))
    return rv;

  SDTStream *associatedStream = self->mInputFrameDataStream;
  ++(self->mServerPushedResources);

  // Anytime we start using the high bit of stream ID (either client or server)
  // begin to migrate to a new session.
  if (promisedID >= kMaxStreamID)
    self->mShouldGoAway = true;

  bool resetStream = true;
  SpdyPushCache *cache = nullptr;

  if (self->mShouldGoAway && !Http2PushedStream::TestOnPush(associatedStream)) {
    LOG3(("SDTSession::RecvPushPromise %p cache push while in GoAway "
          "mode refused.\n", self));
    self->GenerateRstStream(REFUSED_STREAM_ERROR, promisedID);
  } else if (!gHttpHandler->AllowPush()) {
    // ENABLE_PUSH and MAX_CONCURRENT_STREAMS of 0 in settings disabled push
    LOG3(("SDTSession::RecvPushPromise Push Recevied when Disabled\n"));
    if (self->mGoAwayOnPush) {
      LOG3(("SDTSession::RecvPushPromise sending GOAWAY"));
      RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
    }
    self->GenerateRstStream(REFUSED_STREAM_ERROR, promisedID);
  } else if (!(associatedID & 1)) {
    LOG3(("SDTSession::RecvPushPromise %p assocated=0x%X on pushed (even) stream not allowed\n",
          self, associatedID));
    self->GenerateRstStream(PROTOCOL_ERROR, promisedID);
  } else if (!associatedStream) {
    LOG3(("SDTSession::RecvPushPromise %p lookup associated ID failed.\n", self));
    self->GenerateRstStream(PROTOCOL_ERROR, promisedID);
  } else {
    nsIRequestContext *requestContext = associatedStream->RequestContext();
    if (requestContext) {
      requestContext->GetSpdyPushCache(&cache);
      if (!cache) {
        cache = new SpdyPushCache();
        if (!cache || NS_FAILED(requestContext->SetSpdyPushCache(cache))) {
          delete cache;
          cache = nullptr;
        }
      }
    }
    if (!cache) {
      // this is unexpected, but we can handle it just by refusing the push
      LOG3(("SDTSession::RecvPushPromise Push Recevied without push cache\n"));
      self->GenerateRstStream(REFUSED_STREAM_ERROR, promisedID);
    } else {
      resetStream = false;
    }
  }

  if (resetStream) {
    // Need to decompress the headers even though we aren't using them yet in
    // order to keep the compression context consistent for other frames
    self->mDecompressBuffer.Append(&self->mInputFrameBuffer[kFrameHeaderBytes + promiseLen],
                                   self->mInputFrameDataSize - promiseLen);
    if (self->mInputFrameFlags & kFlag_END_PUSH_PROMISE) {
      rv = self->UncompressAndDiscard(true);
      if (NS_FAILED(rv)) {
        LOG3(("SDTSession::RecvPushPromise uncompress failed\n"));
        self->mGoAwayReason = COMPRESSION_ERROR;
        return rv;
      }
    }
    self->ResetDownstreamState();
    return NS_OK;
  }

  self->mDecompressBuffer.Append(&self->mInputFrameBuffer[kFrameHeaderBytes + promiseLen],
                                 self->mInputFrameDataSize - promiseLen);

  if (!(self->mInputFrameFlags & kFlag_END_PUSH_PROMISE)) {
    LOG3(("SDTSession::RecvPushPromise not finishing processing for multi-frame push\n"));
    self->ResetDownstreamState();
    return NS_OK;
  }

  // Create the buffering transaction and push stream
  RefPtr<Http2PushTransactionBuffer> transactionBuffer =
    new Http2PushTransactionBuffer();
  transactionBuffer->SetConnection(self);
  Http2PushedStream *pushedStream =
    new Http2PushedStream(transactionBuffer, self, associatedStream, promisedID);

  rv = pushedStream->ConvertPushHeaders(&self->mDecompressor,
                                        self->mDecompressBuffer,
                                        pushedStream->GetRequestString());

  if (rv == NS_ERROR_NOT_IMPLEMENTED) {
    LOG3(("SDTSession::PushPromise Semantics not Implemented\n"));
    self->GenerateRstStream(REFUSED_STREAM_ERROR, promisedID);
    delete pushedStream;
    self->ResetDownstreamState();
    return NS_OK;
  }

  if (rv == NS_ERROR_ILLEGAL_VALUE) {
    // This means the decompression completed ok, but there was a problem with
    // the decoded headers. Reset the stream and go away.
    self->GenerateRstStream(PROTOCOL_ERROR, promisedID);
    delete pushedStream;
    self->ResetDownstreamState();
    return NS_OK;
  } else if (NS_FAILED(rv)) {
    // This is fatal to the session.
    self->mGoAwayReason = COMPRESSION_ERROR;
    return rv;
  }

  // Ownership of the pushed stream is by the transaction hash, just as it
  // is for a client initiated stream. Errors that aren't fatal to the
  // whole session must call cleanupStream() after this point in order
  // to remove the stream from that hash.
  self->mStreamTransactionHash.Put(transactionBuffer, pushedStream);
  self->mPushedStreams.AppendElement(pushedStream);

  if (self->RegisterStreamID(pushedStream, promisedID) == kDeadStreamID) {
    LOG3(("SDTSession::RecvPushPromise registerstreamid failed\n"));
    self->mGoAwayReason = INTERNAL_ERROR;
    return NS_ERROR_FAILURE;
  }

  if (promisedID > self->mOutgoingGoAwayID)
    self->mOutgoingGoAwayID = promisedID;

  // Fake the request side of the pushed HTTP transaction. Sets up hash
  // key and origin
  uint32_t notUsed;
  pushedStream->ReadSegments(nullptr, 1, &notUsed);

  nsAutoCString key;
  if (!pushedStream->GetHashKey(key)) {
    LOG3(("SDTSession::RecvPushPromise one of :authority :scheme :path missing from push\n"));
    self->CleanupStream(pushedStream, NS_ERROR_FAILURE, PROTOCOL_ERROR);
    self->ResetDownstreamState();
    return NS_OK;
  }

  RefPtr<nsStandardURL> associatedURL, pushedURL;
  rv = SDTStream::MakeOriginURL(associatedStream->Origin(), associatedURL);
  if (NS_SUCCEEDED(rv)) {
    rv = SDTStream::MakeOriginURL(pushedStream->Origin(), pushedURL);
  }
  LOG3(("SDTSession::RecvPushPromise %p checking %s == %s", self,
        associatedStream->Origin().get(), pushedStream->Origin().get()));
  bool match = false;
  if (NS_SUCCEEDED(rv)) {
    rv = associatedURL->Equals(pushedURL, &match);
  }
  if (NS_FAILED(rv)) {
    // Fallback to string equality of origins. This won't be guaranteed to be as
    // liberal as we want it to be, but it will at least be safe
    match = associatedStream->Origin().Equals(pushedStream->Origin());
  }
  if (!match) {
    LOG3(("SDTSession::RecvPushPromise %p pushed stream mismatched origin "
          "associated origin %s .. pushed origin %s\n", self,
          associatedStream->Origin().get(), pushedStream->Origin().get()));
    self->CleanupStream(pushedStream, NS_ERROR_FAILURE, REFUSED_STREAM_ERROR);
    self->ResetDownstreamState();
    return NS_OK;
  }

  if (pushedStream->TryOnPush()) {
    LOG3(("SDTSession::RecvPushPromise %p channel implements nsIHttpPushListener "
          "stream %p will not be placed into session cache.\n", self, pushedStream));
  } else {
    LOG3(("SDTSession::RecvPushPromise %p place stream into session cache\n", self));
    if (!cache->RegisterPushedStreamHttp2(key, pushedStream)) {
      LOG3(("SDTSession::RecvPushPromise registerPushedStream Failed\n"));
      self->CleanupStream(pushedStream, NS_ERROR_FAILURE, INTERNAL_ERROR);
      self->ResetDownstreamState();
      return NS_OK;
    }
  }

  pushedStream->SetHTTPState(SDTStream::RESERVED_BY_REMOTE);
  static_assert(SDTStream::kWorstPriority >= 0,
                "kWorstPriority out of range");
  uint8_t priorityWeight = (nsISupportsPriority::PRIORITY_LOWEST + 1) -
    (Http2Stream::kWorstPriority - Http2Stream::kNormalPriority);
  pushedStream->SetPriority(Http2Stream::kWorstPriority);
  self->GeneratePriority(promisedID, priorityWeight);
  self->ResetDownstreamState();
*/
  return NS_OK;
}

nsresult
SDTSession::RecvContinuation(SDTSession *self)
{
  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_CONTINUATION);
  MOZ_ASSERT(self->mInputFrameID);
  MOZ_ASSERT(self->mExpectedPushPromiseID || self->mExpectedHeaderID);
  MOZ_ASSERT(!(self->mExpectedPushPromiseID && self->mExpectedHeaderID));

  LOG3(("SDTSession::RecvContinuation %p Flags 0x%X id 0x%X "
        "promise id 0x%X header id 0x%X\n",
        self, self->mInputFrameFlags, self->mInputFrameID,
        self->mExpectedPushPromiseID, self->mExpectedHeaderID));

  self->SetInputFrameDataStream(self->mInputFrameID);

  if (!self->mInputFrameDataStream) {
    LOG3(("SDTSession::RecvContination stream ID 0x%X not found.",
          self->mInputFrameID));
    RETURN_SESSION_ERROR(self, PROTOCOL_ERROR);
  }

  // continued headers
  if (self->mExpectedHeaderID) {
    return RecvHeaders(self);
  }
MOZ_ASSERT(false, "RecvPushPromise !!!!!!!");
  // continued push promise
  if (self->mInputFrameFlags & kFlag_END_HEADERS) {
    self->mInputFrameFlags &= ~kFlag_END_HEADERS;
//    self->mInputFrameFlags |= kFlag_END_PUSH_PROMISE;
  }
  return RecvPushPromise(self);
}

class UpdateAltSvcEvent : public Runnable
{
public:
UpdateAltSvcEvent(const nsCString &header,
                  const nsCString &aOrigin,
                  nsHttpConnectionInfo *aCI,
                  nsIInterfaceRequestor *callbacks)
    : mHeader(header)
    , mOrigin(aOrigin)
    , mCI(aCI)
    , mCallbacks(callbacks)
  {
  }

  NS_IMETHOD Run() override
  {
    MOZ_ASSERT(NS_IsMainThread());

    nsCString originScheme;
    nsCString originHost;
    int32_t originPort = -1;

    nsCOMPtr<nsIURI> uri;
    if (NS_FAILED(NS_NewURI(getter_AddRefs(uri), mOrigin))) {
      LOG(("UpdateAltSvcEvent origin does not parse %s\n",
           mOrigin.get()));
      return NS_OK;
    }
    uri->GetScheme(originScheme);
    uri->GetHost(originHost);
    uri->GetPort(&originPort);

    AltSvcMapping::ProcessHeader(mHeader, originScheme, originHost, originPort,
                                 mCI->GetUsername(), mCI->GetPrivate(), mCallbacks,
                                 mCI->ProxyInfo(), 0, mCI->GetOriginAttributes());
    return NS_OK;
  }

private:
  nsCString mHeader;
  nsCString mOrigin;
  RefPtr<nsHttpConnectionInfo> mCI;
  nsCOMPtr<nsIInterfaceRequestor> mCallbacks;
};

// defined as an http2 extension - alt-svc
// defines receipt of frame type 0x0A.. See AlternateSevices.h at least draft -06 sec 4
// as this is an extension, never generate protocol error - just ignore problems
nsresult
SDTSession::RecvAltSvc(SDTSession *self)
{
  MOZ_ASSERT(self->mInputFrameType == FRAME_TYPE_ALTSVC);
  LOG3(("SDTSession::RecvAltSvc %p Flags 0x%X id 0x%X\n", self,
        self->mInputFrameFlags, self->mInputFrameID));

  if (self->mInputFrameDataSize < 2) {
    LOG3(("SDTSession::RecvAltSvc %p frame too small", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  uint16_t originLen = NetworkEndian::readUint16(
      self->mInputFrameBuffer.get() + kFrameHeaderBytes);
  if (originLen + 2U > self->mInputFrameDataSize) {
    LOG3(("SDTSession::RecvAltSvc %p origin len too big for frame", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  if (!gHttpHandler->AllowAltSvc()) {
    LOG3(("SDTSession::RecvAltSvc %p frame alt service pref'd off", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  uint16_t altSvcFieldValueLen = static_cast<uint16_t>(self->mInputFrameDataSize) - 2U - originLen;
  LOG3(("SDTSession::RecvAltSvc %p frame originLen=%u altSvcFieldValueLen=%u\n",
        self, originLen, altSvcFieldValueLen));

  if (self->mInputFrameDataSize > 2000) {
    LOG3(("SDTSession::RecvAltSvc %p frame too large to parse sensibly", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  nsAutoCString origin;
  bool impliedOrigin = true;
  if (originLen) {
    origin.Assign(self->mInputFrameBuffer.get() + kFrameHeaderBytes + 2, originLen);
    impliedOrigin = false;
  }

  nsAutoCString altSvcFieldValue;
  if (altSvcFieldValueLen) {
    altSvcFieldValue.Assign(self->mInputFrameBuffer.get() + kFrameHeaderBytes + 2 + originLen,
                            altSvcFieldValueLen);
  }

  if (altSvcFieldValue.IsEmpty() || !nsHttp::IsReasonableHeaderValue(altSvcFieldValue)) {
    LOG(("SDTSession %p Alt-Svc Response Header seems unreasonable - skipping\n", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  if (self->mInputFrameID & 1) {
    // pulled streams apply to the origin of the pulled stream.
    // If the origin field is filled in the frame, the frame should be ignored
    if (!origin.IsEmpty()) {
      LOG(("SDTSession %p Alt-Svc pulled stream has non empty origin\n", self));
      self->ResetDownstreamState();
      return NS_OK;
    }
    
    if (NS_FAILED(self->SetInputFrameDataStream(self->mInputFrameID)) ||
        !self->mInputFrameDataStream->Transaction() ||
        !self->mInputFrameDataStream->Transaction()->RequestHead()) {
      LOG3(("SDTSession::RecvAltSvc %p got frame w/o origin on invalid stream", self));
      self->ResetDownstreamState();
      return NS_OK;
    }

    self->mInputFrameDataStream->Transaction()->RequestHead()->Origin(origin);
  } else if (!self->mInputFrameID) {
    // ID 0 streams must supply their own origin
    if (origin.IsEmpty()) {
      LOG(("SDTSession %p Alt-Svc Stream 0 has empty origin\n", self));
      self->ResetDownstreamState();
      return NS_OK;
    }
  } else {
    // handling of push streams is not defined. Let's ignore it
    LOG(("SDTSession %p Alt-Svc received on pushed stream - ignoring\n", self));
    self->ResetDownstreamState();
    return NS_OK;
  }

  RefPtr<nsHttpConnectionInfo> ci(self->ConnectionInfo());
  if (!self->mConnection || !ci) {
    LOG3(("SDTSession::RecvAltSvc %p no connection or conninfo for %d", self,
          self->mInputFrameID));
    self->ResetDownstreamState();
    return NS_OK;
  }

  if (!impliedOrigin) {
    bool okToReroute = true;
    nsCOMPtr<nsISupports> securityInfo;
    self->mConnection->GetSecurityInfo(getter_AddRefs(securityInfo));
    nsCOMPtr<nsISSLSocketControl> ssl = do_QueryInterface(securityInfo);
    if (!ssl) {
      okToReroute = false;
    }

    // a little off main thread origin parser. This is a non critical function because
    // any alternate route created has to be verified anyhow
    nsAutoCString specifiedOriginHost;
    if (origin.EqualsIgnoreCase("https://", 8)) {
      specifiedOriginHost.Assign(origin.get() + 8, origin.Length() - 8);
    } else if (origin.EqualsIgnoreCase("http://", 7)) {
      specifiedOriginHost.Assign(origin.get() + 7, origin.Length() - 7);
    }

    int32_t colonOffset = specifiedOriginHost.FindCharInSet(":", 0);
    if (colonOffset != kNotFound) {
      specifiedOriginHost.Truncate(colonOffset);
    }

    if (okToReroute) {
      ssl->IsAcceptableForHost(specifiedOriginHost, &okToReroute);
    }

    if (!okToReroute) {
      LOG3(("SDTSession::RecvAltSvc %p can't reroute non-authoritative origin %s",
            self, origin.BeginReading()));
      self->ResetDownstreamState();
      return NS_OK;
    }
  }

  nsCOMPtr<nsISupports> callbacks;
  self->mConnection->GetSecurityInfo(getter_AddRefs(callbacks));
  nsCOMPtr<nsIInterfaceRequestor> irCallbacks = do_QueryInterface(callbacks);

  RefPtr<UpdateAltSvcEvent> event =
    new UpdateAltSvcEvent(altSvcFieldValue, origin, ci, irCallbacks);
  NS_DispatchToMainThread(event);
  self->ResetDownstreamState();
  return NS_OK;
}

//-----------------------------------------------------------------------------
// nsAHttpTransaction. It is expected that nsHttpConnection is the caller
// of these methods
//-----------------------------------------------------------------------------

void
SDTSession::OnTransportStatus(nsITransport* aTransport,
                              nsresult aStatus, int64_t aProgress)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  switch (aStatus) {
    // These should appear only once, deliver to the first
    // transaction on the session.
  case NS_NET_STATUS_RESOLVING_HOST:
  case NS_NET_STATUS_RESOLVED_HOST:
  case NS_NET_STATUS_CONNECTING_TO:
  case NS_NET_STATUS_CONNECTED_TO:
  {
    SDTStream *target = mStreamIDHash.Get(1);
    nsAHttpTransaction *transaction = target ? target->Transaction() : nullptr;
    if (transaction)
      transaction->OnTransportStatus(aTransport, aStatus, aProgress);
    break;
  }

  default:
    // The other transport events are ignored here because there is no good
    // way to map them to the right transaction in http/2. Instead, the events
    // are generated again from the http/2 code and passed directly to the
    // correct transaction.

    // NS_NET_STATUS_SENDING_TO:
    // This is generated by the socket transport when (part) of
    // a transaction is written out
    //
    // There is no good way to map it to the right transaction in http/2,
    // so it is ignored here and generated separately when the request
    // is sent from SDTStream::TransmitFrame

    // NS_NET_STATUS_WAITING_FOR:
    // Created by nsHttpConnection when the request has been totally sent.
    // There is no good way to map it to the right transaction in http/2,
    // so it is ignored here and generated separately when the same
    // condition is complete in SDTStream when there is no more
    // request body left to be transmitted.

    // NS_NET_STATUS_RECEIVING_FROM
    // Generated in session whenever we read a data frame or a HEADERS
    // that can be attributed to a particular stream/transaction

    break;
  }
}

// ReadSegments() is used to write data to the network. Generally, HTTP
// request data is pulled from the approriate transaction and
// converted to http/2 data. Sometimes control data like window-update are
// generated instead.

nsresult
SDTSession::ReadSegmentsAgain(nsAHttpSegmentReader *reader,
                                uint32_t count, uint32_t *countRead, bool *again)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  MOZ_ASSERT(!mSegmentReader || !reader || (mSegmentReader == reader),
             "Inconsistent Write Function Callback");

  nsresult rv = ConfirmTLSProfile();
  if (NS_FAILED(rv)) {
    if (mGoAwayReason == INADEQUATE_SECURITY) {
      LOG3(("SDTSession::ReadSegments %p returning INADEQUATE_SECURITY %x",
            this, NS_ERROR_NET_INADEQUATE_SECURITY));
      rv = NS_ERROR_NET_INADEQUATE_SECURITY;
    }
    return rv;
  }

  if (reader)
    mSegmentReader = reader;

  *countRead = 0;

  LOG3(("SDTSession::ReadSegments %p", this));

  SDTStream *stream = static_cast<SDTStream *>(mReadyForWrite.PopFront());
  if (!stream) {
    LOG3(("SDTSession %p could not identify a stream to write; suspending.",
          this));
    FlushOutputQueue();
    SetWriteCallbacks();
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  LOG3(("SDTSession %p will write from SDTStream %p 0x%X "
        "block-input=%d block-output=%d\n", this, stream, stream->StreamID(),
        stream->RequestBlockedOnRead(), stream->BlockedOnRwin()));

  rv = stream->ReadSegments(this, count, countRead);

  // Not every permutation of stream->ReadSegents produces data (and therefore
  // tries to flush the output queue) - SENDING_FIN_STREAM can be an example
  // of that. But we might still have old data buffered that would be good
  // to flush.
  FlushOutputQueue();

  // Allow new server reads - that might be data or control information
  // (e.g. window updates or http replies) that are responses to these writes
  ResumeRecv();

  if (stream->RequestBlockedOnRead()) {

    // We are blocked waiting for input - either more http headers or
    // any request body data. When more data from the request stream
    // becomes available the httptransaction will call conn->ResumeSend().

    LOG3(("SDTSession::ReadSegments %p dealing with block on read", this));

    // call readsegments again if there are other streams ready
    // to run in this session
    if (GetWriteQueueSize()) {
      rv = NS_OK;
    } else {
      rv = NS_BASE_STREAM_WOULD_BLOCK;
    }
    SetWriteCallbacks();
    return rv;
  }

  if (NS_FAILED(rv)) {
    LOG3(("SDTSession::ReadSegments %p may return FAIL code %X",
          this, rv));
    if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
      return rv;
    }

    CleanupStream(stream, rv, CANCEL_ERROR);
    if (SoftStreamError(rv)) {
      LOG3(("SDTSession::ReadSegments %p soft error override\n", this));
      *again = false;
      SetWriteCallbacks();
      rv = NS_OK;
    }
    return rv;
  }

  if (*countRead > 0) {
    LOG3(("SDTSession::ReadSegments %p stream=%p countread=%d",
          this, stream, *countRead));
    mReadyForWrite.Push(stream);
    SetWriteCallbacks();
    return rv;
  }

  if (stream->BlockedOnRwin()) {
    LOG3(("SDTSession %p will stream %p 0x%X suspended for flow control\n",
          this, stream, stream->StreamID()));
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  LOG3(("SDTSession::ReadSegments %p stream=%p stream send complete",
        this, stream));

  // call readsegments again if there are other streams ready
  // to go in this session
  SetWriteCallbacks();

  return rv;
}

nsresult
SDTSession::ReadSegments(nsAHttpSegmentReader *reader,
                         uint32_t count, uint32_t *countRead)
{
  bool again = false;
  return ReadSegmentsAgain(reader, count, countRead, &again);
}

// WriteSegments() is used to read data off the socket. Generally this is
// just the http2 frame header and from there the appropriate *Stream
// is identified from the Stream-ID. The http transaction associated with
// that read then pulls in the data directly, which it will feed to
// OnWriteSegment(). That function will gateway it into http and feed
// it to the appropriate transaction.

// we call writer->OnWriteSegment via NetworkRead() to get a http2 header..
// and decide if it is data or control.. if it is control, just deal with it.
// if it is data, identify the stream
// call stream->WriteSegments which can call this::OnWriteSegment to get the
// data. It always gets full frames if they are part of the stream

nsresult
SDTSession::WriteSegmentsAgain(nsAHttpSegmentWriter *writer,
                               uint32_t count, uint32_t *countWritten,
                                 bool *again)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  LOG3(("SDTSession::WriteSegments %p InternalState %X\n",
        this, mDownstreamState));

  *countWritten = 0;

  if (mClosed)
    return NS_ERROR_FAILURE;

  nsresult rv = ConfirmTLSProfile();
  if (NS_FAILED(rv))
    return rv;

  SetWriteCallbacks();

  // If there are http transactions attached to a push stream with filled buffers
  // trigger that data pump here. This only reads from buffers (not the network)
  // so mDownstreamState doesn't matter.
//  SDTStream *pushConnectedStream =
//    static_cast<SDTStream *>(mPushesReadyForRead.PopFront());
//  if (pushConnectedStream) {
//    return ProcessConnectedPush(pushConnectedStream, writer, count, countWritten);
//  }

  // The BUFFERING_OPENING_SETTINGS state is just like any BUFFERING_FRAME_HEADER
  // except the only frame type it will allow is SETTINGS

  nsTArray<uint32_t> streamsReady;
  nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
  MOZ_ASSERT(sock);
  sock->GetStreamsReadyToRead(streamsReady);

  for (uint32_t i = 0; i < streamsReady.Length(); i++) {
    if (streamsReady[i] == 3) {
      rv = ReadControlStream(writer, count, countWritten, again);
    } else {
      rv = ReadStream(streamsReady[i], writer, count, countWritten, again);
    }
    if (rv != NS_BASE_STREAM_WOULD_BLOCK) {
      return rv;
    }
  }
  return NS_OK;
}

nsresult
SDTSession::ReadControlStream(nsAHttpSegmentWriter *writer,
                              uint32_t count, uint32_t *countWritten,
                              bool *again)
{
  if (mDownstreamState == BUFFERING_OPENING_SETTINGS ||
      mDownstreamState == BUFFERING_FRAME_HEADER) {

    MOZ_ASSERT(mInputFrameBufferUsed < kFrameHeaderBytes,
               "Frame Buffer Used Too Large for State");

    nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
    MOZ_ASSERT(sock);
    int32_t sdtStatus;
    sock->SetNextStreamToRead(3, &sdtStatus);
    MOZ_ASSERT(sdtStatus == SDTE_OK);

    nsresult rv = NetworkRead(writer,
                              &mInputFrameBuffer[mInputFrameBufferUsed],
                              kFrameHeaderBytes - mInputFrameBufferUsed,
                              countWritten);

    sock->SetNextStreamToRead(0, &sdtStatus);
    MOZ_ASSERT(sdtStatus == SDTE_OK);

    if (NS_FAILED(rv)) {
      LOG3(("Http2Session %p buffering frame header read failure %" PRIx32 "\n",
            this, static_cast<uint32_t>(rv)));
      return rv;
    }

    mInputFrameBufferUsed += *countWritten;

    if (mInputFrameBufferUsed < kFrameHeaderBytes)
    {
      LOG3(("Http2Session::WriteSegments %p "
            "BUFFERING FRAME HEADER incomplete size=%d",
            this, mInputFrameBufferUsed));
      return rv;
    }

    // 3 bytes of length, 1 type byte, 1 flag byte, 1 unused bit, 31 bits of ID
    uint8_t totallyWastedByte = mInputFrameBuffer.get()[0];
    mInputFrameDataSize = NetworkEndian::readUint16(
        mInputFrameBuffer.get() + 1);
    if (totallyWastedByte || (mInputFrameDataSize > kMaxFrameData)) {
      LOG3(("Got frame too large 0x%02X%04X", totallyWastedByte, mInputFrameDataSize));
      RETURN_SESSION_ERROR(this, PROTOCOL_ERROR);
    }

    mInputFrameType = *reinterpret_cast<uint8_t *>(mInputFrameBuffer.get() + kFrameLengthBytes);
    mInputFrameFlags = *reinterpret_cast<uint8_t *>(mInputFrameBuffer.get() + kFrameLengthBytes + kFrameTypeBytes);
    mInputFrameID = NetworkEndian::readUint32(
        mInputFrameBuffer.get() + kFrameLengthBytes + kFrameTypeBytes + kFrameFlagBytes);
    mInputFrameID &= 0x7fffffff;
    mInputFrameDataRead = 0;

    LOG3(("SDTSession::WriteSegments[%p::%x] Frame Header Read "
          "type %X data len %u flags %x id 0x%X",
          this, mSerial, mInputFrameType, mInputFrameDataSize, mInputFrameFlags,
          mInputFrameID));

    // if mExpectedHeaderID is non 0, it means this frame must be a CONTINUATION of
    // a HEADERS frame with a matching ID (section 6.2)
    if (mExpectedHeaderID &&
        ((mInputFrameType != FRAME_TYPE_CONTINUATION) ||
         (mExpectedHeaderID != mInputFrameID))) {
      LOG3(("Expected CONINUATION OF HEADERS for ID 0x%X\n", mExpectedHeaderID));
      RETURN_SESSION_ERROR(this, PROTOCOL_ERROR);
    }

    // if mExpectedPushPromiseID is non 0, it means this frame must be a
    // CONTINUATION of a PUSH_PROMISE with a matching ID (section 6.2)
    if (mExpectedPushPromiseID &&
        ((mInputFrameType != FRAME_TYPE_CONTINUATION) ||
         (mExpectedPushPromiseID != mInputFrameID))) {
      LOG3(("Expected CONTINUATION of PUSH PROMISE for ID 0x%X\n",
            mExpectedPushPromiseID));
      RETURN_SESSION_ERROR(this, PROTOCOL_ERROR);
    }

    if (mDownstreamState == BUFFERING_OPENING_SETTINGS &&
        mInputFrameType != FRAME_TYPE_SETTINGS) {
      LOG3(("First Frame Type Must Be Settings\n"));
      RETURN_SESSION_ERROR(this, PROTOCOL_ERROR);
    }

    EnsureBuffer(mInputFrameBuffer, mInputFrameDataSize + kFrameHeaderBytes,
                 kFrameHeaderBytes, mInputFrameBufferSize);
    ChangeDownstreamState(BUFFERING_CONTROL_FRAME);
  }

  if (mDownstreamState == PROCESSING_COMPLETE_HEADERS) {

    // The cleanup stream should only be set while stream->WriteSegments is
    // on the stack and then cleaned up in this code block afterwards.
    MOZ_ASSERT(!mNeedsCleanup, "cleanup stream set unexpectedly");
    mNeedsCleanup = nullptr;                     /* just in case */

    uint32_t streamID = mInputFrameDataStream->StreamID();
    mSegmentWriter = writer;
    nsresult rv = mInputFrameDataStream->WriteSegments(this, count,
                                                       countWritten);
    mSegmentWriter = nullptr;

    mLastDataReadEpoch = mLastReadEpoch;

    if (SoftStreamError(rv)) {
      // This will happen when the transaction figures out it is EOF, generally
      // due to a content-length match being made. Return OK from this function
      // otherwise the whole session would be torn down.

      // if we were doing PROCESSING_COMPLETE_HEADERS need to pop the state
      // back to BUFFERING_FRAME_HEADER where we came from
//TODO !!!!!!
      mDownstreamState = BUFFERING_FRAME_HEADER;

      if (mInputFrameDataRead == mInputFrameDataSize)
        ResetDownstreamState();
      LOG3(("SDTSession::WriteSegments session=%p id 0x%X "
            "needscleanup=%p. cleanup stream based on "
            "stream->writeSegments returning code %x\n",
            this, streamID, mNeedsCleanup, rv));
      MOZ_ASSERT(!mNeedsCleanup || mNeedsCleanup->StreamID() == streamID);
      CleanupStream(streamID, NS_OK, CANCEL_ERROR);
      mNeedsCleanup = nullptr;
      *again = false;
      ResumeRecv();
      return NS_OK;
    }

    if (mNeedsCleanup) {
      LOG3(("SDTSession::WriteSegments session=%p stream=%p 0x%X "
            "cleanup stream based on mNeedsCleanup.\n",
            this, mNeedsCleanup, mNeedsCleanup ? mNeedsCleanup->StreamID() : 0));
      CleanupStream(mNeedsCleanup, NS_OK, CANCEL_ERROR);
      mNeedsCleanup = nullptr;
    }

    if (NS_FAILED(rv)) {
      LOG3(("SDTSession %p data frame read failure %x\n", this, rv));
      // maybe just blocked reading from network
      if (rv == NS_BASE_STREAM_WOULD_BLOCK)
        rv = NS_OK;
    }

    return rv;
  }

  if (mDownstreamState != BUFFERING_CONTROL_FRAME) {
    MOZ_ASSERT(false); // this cannot happen
    return NS_ERROR_UNEXPECTED;
  }

  MOZ_ASSERT(mInputFrameBufferUsed == kFrameHeaderBytes, "Frame Buffer Header Not Present");
  MOZ_ASSERT(mInputFrameDataSize + kFrameHeaderBytes <= mInputFrameBufferSize,
             "allocation for control frame insufficient");

  nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
  MOZ_ASSERT(sock);
  int32_t sdtStatus;
  sock->SetNextStreamToRead(3, &sdtStatus);
  MOZ_ASSERT(sdtStatus == SDTE_OK);
  nsresult rv = NetworkRead(writer,
                            &mInputFrameBuffer[kFrameHeaderBytes + mInputFrameDataRead],
                            mInputFrameDataSize - mInputFrameDataRead,
                            countWritten);
  sock->SetNextStreamToRead(0, &sdtStatus);
  MOZ_ASSERT(sdtStatus == SDTE_OK);

  if (NS_FAILED(rv)) {
    LOG3(("SDTSession %p buffering control frame read failure %x\n",
          this, rv));
    // maybe just blocked reading from network
    if (rv == NS_BASE_STREAM_WOULD_BLOCK)
      rv = NS_OK;
    return rv;
  }

  LogIO(this, nullptr, "Reading Control Frame",
        &mInputFrameBuffer[kFrameHeaderBytes + mInputFrameDataRead], *countWritten);

  mInputFrameDataRead += *countWritten;

  if (mInputFrameDataRead != mInputFrameDataSize)
    return NS_OK;

  if (mInputFrameType < FRAME_TYPE_LAST) {
    rv = sControlFunctions[mInputFrameType](this);
  } else {
    // Section 4.1 requires this to be ignored; though protocol_error would
    // be better
    LOG3(("SDTSession %p unknown frame type %x ignored\n",
          this, mInputFrameType));
    ResetDownstreamState();
    rv = NS_OK;
  }

  MOZ_ASSERT(NS_FAILED(rv) ||
             mDownstreamState != BUFFERING_CONTROL_FRAME,
             "Control Handler returned OK but did not change state");

  if (mShouldGoAway && !mStreamTransactionHash.Count())
    Close(NS_OK);
  return rv;
}

nsresult
SDTSession::ReadStream(uint32_t streamID, nsAHttpSegmentWriter *writer,
                       uint32_t count, uint32_t *countWritten, bool *again)
{
  SDTStream *stream = mStreamIDHash.Get(streamID);
  if (!VerifyStream(stream, streamID)) {
    LOG3(("Http2Session::ReadStream failed to verify 0x%X\n",
          streamID));
    nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
    MOZ_ASSERT(sock);
    sock->ResetStream(streamID);
    return NS_ERROR_UNEXPECTED;
  }

  mReadStreamData = stream;
  mSegmentWriter = writer;
  nsresult rv = stream->WriteSegments(this, count, countWritten);
  mSegmentWriter = nullptr;
  mReadStreamData = nullptr;
  mLastDataReadEpoch = mLastReadEpoch;

  if (SoftStreamError(rv)) {
    // This will happen when the transaction figures out it is EOF, generally
    // due to a content-length match being made. Return OK from this function
    // otherwise the whole session would be torn down.
    CleanupStream(streamID, NS_OK, CANCEL_ERROR);
    mNeedsCleanup = nullptr;
    *again = false;
    rv = ResumeRecv();
    if (NS_FAILED(rv)) {
      LOG3(("ResumeRecv returned code %x", static_cast<uint32_t>(rv)));
    }
    return NS_OK;
  }

  if (mNeedsCleanup) {
    LOG3(("SDTSession::ReadStream session=%p stream=%p 0x%X "
          "cleanup stream based on mNeedsCleanup.\n",
          this, mNeedsCleanup, mNeedsCleanup ? mNeedsCleanup->StreamID() : 0));
    CleanupStream(mNeedsCleanup, NS_OK, CANCEL_ERROR);
    mNeedsCleanup = nullptr;
  }

  if (NS_FAILED(rv)) {
    LOG3(("SDTSession %p data frame read failure %x\n", this, rv));
    // maybe just blocked reading from network
    if (rv == NS_BASE_STREAM_WOULD_BLOCK)
      rv = NS_OK;
  }

  return rv;
}

void
SDTSession::ResetStream()
{
  nsresult streamCleanupCode;

  // There is no bounds checking on the error code.. we provide special
  // handling for a couple of cases and all others (including unknown) are
  // equivalent to cancel.
  if (mDownstreamRstReason == REFUSED_STREAM_ERROR) {
    streamCleanupCode = NS_ERROR_NET_RESET;      // can retry this 100% safely
    mInputFrameDataStream->Transaction()->ReuseConnectionOnRestartOK(true);
  } else if (mDownstreamRstReason == HTTP_1_1_REQUIRED) {
    streamCleanupCode = NS_ERROR_NET_RESET;
    mInputFrameDataStream->Transaction()->ReuseConnectionOnRestartOK(true);
    mInputFrameDataStream->Transaction()->DisableSpdy();
  } else {
    streamCleanupCode = mInputFrameDataStream->RecvdData() ?
      NS_ERROR_NET_PARTIAL_TRANSFER :
      NS_ERROR_NET_INTERRUPT;
  }

  if (mDownstreamRstReason == COMPRESSION_ERROR) {
    mShouldGoAway = true;
  }

  // mInputFrameDataStream is reset by ChangeDownstreamState
  SDTStream *stream = mInputFrameDataStream;
  ResetDownstreamState();
  LOG3(("SDTSession::WriteSegments cleanup stream on recv of rst "
        "session=%p stream=%p 0x%X\n", this, stream,
        stream ? stream->StreamID() : 0));
  CleanupStream(stream, streamCleanupCode, CANCEL_ERROR);
}

nsresult
SDTSession::WriteSegments(nsAHttpSegmentWriter *writer,
                            uint32_t count, uint32_t *countWritten)
{
  bool again = false;
  return WriteSegmentsAgain(writer, count, countWritten, &again);
}
/*
nsresult
SDTSession::ProcessConnectedPush(SDTStream *pushConnectedStream,
                                 nsAHttpSegmentWriter * writer,
                                 uint32_t count, uint32_t *countWritten)
{
  LOG3(("SDTSession::ProcessConnectedPush %p 0x%X\n",
        this, pushConnectedStream->StreamID()));
  mSegmentWriter = writer;
  nsresult rv = pushConnectedStream->WriteSegments(this, count, countWritten);
  mSegmentWriter = nullptr;

  // The pipe in nsHttpTransaction rewrites CLOSED error codes into OK
  // so we need this check to determine the truth.
  if (NS_SUCCEEDED(rv) && !*countWritten &&
      pushConnectedStream->PushSource() &&
      pushConnectedStream->PushSource()->GetPushComplete()) {
    rv = NS_BASE_STREAM_CLOSED;
  }

  if (rv == NS_BASE_STREAM_CLOSED) {
    CleanupStream(pushConnectedStream, NS_OK, CANCEL_ERROR);
    rv = NS_OK;
  }

  // if we return OK to nsHttpConnection it will use mSocketInCondition
  // to determine whether to schedule more reads, incorrectly
  // assuming that nsHttpConnection::OnSocketWrite() was called.
  if (NS_SUCCEEDED(rv) || rv == NS_BASE_STREAM_WOULD_BLOCK) {
    rv = NS_BASE_STREAM_WOULD_BLOCK;
    ResumeRecv();
  }
  return rv;
}
*/
void
SDTSession::Close(nsresult aReason)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  if (mClosed)
    return;

  LOG3(("SDTSession::Close %p %X", this, aReason));

  mClosed = true;

  Shutdown();

  mStreamIDHash.Clear();
  mStreamTransactionHash.Clear();

  uint32_t goAwayReason;
  if (mGoAwayReason != NO_HTTP_ERROR) {
    goAwayReason = mGoAwayReason;
  } else if (NS_SUCCEEDED(aReason)) {
    goAwayReason = NO_HTTP_ERROR;
  } else if (aReason == NS_ERROR_ILLEGAL_VALUE) {
    goAwayReason = PROTOCOL_ERROR;
  } else {
    goAwayReason = INTERNAL_ERROR;
  }
//TODO!!!
  //GenerateGoAway(goAwayReason);
  mConnection = nullptr;
  mSegmentReader = nullptr;
  mSegmentWriter = nullptr;
}

nsHttpConnectionInfo *
SDTSession::ConnectionInfo()
{
  RefPtr<nsHttpConnectionInfo> ci;
  GetConnectionInfo(getter_AddRefs(ci));
  return ci.get();
}

void
SDTSession::CloseTransaction(nsAHttpTransaction *aTransaction,
                               nsresult aResult)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::CloseTransaction %p %p %x", this, aTransaction, aResult));

  // Generally this arrives as a cancel event from the connection manager.

  // need to find the stream and call CleanupStream() on it.
  SDTStream *stream = mStreamTransactionHash.Get(aTransaction);
  if (!stream) {
    LOG3(("SDTSession::CloseTransaction %p %p %x - not found.",
          this, aTransaction, aResult));
    return;
  }
  LOG3(("SDTSession::CloseTransaction probably a cancel. "
        "this=%p, trans=%p, result=%x, streamID=0x%X stream=%p",
        this, aTransaction, aResult, stream->StreamID(), stream));
  CleanupStream(stream, aResult, CANCEL_ERROR);
  ResumeRecv();
}

//-----------------------------------------------------------------------------
// nsAHttpSegmentReader
//-----------------------------------------------------------------------------

nsresult
SDTSession::OnReadSegment(const char *buf,
                            uint32_t count, uint32_t *countRead)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsresult rv;

  // If we can release old queued data then we can try and write the new
  // data directly to the network without using the output queue at all
  if (mOutputQueueUsed)
    FlushOutputQueue();

  if (!mOutputQueueUsed && mSegmentReader) {
    // try and write directly without output queue
    rv = mSegmentReader->OnReadSegment(buf, count, countRead);

    if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
      *countRead = 0;
    } else if (NS_FAILED(rv)) {
      return rv;
    }

    if (*countRead < count) {
      uint32_t required = count - *countRead;
      // assuming a commitment() happened, this ensurebuffer is a nop
      // but just in case the queuesize is too small for the required data
      // call ensurebuffer().
      EnsureBuffer(mOutputQueueBuffer, required, 0, mOutputQueueSize);
      memcpy(mOutputQueueBuffer.get(), buf + *countRead, required);
      mOutputQueueUsed = required;
    }

    *countRead = count;
    return NS_OK;
  }

  // At this point we are going to buffer the new data in the output
  // queue if it fits. By coalescing multiple small submissions into one larger
  // buffer we can get larger writes out to the network later on.

  // This routine should not be allowed to fill up the output queue
  // all on its own - at least kQueueReserved bytes are always left
  // for other routines to use - but this is an all-or-nothing function,
  // so if it will not all fit just return WOULD_BLOCK

  if ((mOutputQueueUsed + count) > (mOutputQueueSize - kQueueReserved))
    return NS_BASE_STREAM_WOULD_BLOCK;

  memcpy(mOutputQueueBuffer.get() + mOutputQueueUsed, buf, count);
  mOutputQueueUsed += count;
  *countRead = count;

  FlushOutputQueue();

  return NS_OK;
}

nsresult
SDTSession::CommitToSegmentSize(uint32_t count, bool forceCommitment)
{
  if (mOutputQueueUsed)
    FlushOutputQueue();

  // would there be enough room to buffer this if needed?
  if ((mOutputQueueUsed + count) <= (mOutputQueueSize - kQueueReserved))
    return NS_OK;

  // if we are using part of our buffers already, try again later unless
  // forceCommitment is set.
  if (mOutputQueueUsed && !forceCommitment)
    return NS_BASE_STREAM_WOULD_BLOCK;

  if (mOutputQueueUsed) {
    // normally we avoid the memmove of RealignOutputQueue, but we'll try
    // it if forceCommitment is set before growing the buffer.
    RealignOutputQueue();

    // is there enough room now?
    if ((mOutputQueueUsed + count) <= (mOutputQueueSize - kQueueReserved))
      return NS_OK;
  }

  // resize the buffers as needed
  EnsureOutputBuffer(count + kQueueReserved);

  MOZ_ASSERT((mOutputQueueUsed + count) <= (mOutputQueueSize - kQueueReserved),
             "buffer not as large as expected");

  return NS_OK;
}

//-----------------------------------------------------------------------------
// nsAHttpSegmentWriter
//-----------------------------------------------------------------------------

nsresult
SDTSession::OnWriteSegment(char *buf,
                           uint32_t count, uint32_t *countWritten)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsresult rv;

  if (!mSegmentWriter) {
    // the only way this could happen would be if Close() were called on the
    // stack with WriteSegments()
    return NS_ERROR_FAILURE;
  }

  if (!mReadStreamData) {
    if (mDownstreamState == BUFFERING_FRAME_HEADER) {
      return NS_BASE_STREAM_WOULD_BLOCK;
    } else if (mDownstreamState == PROCESSING_COMPLETE_HEADERS) {

      count = std::min(count,
                       mFlatHTTPResponseHeaders.Length() -
                       mFlatHTTPResponseHeadersOut);
      memcpy(buf,
             mFlatHTTPResponseHeaders.get() + mFlatHTTPResponseHeadersOut,
             count);
      mFlatHTTPResponseHeadersOut += count;
      *countWritten = count;

      if (mFlatHTTPResponseHeaders.Length() == mFlatHTTPResponseHeadersOut) {
        ResetDownstreamState();
      }

      return NS_OK;
    }
  } else {
    nsCOMPtr<nsISocketTransportSDT> sock = do_QueryInterface(mSocketTransport);
    MOZ_ASSERT(sock);
    int32_t sdtStatus;
    sock->SetNextStreamToRead(mReadStreamData->StreamID(), &sdtStatus);
    if (sdtStatus == SDT_STREAM_FIN) {
      LOG3(("SDTSession::ReadStream session=%p stream=%p 0x%X "
            "cleanup stream based on mNeedsCleanup.\n",
            this, mReadStreamData, mReadStreamData->StreamID()));
      SetNeedsCleanup(mReadStreamData);
      mReadStreamData->SetResponseIsComplete();
      return NS_BASE_STREAM_CLOSED;
    } else if (sdtStatus == SDT_STREAM_RST) {
      mReadStreamData->SetRecvdReset(true);
      return NS_OK;
    }
    MOZ_ASSERT(sdtStatus == SDTE_OK);
    rv = NetworkRead(mSegmentWriter, buf, count, countWritten);
    sock->SetNextStreamToRead(0, &sdtStatus);
    MOZ_ASSERT(sdtStatus == SDTE_OK);
    if (NS_FAILED(rv))
      return rv;

    LogIO(this, mInputFrameDataStream, "Reading Data Frame",
          buf, *countWritten);

    mInputFrameDataStream->UpdateTransportReadEvents(*countWritten);

    return rv;
  }

  return NS_OK;
}

void
SDTSession::SetNeedsCleanup(SDTStream *stream)
{
  LOG3(("SDTSession::SetNeedsCleanup %p - recorded downstream fin of "
        "stream %p 0x%X", this, stream, stream->StreamID()));

  // This will result in Close() being called
  MOZ_ASSERT(!mNeedsCleanup, "mNeedsCleanup unexpectedly set");
  stream->SetResponseIsComplete();
  mNeedsCleanup = stream;
}

uint32_t
SDTSession::FindTunnelCount(nsHttpConnectionInfo *aConnInfo)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  uint32_t rv = 0;
  mTunnelHash.Get(aConnInfo->HashKey(), &rv);
  return rv;
}

void
SDTSession::RegisterTunnel(SDTStream *aTunnel)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsHttpConnectionInfo *ci = aTunnel->Transaction()->ConnectionInfo();
  uint32_t newcount = FindTunnelCount(ci) + 1;
  mTunnelHash.Remove(ci->HashKey());
  mTunnelHash.Put(ci->HashKey(), newcount);
  LOG3(("SDTStream::RegisterTunnel %p stream=%p tunnels=%d [%s]",
        this, aTunnel, newcount, ci->HashKey().get()));
}

void
SDTSession::UnRegisterTunnel(SDTStream *aTunnel)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsHttpConnectionInfo *ci = aTunnel->Transaction()->ConnectionInfo();
  MOZ_ASSERT(FindTunnelCount(ci));
  uint32_t newcount = FindTunnelCount(ci) - 1;
  mTunnelHash.Remove(ci->HashKey());
  if (newcount) {
    mTunnelHash.Put(ci->HashKey(), newcount);
  }
  LOG3(("SDTSession::UnRegisterTunnel %p stream=%p tunnels=%d [%s]",
        this, aTunnel, newcount, ci->HashKey().get()));
}

void
SDTSession::CreateTunnel(nsHttpTransaction *trans,
                         nsHttpConnectionInfo *ci,
                         nsIInterfaceRequestor *aCallbacks)
{
  LOG(("SDTSession::CreateTunnel %p %p make new tunnel\n", this, trans));
  // The connect transaction will hold onto the underlying http
  // transaction so that an auth created by the connect can be mappped
  // to the correct security callbacks

  RefPtr<SpdyConnectTransaction> connectTrans =
    new SpdyConnectTransaction(ci, aCallbacks, trans->Caps(), trans, this);
  AddStream(connectTrans, nsISupportsPriority::PRIORITY_NORMAL, false, nullptr);
  SDTStream *tunnel = mStreamTransactionHash.Get(connectTrans);
  MOZ_ASSERT(tunnel);
  RegisterTunnel(tunnel);
}

void
SDTSession::DispatchOnTunnel(nsAHttpTransaction *aHttpTransaction,
                             nsIInterfaceRequestor *aCallbacks)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsHttpTransaction *trans = aHttpTransaction->QueryHttpTransaction();
  nsHttpConnectionInfo *ci = aHttpTransaction->ConnectionInfo();
  MOZ_ASSERT(trans);

  LOG3(("SDTSession::DispatchOnTunnel %p trans=%p", this, trans));

  aHttpTransaction->SetConnection(nullptr);

  // this transaction has done its work of setting up a tunnel, let
  // the connection manager queue it if necessary
  trans->SetTunnelProvider(this);
  trans->EnableKeepAlive();

  if (FindTunnelCount(ci) < gHttpHandler->MaxConnectionsPerOrigin()) {
    LOG3(("SDTSession::DispatchOnTunnel %p create on new tunnel %s",
          this, ci->HashKey().get()));
    CreateTunnel(trans, ci, aCallbacks);
  } else {
    // requeue it. The connection manager is responsible for actually putting
    // this on the tunnel connection with the specific ci. If that can't
    // happen the cmgr checks with us via MaybeReTunnel() to see if it should
    // make a new tunnel or just wait longer.
    LOG3(("SDTSession::DispatchOnTunnel %p trans=%p queue in connection manager",
          this, trans));
    gHttpHandler->InitiateTransaction(trans, trans->Priority());
  }
}

// From ASpdySession

void
SDTSession::SendPing()
{
}

bool
SDTSession::MaybeReTunnel(nsAHttpTransaction *aHttpTransaction)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  nsHttpTransaction *trans = aHttpTransaction->QueryHttpTransaction();
  LOG(("SDTSession::MaybeReTunnel %p trans=%p\n", this, trans));
  if (!trans || trans->TunnelProvider() != this) {
    // this isn't really one of our transactions.
    return false;
  }

  if (mClosed || mShouldGoAway) {
    LOG(("SDTSession::MaybeReTunnel %p %p session closed - requeue\n", this, trans));
    trans->SetTunnelProvider(nullptr);
    gHttpHandler->InitiateTransaction(trans, trans->Priority());
    return true;
  }

  nsHttpConnectionInfo *ci = aHttpTransaction->ConnectionInfo();
  LOG(("SDTSession:MaybeReTunnel %p %p count=%d limit %d\n",
       this, trans, FindTunnelCount(ci), gHttpHandler->MaxConnectionsPerOrigin()));
  if (FindTunnelCount(ci) >= gHttpHandler->MaxConnectionsPerOrigin()) {
    // patience - a tunnel will open up.
    return false;
  }

  LOG(("SDTSession::MaybeReTunnel %p %p make new tunnel\n", this, trans));
  CreateTunnel(trans, ci, trans->SecurityCallbacks());
  return true;
}

nsresult
SDTSession::BufferOutput(const char *buf,
                         uint32_t count,
                         uint32_t *countRead)
{
  nsAHttpSegmentReader *old = mSegmentReader;
  mSegmentReader = nullptr;
  nsresult rv = OnReadSegment(buf, count, countRead);
  mSegmentReader = old;
  return rv;
}

bool // static
SDTSession::ALPNCallback(nsISupports *securityInfo)
{
  if (!gHttpHandler->IsH2MandatorySuiteEnabled()) {
    LOG3(("SDTSession::ALPNCallback Mandatory Cipher Suite Unavailable\n"));
    return false;
  }

  nsCOMPtr<nsISSLSocketControl> ssl = do_QueryInterface(securityInfo);
  LOG3(("SDTSession::ALPNCallback sslsocketcontrol=%p\n", ssl.get()));
  if (ssl) {
    int16_t version = ssl->GetSSLVersionOffered();
    LOG3(("SDTSession::ALPNCallback version=%x\n", version));
    if (version >= nsISSLSocketControl::TLS_VERSION_1_2) {
      return true;
    }
  }
  return false;
}

nsresult
SDTSession::ConfirmTLSProfile()
{
  if (mTLSProfileConfirmed)
    return NS_OK;

  LOG3(("SDTSession::ConfirmTLSProfile %p mConnection=%p\n",
        this, mConnection.get()));

  if (!gHttpHandler->EnforceHttp2TlsProfile()) {
    LOG3(("SDTSession::ConfirmTLSProfile %p passed due to configuration bypass\n", this));
    mTLSProfileConfirmed = true;
    return NS_OK;
  }

  if (!mConnection)
    return NS_ERROR_FAILURE;

  nsCOMPtr<nsISupports> securityInfo;
  mConnection->GetSecurityInfo(getter_AddRefs(securityInfo));
  nsCOMPtr<nsISSLSocketControl> ssl = do_QueryInterface(securityInfo);
  LOG3(("SDTSession::ConfirmTLSProfile %p sslsocketcontrol=%p\n", this, ssl.get()));
  if (!ssl)
    return NS_ERROR_FAILURE;

  int16_t version = ssl->GetSSLVersionUsed();
  LOG3(("SDTSession::ConfirmTLSProfile %p version=%x\n", this, version));
  if (version < nsISSLSocketControl::TLS_VERSION_1_2) {
    LOG3(("SDTSession::ConfirmTLSProfile %p FAILED due to lack of TLS1.2\n", this));
    RETURN_SESSION_ERROR(this, INADEQUATE_SECURITY);
  }

  uint16_t kea = ssl->GetKEAUsed();
  if (kea != ssl_kea_dh && kea != ssl_kea_ecdh) {
    LOG3(("SDTSession::ConfirmTLSProfile %p FAILED due to invalid KEA %d\n",
          this, kea));
    RETURN_SESSION_ERROR(this, INADEQUATE_SECURITY);
  }

  uint32_t keybits = ssl->GetKEAKeyBits();
  if (kea == ssl_kea_dh && keybits < 2048) {
    LOG3(("SDTSession::ConfirmTLSProfile %p FAILED due to DH %d < 2048\n",
          this, keybits));
    RETURN_SESSION_ERROR(this, INADEQUATE_SECURITY);
  } else if (kea == ssl_kea_ecdh && keybits < 224) { // see rfc7540 9.2.1.
    LOG3(("SDTSession::ConfirmTLSProfile %p FAILED due to ECDH %d < 224\n",
          this, keybits));
    RETURN_SESSION_ERROR(this, INADEQUATE_SECURITY);
  }

  int16_t macAlgorithm = ssl->GetMACAlgorithmUsed();
  LOG3(("SDTSession::ConfirmTLSProfile %p MAC Algortihm (aead==6) %d\n",
        this, macAlgorithm));
  if (macAlgorithm != nsISSLSocketControl::SSL_MAC_AEAD) {
    LOG3(("SDTSession::ConfirmTLSProfile %p FAILED due to lack of AEAD\n", this));
    RETURN_SESSION_ERROR(this, INADEQUATE_SECURITY);
  }

  /* We are required to send SNI. We do that already, so no check is done
   * here to make sure we did. */

  /* We really should check to ensure TLS compression isn't enabled on
   * this connection. However, we never enable TLS compression on our end,
   * anyway, so it'll never be on. All the same, see https://bugzil.la/965881
   * for the possibility for an interface to ensure it never gets turned on. */

  mTLSProfileConfirmed = true;
  return NS_OK;
}


//-----------------------------------------------------------------------------
// Modified methods of nsAHttpConnection
//-----------------------------------------------------------------------------

void
SDTSession::TransactionHasDataToWrite(nsAHttpTransaction *caller)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::TransactionHasDataToWrite %p trans=%p", this, caller));

  // a trapped signal from the http transaction to the connection that
  // it is no longer blocked on read.

  SDTStream *stream = mStreamTransactionHash.Get(caller);
  if (!stream || !VerifyStream(stream)) {
    LOG3(("SDTSession::TransactionHasDataToWrite %p caller %p not found",
          this, caller));
    return;
  }

  LOG3(("SDTSession::TransactionHasDataToWrite %p ID is 0x%X\n",
        this, stream->StreamID()));

  if (!mClosed) {
    mReadyForWrite.Push(stream);
    SetWriteCallbacks();
  } else {
    LOG3(("SDTSession::TransactionHasDataToWrite %p closed so not setting Ready4Write\n",
          this));
  }

  // NSPR poll will not poll the network if there are non system PR_FileDesc's
  // that are ready - so we can get into a deadlock waiting for the system IO
  // to come back here if we don't force the send loop manually.
  ForceSend();
}

void
SDTSession::TransactionHasDataToRecv(nsAHttpTransaction *caller)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::TransactionHasDataToRecv %p trans=%p", this, caller));

  // a signal from the http transaction to the connection that it will consume more
  SDTStream *stream = mStreamTransactionHash.Get(caller);
  if (!stream || !VerifyStream(stream)) {
    LOG3(("SDTSession::TransactionHasDataToRecv %p caller %p not found",
          this, caller));
    return;
  }

  LOG3(("SDTSession::TransactionHasDataToRecv %p ID is 0x%X\n",
        this, stream->StreamID()));
}

void
SDTSession::TransactionHasDataToWrite(SDTStream *stream)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  LOG3(("SDTSession::TransactionHasDataToWrite %p stream=%p ID=0x%x",
        this, stream, stream->StreamID()));

  mReadyForWrite.Push(stream);
  SetWriteCallbacks();
  ForceSend();
}

bool
SDTSession::IsPersistent()
{
  return true;
}

nsresult
SDTSession::TakeTransport(nsISocketTransport **,
                          nsIAsyncInputStream **, nsIAsyncOutputStream **)
{
  MOZ_ASSERT(false, "TakeTransport of SDTSession");
  return NS_ERROR_UNEXPECTED;
}

already_AddRefed<nsHttpConnection>
SDTSession::TakeHttpConnection()
{
  MOZ_ASSERT(false, "TakeHttpConnection of SDTSession");
  return nullptr;
}

void
SDTSession::GetSecurityCallbacks(nsIInterfaceRequestor **aOut)
{
  *aOut = nullptr;
}

//-----------------------------------------------------------------------------
// unused methods of nsAHttpTransaction
// We can be sure of this because SDTSession is only constructed in
// nsHttpConnection and is never passed out of that object or a TLSFilterTransaction
// TLS tunnel
//-----------------------------------------------------------------------------

void
SDTSession::SetConnection(nsAHttpConnection *)
{
  // This is unexpected
  MOZ_ASSERT(false, "SDTSession::SetConnection()");
}

void
SDTSession::SetProxyConnectFailed()
{
  MOZ_ASSERT(false, "SDTSession::SetProxyConnectFailed()");
}

bool
SDTSession::IsDone()
{
  return !mStreamTransactionHash.Count();
}

nsresult
SDTSession::Status()
{
  MOZ_ASSERT(false, "SDTSession::Status()");
  return NS_ERROR_UNEXPECTED;
}

uint32_t
SDTSession::Caps()
{
  MOZ_ASSERT(false, "SDTSession::Caps()");
  return 0;
}

void
SDTSession::SetDNSWasRefreshed()
{
  MOZ_ASSERT(false, "SDTSession::SetDNSWasRefreshed()");
}

uint64_t
SDTSession::Available()
{
  MOZ_ASSERT(false, "SDTSession::Available()");
  return 0;
}

nsHttpRequestHead *
SDTSession::RequestHead()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(false,
             "SDTSession::RequestHead() "
             "should not be called after http/2 is setup");
  return NULL;
}

uint32_t
SDTSession::Http1xTransactionCount()
{
  return 0;
}

nsresult
SDTSession::TakeSubTransactions(
  nsTArray<RefPtr<nsAHttpTransaction> > &outTransactions)
{
  // Generally this cannot be done with http/2 as transactions are
  // started right away.

  LOG3(("SDTSession::TakeSubTransactions %p\n", this));

  LOG3(("   taking %d\n", mStreamTransactionHash.Count()));

  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    outTransactions.AppendElement(iter.Key());

    // Removing the stream from the hash will delete the stream and drop the
    // transaction reference the hash held.
    iter.Remove();
  }
  return NS_OK;
}

//-----------------------------------------------------------------------------
// Pass through methods of nsAHttpConnection
//-----------------------------------------------------------------------------

nsAHttpConnection *
SDTSession::Connection()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  return mConnection;
}

nsresult
SDTSession::OnHeadersAvailable(nsAHttpTransaction *transaction,
                               nsHttpRequestHead *requestHead,
                               nsHttpResponseHead *responseHead, bool *reset)
{
  return mConnection->OnHeadersAvailable(transaction,
                                         requestHead,
                                         responseHead,
                                         reset);
}

bool
SDTSession::IsReused()
{
  return mConnection->IsReused();
}

nsresult
SDTSession::PushBack(const char *buf, uint32_t len)
{
  return mConnection->PushBack(buf, len);
}

nsresult
SDTSession::SetNextStreamToWrite(uint32_t aStreamId, int32_t *aStatus)
{
  nsCOMPtr<nsISocketTransportSDT> trans = do_QueryInterface(mSocketTransport);
  return trans->SetNextStreamToWrite(aStreamId, aStatus);
}

nsresult
SDTSession::CloseStream(uint32_t aStreamId)
{
  nsCOMPtr<nsISocketTransportSDT> trans = do_QueryInterface(mSocketTransport);
  return trans->CloseStream(aStreamId);
}

bool
SDTSession::StreamCanWrite(uint32_t aStreamId)
{
  nsCOMPtr<nsISocketTransportSDT> trans = do_QueryInterface(mSocketTransport);
  bool canWrite;
  if (NS_FAILED(trans->StreamCanWrite(aStreamId, &canWrite))) {
    return false;
  }
  return canWrite;
}

void
SDTSession::ThrottleResponse(bool aThrottle)
{
  // Response throttling later
}
} // namespace net
} // namespace mozilla
