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

#include "Http2Compression.h"
#include "SDTSession.h"
#include "SDTStream.h"
//#include "Http2Push.h"
#include "TunnelUtils.h"

#include "mozilla/Telemetry.h"
#include "nsAlgorithm.h"
#include "nsHttp.h"
#include "nsHttpHandler.h"
#include "nsHttpRequestHead.h"
#include "nsIClassOfService.h"
#include "nsIPipe.h"
#include "nsISocketTransport.h"
#include "nsStandardURL.h"
#include "prnetdb.h"

namespace mozilla {
namespace net {

SDTStream::SDTStream(nsAHttpTransaction *httpTransaction,
                     SDTSession *session,
                     int32_t priority)
  : mStreamID(0)
  , mSession(session)
  , mSegmentReader(nullptr)
  , mSegmentWriter(nullptr)
  , mUpstreamState(GENERATING_HEADERS)
//  , mState(IDLE)
  , mRequestHeadersDone(0)
  , mOpenGenerated(0)
  , mAllHeadersReceived(0)
  , mQueued(0)
  , mTransaction(httpTransaction)
  , mSocketTransport(session->SocketTransport())
  , mRequestBlockedOnRead(0)
  , mRecvdFin(0)
  , mReceivedData(0)
  , mRecvdReset(0)
  , mSentReset(0)
  , mCountAsActive(0)
  , mSentFin(0)
  , mSentWaitingFor(0)
  , mSetTCPSocketBuffer(0)
  , mBypassInputBuffer(0)
  , mTxInlineFrameSize(SDTSession::kDefaultBufferSize)
  , mTxInlineFrameUsed(0)
  , mRequestBodyLenRemaining(0)
  , mBlockedOnRwin(false)
  , mTotalSent(0)
  , mTotalRead(0)
//  , mPushSource(nullptr)
  , mIsTunnel(false)
  , mPlainTextTunnel(false)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  LOG3(("SDTStream::SDTStream %p", this));

  mClientReceiveWindow = session->PushAllowance();

  mTxInlineFrame = MakeUnique<uint8_t[]>(mTxInlineFrameSize);

  static_assert(nsISupportsPriority::PRIORITY_LOWEST <= kNormalPriority,
                "Lowest Priority should be less than kNormalPriority");

  // values of priority closer to 0 are higher priority for the priority
  // argument. This value is used as a group, which maps to a
  // weight that is related to the nsISupportsPriority that we are given.
  int32_t httpPriority;
  if (priority >= nsISupportsPriority::PRIORITY_LOWEST) {
    httpPriority = kWorstPriority;
  } else if (priority <= nsISupportsPriority::PRIORITY_HIGHEST) {
    httpPriority = kBestPriority;
  } else {
    httpPriority = kNormalPriority + priority;
  }
  MOZ_ASSERT(httpPriority >= 0);
  SetPriority(static_cast<uint32_t>(httpPriority));
}

SDTStream::~SDTStream()
{
  ClearTransactionsBlockedOnTunnel();
  mStreamID = SDTSession::kDeadStreamID;
}

// ReadSegments() is used to write data down the socket. Generally, HTTP
// request data is pulled from the approriate transaction and
// converted to HTTP/2 data. Sometimes control data like a window-update is
// generated instead.

nsresult
SDTStream::ReadSegments(nsAHttpSegmentReader *reader,
                          uint32_t count,
                          uint32_t *countRead)
{
  LOG3(("SDTStream %p ReadSegments reader=%p count=%d state=%x",
        this, reader, count, mUpstreamState));

  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  nsresult rv = NS_ERROR_UNEXPECTED;
  mRequestBlockedOnRead = 0;

  if (mRecvdFin || mRecvdReset) {
    // Don't transmit any request frames if the peer cannot respond
    LOG3(("SDTStream %p ReadSegments request stream aborted due to"
          " response side closure\n", this));
    return NS_ERROR_ABORT;
  }

  switch (mUpstreamState) {
  case GENERATING_HEADERS:
  case SENDING_BODY:
    // Call into the HTTP Transaction to generate the HTTP request
    // stream. That stream will show up in OnReadSegment().
    mSegmentReader = reader;
    rv = mTransaction->ReadSegments(this, count, countRead);
    mSegmentReader = nullptr;

    LOG3(("SDTStream::ReadSegments %p trans readsegments rv %x read=%d\n",
          this, rv, *countRead));

    // Check to see if the transaction's request could be written out now.
    // If not, mark the stream for callback when writing can proceed.
    if (NS_SUCCEEDED(rv) &&
        mUpstreamState == GENERATING_HEADERS &&
        !mRequestHeadersDone)
      mSession->TransactionHasDataToWrite(this);

    // mTxinlineFrameUsed represents any queued un-sent frame. It might
    // be 0 if there is no such frame, which is not a gurantee that we
    // don't have more request body to send - just that any data that was
    // sent comprised a complete HTTP/2 frame. Likewise, a non 0 value is
    // a queued, but complete, http/2 frame length.

    // Mark that we are blocked on read if the http transaction needs to
    // provide more of the request message body and there is nothing queued
    // for writing
    if (rv == NS_BASE_STREAM_WOULD_BLOCK && !mTxInlineFrameUsed)
      mRequestBlockedOnRead = 1;

    // A transaction that had already generated its headers before it was
    // queued at the session level (due to concurrency concerns) may not call
    // onReadSegment off the ReadSegments() stack above.
    if (mUpstreamState == GENERATING_HEADERS && NS_SUCCEEDED(rv)) {
      LOG3(("SDTStream %p ReadSegments forcing OnReadSegment call\n", this));
      uint32_t wasted = 0;
      mSegmentReader = reader;
      OnReadSegment("", 0, &wasted);
      mSegmentReader = nullptr;
    }

    // If the sending flow control window is open (!mBlockedOnRwin) then
    // continue sending the request
    if (mOpenGenerated &&
        !mTxInlineFrameUsed && NS_SUCCEEDED(rv) && (!*countRead)) {
      MOZ_ASSERT(!mQueued);
      MOZ_ASSERT(mRequestHeadersDone);
      LOG3(("SDTStream::ReadSegments %p 0x%X: Sending request data complete, "
            "mUpstreamState=%x\n",this, mStreamID, mUpstreamState));
      if (!mSentFin) {
        mSession->CloseStream(mStreamID);
        UpdateTransportSendEvents(0);
        rv = NS_BASE_STREAM_WOULD_BLOCK;
      }
      ChangeState(UPSTREAM_COMPLETE);
    }
    break;

  case UPSTREAM_COMPLETE:
    *countRead = 0;
    rv = NS_OK;
    break;

  default:
    MOZ_ASSERT(false, "SDTStream::ReadSegments unknown state");
    break;
  }

  return rv;
}

nsresult
SDTStream::BufferInput(uint32_t count, uint32_t *countWritten)
{
  char buf[SimpleBufferPage::kSimpleBufferPageSize];
  if (SimpleBufferPage::kSimpleBufferPageSize < count) {
    count = SimpleBufferPage::kSimpleBufferPageSize;
  }

  mBypassInputBuffer = 1;
  nsresult rv = mSegmentWriter->OnWriteSegment(buf, count, countWritten);
  mBypassInputBuffer = 0;

  if (NS_SUCCEEDED(rv)) {
    rv = mSimpleBuffer.Write(buf, *countWritten);
    if (NS_FAILED(rv)) {
      MOZ_ASSERT(rv == NS_ERROR_OUT_OF_MEMORY);
      return NS_ERROR_OUT_OF_MEMORY;
    }
  }
  return rv;
}

bool
SDTStream::DeferCleanup(nsresult status)
{
  // do not cleanup a stream that has data buffered for the transaction
  return (NS_SUCCEEDED(status) && mSimpleBuffer.Available());
}

// WriteSegments() is used to read data off the socket. Generally this is
// just a call through to the associated nsHttpTransaction for this stream
// for the remaining data bytes indicated by the current DATA frame.

nsresult
SDTStream::WriteSegments(nsAHttpSegmentWriter *writer,
                         uint32_t count,
                         uint32_t *countWritten)
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(!mSegmentWriter, "segment writer in progress");

  LOG3(("SDTStream::WriteSegments %p count=%d state=%x",
        this, count, mUpstreamState));

  mSegmentWriter = writer;
  nsresult rv = mTransaction->WriteSegments(this, count, countWritten);

  if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
    // consuming transaction won't take data. but we need to read it into a buffer so that it
    // won't block other streams. but we should not advance the flow control window
    // so that we'll eventually push back on the sender.

    // with tunnels you need to make sure that this is an underlying connction established
    // that can be meaningfully giving this signal
    bool doBuffer = true;
    if (mIsTunnel) {
      RefPtr<SpdyConnectTransaction> qiTrans(mTransaction->QuerySpdyConnectTransaction());
      if (qiTrans) {
        doBuffer = qiTrans->ConnectedReadyForInput();
      }
    }
    // stash this data
    if (doBuffer) {
      rv = BufferInput(count, countWritten);
      LOG3(("SDTStream::WriteSegments %p Buffered %X %d\n", this, rv, *countWritten));
    }
  }
  mSegmentWriter = nullptr;
  return rv;
}

nsresult
SDTStream::MakeOriginURL(const nsACString &origin, RefPtr<nsStandardURL> &url)
{
  nsAutoCString scheme;
  nsresult rv = net_ExtractURLScheme(origin, scheme);
  NS_ENSURE_SUCCESS(rv, rv);
  return MakeOriginURL(scheme, origin, url);
}

nsresult
SDTStream::MakeOriginURL(const nsACString &scheme, const nsACString &origin,
                           RefPtr<nsStandardURL> &url)
{
  url = new nsStandardURL();
  nsresult rv = url->Init(nsIStandardURL::URLTYPE_AUTHORITY,
                          scheme.EqualsLiteral("http") ?
                              NS_HTTP_DEFAULT_PORT :
                              NS_HTTPS_DEFAULT_PORT,
                          origin, nullptr, nullptr);
  return rv;
}

void
SDTStream::CreatePushHashKey(const nsCString &scheme,
                             const nsCString &hostHeader,
                             uint64_t serial,
                             const nsCSubstring &pathInfo,
                             nsCString &outOrigin,
                             nsCString &outKey)
{
  nsCString fullOrigin = scheme;
  fullOrigin.AppendLiteral("://");
  fullOrigin.Append(hostHeader);

  RefPtr<nsStandardURL> origin;
  nsresult rv = SDTStream::MakeOriginURL(scheme, fullOrigin, origin);

  if (NS_SUCCEEDED(rv)) {
    rv = origin->GetAsciiSpec(outOrigin);
    outOrigin.Trim("/", false, true, false);
  }

  if (NS_FAILED(rv)) {
    // Fallback to plain text copy - this may end up behaving poorly
    outOrigin = fullOrigin;
  }

  outKey = outOrigin;
  outKey.AppendLiteral("/[http2.");
  outKey.AppendInt(serial);
  outKey.Append(']');
  outKey.Append(pathInfo);
}

nsresult
SDTStream::ParseHttpRequestHeaders(const char *buf,
                                   uint32_t avail,
                                   uint32_t *countUsed)
{
  // Returns NS_OK even if the headers are incomplete
  // set mRequestHeadersDone flag if they are complete

  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(mUpstreamState == GENERATING_HEADERS);
  MOZ_ASSERT(!mRequestHeadersDone);

  LOG3(("SDTStream::ParseHttpRequestHeaders %p avail=%d state=%x",
        this, avail, mUpstreamState));

  mFlatHttpRequestHeaders.Append(buf, avail);
  nsHttpRequestHead *head = mTransaction->RequestHead();

  // We can use the simple double crlf because firefox is the
  // only client we are parsing
  int32_t endHeader = mFlatHttpRequestHeaders.Find("\r\n\r\n");

  if (endHeader == kNotFound) {
    // We don't have all the headers yet
    LOG3(("SDTStream::ParseHttpRequestHeaders %p "
          "Need more header bytes. Len = %d",
          this, mFlatHttpRequestHeaders.Length()));
    *countUsed = avail;
    return NS_OK;
  }

  // We have recvd all the headers, trim the local
  // buffer of the final empty line, and set countUsed to reflect
  // the whole header has been consumed.
  uint32_t oldLen = mFlatHttpRequestHeaders.Length();
  mFlatHttpRequestHeaders.SetLength(endHeader + 2);
  *countUsed = avail - (oldLen - endHeader) + 4;
  mRequestHeadersDone = 1;

  nsAutoCString authorityHeader;
  nsAutoCString hashkey;
  head->GetHeader(nsHttp::Host, authorityHeader);

  nsAutoCString requestURI;
  head->RequestURI(requestURI);
  CreatePushHashKey(nsDependentCString(head->IsHTTPS() ? "https" : "http"),
                    authorityHeader, mSession->Serial(),
                    requestURI,
                    mOrigin, hashkey);

  // check the push cache for GET
  if (head->IsGet()) {
    // from :scheme, :authority, :path
    nsIRequestContext *requestContext = mTransaction->RequestContext();
    SpdyPushCache *cache = nullptr;
    if (requestContext) {
      requestContext->GetSpdyPushCache(&cache);
    }

/*    Http2PushedStream *pushedStream = nullptr;

    // If a push stream is attached to the transaction via onPush, match only with that
    // one. This occurs when a push was made with in conjunction with a nsIHttpPushListener
    nsHttpTransaction *trans = mTransaction->QueryHttpTransaction();
    if (trans && (pushedStream = trans->TakePushedStream())) {
      if (pushedStream->mSession == mSession) {
        LOG3(("Pushed Stream match based on OnPush correlation %p", pushedStream));
      } else {
        LOG3(("Pushed Stream match failed due to stream mismatch %p %d %d\n", pushedStream,
              pushedStream->mSession->Serial(), mSession->Serial()));
        pushedStream->OnPushFailed();
        pushedStream = nullptr;
      }
    }

    // we remove the pushedstream from the push cache so that
    // it will not be used for another GET. This does not destroy the
    // stream itself - that is done when the transactionhash is done with it.
    if (cache && !pushedStream){
        pushedStream = cache->RemovePushedStreamHttp2(hashkey);
    }

    LOG3(("Pushed Stream Lookup "
          "session=%p key=%s requestcontext=%p cache=%p hit=%p\n",
          mSession, hashkey.get(), requestContext, cache, pushedStream));

    if (pushedStream) {
      LOG3(("Pushed Stream Match located %p id=0x%X key=%s\n",
            pushedStream, pushedStream->StreamID(), hashkey.get()));
      pushedStream->SetConsumerStream(this);
      mPushSource = pushedStream;
      SetSentFin(true);
      AdjustPushedPriority();

      // There is probably pushed data buffered so trigger a read manually
      // as we can't rely on future network events to do it
      mSession->ConnectPushedStream(this);
      mOpenGenerated = 1;
      return NS_OK;
    }*/
  }
  return NS_OK;
}

// This is really a headers frame, but open is pretty clear from a workflow pov
nsresult
SDTStream::GenerateOpen()
{
  // It is now OK to assign a streamID that we are assured will
  // be monotonically increasing amongst new streams on this
  // session
  mStreamID = mSession->RegisterStreamID(this);
  MOZ_ASSERT(mStreamID & 1, "SDT Stream Channel ID must be odd");
  MOZ_ASSERT(!mOpenGenerated);

  mOpenGenerated = 1;

  nsHttpRequestHead *head = mTransaction->RequestHead();
  nsAutoCString requestURI;
  head->RequestURI(requestURI);
  LOG3(("SDTStream %p Stream ID 0x%X [session=%p] for URI %s\n",
        this, mStreamID, mSession, requestURI.get()));

  if (mStreamID >= 0x80000000) {
    // streamID must fit in 31 bits. Evading This is theoretically possible
    // because stream ID assignment is asynchronous to stream creation
    // because of the protocol requirement that the new stream ID
    // be monotonically increasing. In reality this is really not possible
    // because new streams stop being added to a session with millions of
    // IDs still available and no race condition is going to bridge that gap;
    // so we can be comfortable on just erroring out for correctness in that
    // case.
    LOG3(("Stream assigned out of range ID: 0x%X", mStreamID));
    return NS_ERROR_UNEXPECTED;
  }

  // Now we need to convert the flat http headers into a set
  // of HTTP/2 headers by writing to mTxInlineFrame{sz}

  nsCString compressedData;
  nsAutoCString authorityHeader;
  head->GetHeader(nsHttp::Host, authorityHeader);

  nsDependentCString scheme(head->IsHTTPS() ? "https" : "http");
  if (head->IsConnect()) {
    MOZ_ASSERT(mTransaction->QuerySpdyConnectTransaction());
    mIsTunnel = true;
    mRequestBodyLenRemaining = 0x0fffffffffffffffULL;

    // Our normal authority has an implicit port, best to use an
    // explicit one with a tunnel
    nsHttpConnectionInfo *ci = mTransaction->ConnectionInfo();
    if (!ci) {
      return NS_ERROR_UNEXPECTED;
    }

    authorityHeader = ci->GetOrigin();
    authorityHeader.Append(':');
    authorityHeader.AppendInt(ci->OriginPort());
  }

  nsAutoCString method;
  nsAutoCString path;
  head->Method(method);
  head->Path(path);
  mSession->Compressor()->EncodeHeaderBlock(mFlatHttpRequestHeaders,
                                            method,
                                            path,
                                            authorityHeader,
                                            scheme,
                                            head->IsConnect(),
                                            compressedData);

  int64_t clVal = mSession->Compressor()->GetParsedContentLength();
  if (clVal != -1) {
    mRequestBodyLenRemaining = clVal;
  }

  // split this one HEADERS frame up into N HEADERS + CONTINUATION frames if it
  // exceeds the 2^14-1 limit for 1 frame. Do it by inserting header size gaps
  // in the existing frame for the new headers. There is no question this is
  // ugly, but a 16KB HEADERS frame should be a long tail event, so this is
  // really just for correctness and a nop in the base case.
  //

  MOZ_ASSERT(!mTxInlineFrameUsed);

  uint32_t dataLength = compressedData.Length();
  uint32_t numFrames = (dataLength + SDTSession::kMaxFrameData - 1) /
      SDTSession::kMaxFrameData;
  if (!numFrames) {
    numFrames++;
  }

  // note that we could still have 1 frame for 0 bytes of data. that's ok.

  uint32_t messageSize = dataLength;
  messageSize += numFrames * SDTSession::kFrameHeaderBytes; // frame header overhead in CONTINUATION frames

  EnsureBuffer(mTxInlineFrame, messageSize,
               mTxInlineFrameUsed, mTxInlineFrameSize);

  mTxInlineFrameUsed += messageSize;
  UpdatePriorityDependency();
  LOG3(("SDTStream %p Generating %d bytes of HEADERS for stream 0x%X with "
        "priority weight %u dep 0x%X frames %u uri=%s\n",
        this, mTxInlineFrameUsed, mStreamID, mPriorityWeight,
        mPriorityDependency, numFrames, requestURI.get()));

  // TODO generate PRIORIT frame!!! -> SDTSession::GeneratePriority.
  uint32_t outputOffset = 0;
  uint32_t compressedDataOffset = 0;
  for (uint32_t idx = 0; idx < numFrames; ++idx) {
    uint32_t flags, frameLen;
    bool lastFrame = (idx == numFrames - 1);

    flags = 0;
    frameLen = SDTSession::kMaxFrameData;
    if (lastFrame) {
      frameLen = dataLength;
      flags |= SDTSession::kFlag_END_HEADERS;
    }
    dataLength -= frameLen;

    mSession->CreateFrameHeader(
      mTxInlineFrame.get() + outputOffset,
      frameLen,
      (idx) ? SDTSession::FRAME_TYPE_CONTINUATION : SDTSession::FRAME_TYPE_HEADERS,
      flags, mStreamID);
    outputOffset += SDTSession::kFrameHeaderBytes;

/*    if (!idx) {
      uint32_t wireDep = PR_htonl(mPriorityDependency);
      memcpy(mTxInlineFrame.get() + outputOffset, &wireDep, 4);
      memcpy(mTxInlineFrame.get() + outputOffset + 4, &mPriorityWeight, 1);
      outputOffset += 5;
    }
*/
    memcpy(mTxInlineFrame.get() + outputOffset,
           compressedData.BeginReading() + compressedDataOffset, frameLen);
    compressedDataOffset += frameLen;
    outputOffset += frameLen;
  }

  Telemetry::Accumulate(Telemetry::SPDY_SYN_SIZE, compressedData.Length());

  // The size of the input headers is approximate
  uint32_t ratio =
    compressedData.Length() * 100 /
    (11 + requestURI.Length() +
     mFlatHttpRequestHeaders.Length());

  mFlatHttpRequestHeaders.Truncate();
  Telemetry::Accumulate(Telemetry::SPDY_SYN_RATIO, ratio);
  return NS_OK;
}

void
SDTStream::AdjustInitialWindow()
{
  // The default initial_window is sized for pushed streams. When we
  // generate a client pulled stream we want to disable flow control for
  // the stream with a window update. Do the same for pushed streams
  // when they connect to a pull.

  // >0 even numbered IDs are pushed streams.
  // odd numbered IDs are pulled streams.
  // 0 is the sink for a pushed stream.
  SDTStream *stream = this;
  if (!mStreamID) {
    MOZ_ASSERT(false);//mPushSource);
/*    if (!mPushSource)
      return;
    stream = mPushSource;
    MOZ_ASSERT(stream->mStreamID);
    MOZ_ASSERT(!(stream->mStreamID & 1)); // is a push stream

    // If the pushed stream has recvd a FIN, there is no reason to update
    // the window
    if (stream->RecvdFin() || stream->RecvdReset())
      return;*/
  }
}

void
SDTStream::AdjustPushedPriority()
{
  // >0 even numbered IDs are pushed streams. odd numbered IDs are pulled streams.
  // 0 is the sink for a pushed stream.
/*
  if (mStreamID || !mPushSource)
    return;

  MOZ_ASSERT(mPushSource->mStreamID && !(mPushSource->mStreamID & 1));

  // If the pushed stream has recvd a FIN, there is no reason to update
  // the window
  if (mPushSource->RecvdFin() || mPushSource->RecvdReset())
    return;

  EnsureBuffer(mTxInlineFrame, mTxInlineFrameUsed + SDTSession::kFrameHeaderBytes + 5,
               mTxInlineFrameUsed, mTxInlineFrameSize);
  uint8_t *packet = mTxInlineFrame.get() + mTxInlineFrameUsed;
  mTxInlineFrameUsed += SDTSession::kFrameHeaderBytes + 5;

  mSession->CreateFrameHeader(packet, 5,
                              SDTSession::FRAME_TYPE_PRIORITY, 0,
                              mPushSource->mStreamID);

  mPushSource->SetPriority(mPriority);
  memset(packet + SDTSession::kFrameHeaderBytes, 0, 4);
  memcpy(packet + Session::kFrameHeaderBytes + 4, &mPriorityWeight, 1);
 

  LOG3(("AdjustPushedPriority %p id 0x%X to weight %X\n", this, mPushSource->mStreamID,
        mPriorityWeight));
*/
}

void
SDTStream::UpdateTransportReadEvents(uint32_t count)
{
  mTotalRead += count;
  if (!mSocketTransport) {
    return;
  }

  mTransaction->OnTransportStatus(mSocketTransport,
                                  NS_NET_STATUS_RECEIVING_FROM,
                                  mTotalRead);
}

void
SDTStream::UpdateTransportSendEvents(uint32_t count)
{
  mTotalSent += count;

  // normally on non-windows platform we use TCP autotuning for
  // the socket buffers, and this works well (managing enough
  // buffers for BDP while conserving memory) for HTTP even when
  // it creates really deep queues. However this 'buffer bloat' is
  // a problem for http/2 because it ruins the low latency properties
  // necessary for PING and cancel to work meaningfully.
  //
  // If this stream represents a large upload, disable autotuning for
  // the session and cap the send buffers by default at 128KB.
  // (10Mbit/sec @ 100ms)
  //
  uint32_t bufferSize = gHttpHandler->SpdySendBufferSize();
  if ((mTotalSent > bufferSize) && !mSetTCPSocketBuffer) {
    mSetTCPSocketBuffer = 1;
    mSocketTransport->SetSendBufferSize(bufferSize);
  }
 
  if (mUpstreamState != UPSTREAM_COMPLETE)
    mTransaction->OnTransportStatus(mSocketTransport,
                                    NS_NET_STATUS_SENDING_TO,
                                    mTotalSent);

  if (!mSentWaitingFor && !mRequestBodyLenRemaining) {
    mSentWaitingFor = 1;
    mTransaction->OnTransportStatus(mSocketTransport,
                                    NS_NET_STATUS_WAITING_FOR,
                                    0);
  }
}

nsresult
SDTStream::TransmitFrame()
{
  nsresult rv = mSegmentReader->CommitToSegmentSize(mTxInlineFrameUsed, true);

  MOZ_ASSERT(rv != NS_BASE_STREAM_WOULD_BLOCK,
             "force commitment with WOULD_BLOCK");
  if (NS_FAILED(rv)) {
    return rv;
  }

  uint32_t transmittedCount;
  rv = mSession->BufferOutput(reinterpret_cast<char*>(mTxInlineFrame.get()),
                              mTxInlineFrameUsed,
                              &transmittedCount);
  LOG3(("SDTStream::TransmitFrame for inline BufferOutput session=%p "
        "stream=%p result %x len=%d",
        mSession, this, rv, transmittedCount));

  MOZ_ASSERT(rv != NS_BASE_STREAM_WOULD_BLOCK,
             "inconsistent inline commitment result");

  if (NS_FAILED(rv)) {
    return rv;
  }

  MOZ_ASSERT(transmittedCount == mTxInlineFrameUsed,
             "inconsistent inline commitment count");

  SDTSession::LogIO(mSession, this, "Writing from Inline Buffer",
                       reinterpret_cast<char*>(mTxInlineFrame.get()),
                       transmittedCount);

  mSession->FlushOutputQueue();

  UpdateTransportSendEvents(mTxInlineFrameUsed);

  return NS_OK;
}

void
SDTStream::ChangeState(enum upstreamStateType newState)
{
  LOG3(("SDTStream::ChangeState() %p from %X to %X",
        this, mUpstreamState, newState));
  mUpstreamState = newState;
}

// ConvertResponseHeaders is used to convert the response headers
// into HTTP/1 format and report some telemetry
nsresult
SDTStream::ConvertResponseHeaders(Http2Decompressor *decompressor,
                                  nsACString &aHeadersIn,
                                  nsACString &aHeadersOut,
                                  int32_t &httpResponseCode)
{
  aHeadersOut.Truncate();
  aHeadersOut.SetCapacity(aHeadersIn.Length() + 512);

  nsresult rv =
    decompressor->DecodeHeaderBlock(reinterpret_cast<const uint8_t *>(aHeadersIn.BeginReading()),
                                    aHeadersIn.Length(),
                                    aHeadersOut, false);
  if (NS_FAILED(rv)) {
    LOG3(("SDTStream::ConvertResponseHeaders %p decode Error\n", this));
    return rv;
  }

  nsAutoCString statusString;
  decompressor->GetStatus(statusString);
  if (statusString.IsEmpty()) {
    LOG3(("SDTStream::ConvertResponseHeaders %p Error - no status\n", this));
    return NS_ERROR_ILLEGAL_VALUE;
  }

  nsresult errcode;
  httpResponseCode = statusString.ToInteger(&errcode);
  if (mIsTunnel) {
    LOG3(("SDTStream %p Tunnel Response code %d", this, httpResponseCode));
    if ((httpResponseCode / 100) != 2) {
      MapStreamToPlainText();
    }
  }

  if (httpResponseCode == 101) {
    // 8.1.1 of h2 disallows 101.. throw PROTOCOL_ERROR on stream
    LOG3(("SDTStream::ConvertResponseHeaders %p Error - status == 101\n", this));
    return NS_ERROR_ILLEGAL_VALUE;
  }

  if (aHeadersIn.Length() && aHeadersOut.Length()) {
    Telemetry::Accumulate(Telemetry::SPDY_SYN_REPLY_SIZE, aHeadersIn.Length());
    uint32_t ratio =
      aHeadersIn.Length() * 100 / aHeadersOut.Length();
    Telemetry::Accumulate(Telemetry::SPDY_SYN_REPLY_RATIO, ratio);
  }

  // The decoding went ok. Now we can customize and clean up.

  aHeadersIn.Truncate();
  aHeadersOut.Append("X-Firefox-Spdy: h2");
  aHeadersOut.Append("\r\n\r\n");
  LOG (("decoded response headers are:\n%s", aHeadersOut.BeginReading()));
  if (mIsTunnel && !mPlainTextTunnel) {
    aHeadersOut.Truncate();
    LOG(("SDTStream::ConvertHeaders %p 0x%X headers removed for tunnel\n",
         this, mStreamID));
  }
  return NS_OK;
}

// ConvertPushHeaders is used to convert the pushed request headers
// into HTTP/1 format and report some telemetry
nsresult
SDTStream::ConvertPushHeaders(Http2Decompressor *decompressor,
                              nsACString &aHeadersIn,
                              nsACString &aHeadersOut)
{
  aHeadersOut.Truncate();
  aHeadersOut.SetCapacity(aHeadersIn.Length() + 512);
  nsresult rv =
    decompressor->DecodeHeaderBlock(reinterpret_cast<const uint8_t *>(aHeadersIn.BeginReading()),
                                    aHeadersIn.Length(),
                                    aHeadersOut, true);
  if (NS_FAILED(rv)) {
    LOG3(("SDTStream::ConvertPushHeaders %p Error\n", this));
    return rv;
  }

  nsCString method;
  decompressor->GetHost(mHeaderHost);
  decompressor->GetScheme(mHeaderScheme);
  decompressor->GetPath(mHeaderPath);

  if (mHeaderHost.IsEmpty() || mHeaderScheme.IsEmpty() || mHeaderPath.IsEmpty()) {
    LOG3(("SDTStream::ConvertPushHeaders %p Error - missing required "
          "host=%s scheme=%s path=%s\n", this, mHeaderHost.get(), mHeaderScheme.get(),
          mHeaderPath.get()));
    return NS_ERROR_ILLEGAL_VALUE;
  }

  decompressor->GetMethod(method);
  if (!method.EqualsLiteral("GET")) {
    LOG3(("SDTStream::ConvertPushHeaders %p Error - method not supported: %s\n",
          this, method.get()));
    return NS_ERROR_NOT_IMPLEMENTED;
  }

  aHeadersIn.Truncate();
  LOG (("id 0x%X decoded push headers %s %s %s are:\n%s", mStreamID,
        mHeaderScheme.get(), mHeaderHost.get(), mHeaderPath.get(),
        aHeadersOut.BeginReading()));
  return NS_OK;
}

void
SDTStream::Close(nsresult reason)
{
  mTransaction->Close(reason);
}

void
SDTStream::SetResponseIsComplete()
{
  nsHttpTransaction *trans = mTransaction->QueryHttpTransaction();
  if (trans) {
    trans->SetResponseIsComplete();
  }
}

void
SDTStream::SetAllHeadersReceived()
{
  if (mAllHeadersReceived) {
    return;
  }

/*  if (mState == RESERVED_BY_REMOTE) {
    // pushed streams needs to wait until headers have
    // arrived to open up their window
    LOG3(("SDTStream::SetAllHeadersReceived %p state OPEN from reserved\n", this));
    mState = OPEN;
    AdjustInitialWindow();
  }*/

  mAllHeadersReceived = 1;
  if (mIsTunnel) {
    MapStreamToHttpConnection();
    ClearTransactionsBlockedOnTunnel();
  }
  return;
}

void
SDTStream::SetPriority(uint32_t newPriority)
{
  int32_t httpPriority = static_cast<int32_t>(newPriority);
  if (httpPriority > kWorstPriority) {
    httpPriority = kWorstPriority;
  } else if (httpPriority < kBestPriority) {
    httpPriority = kBestPriority;
  }
  mPriority = static_cast<uint32_t>(httpPriority);
  mPriorityWeight = (nsISupportsPriority::PRIORITY_LOWEST + 1) -
    (httpPriority - kNormalPriority);

  mPriorityDependency = 0; // maybe adjusted later
}

void
SDTStream::SetPriorityDependency(uint32_t newDependency, uint8_t newWeight,
                                   bool exclusive)
{
  // undefined what it means when the server sends a priority frame. ignore it.
  LOG3(("SDTStream::SetPriorityDependency %p 0x%X received dependency=0x%X "
        "weight=%u exclusive=%d", this, mStreamID, newDependency, newWeight,
        exclusive));
}

void
SDTStream::UpdatePriorityDependency()
{
  if (!mSession->UseH2Deps()) {
    return;
  }

  nsHttpTransaction *trans = mTransaction->QueryHttpTransaction();
  if (!trans) {
    return;
  }

  // we create 5 fake dependency streams per session,
  // these streams are never opened with HEADERS. our first opened stream is 0xd
  // 3 depends 0, weight 200, leader class (kLeaderGroupID)
  // 5 depends 0, weight 100, other (kOtherGroupID)
  // 7 depends 0, weight 0, background (kBackgroundGroupID)
  // 9 depends 7, weight 0, speculative (kSpeculativeGroupID)
  // b depends 3, weight 0, follower class (kFollowerGroupID)
  //
  // streams for leaders (html, js, css) depend on 3
  // streams for folowers (images) depend on b
  // default streams (xhr, async js) depend on 5
  // explicit bg streams (beacon, etc..) depend on 7
  // spculative bg streams depend on 9

  uint32_t classFlags = trans->ClassOfService();

  if (classFlags & nsIClassOfService::Leader) {
    mPriorityDependency = SDTSession::kLeaderGroupID;
  } else if (classFlags & nsIClassOfService::Follower) {
    mPriorityDependency = SDTSession::kFollowerGroupID;
  } else if (classFlags & nsIClassOfService::Speculative) {
    mPriorityDependency = SDTSession::kSpeculativeGroupID;
  } else if (classFlags & nsIClassOfService::Background) {
    mPriorityDependency = SDTSession::kBackgroundGroupID;
  } else if (classFlags & nsIClassOfService::Unblocked) {
    mPriorityDependency = SDTSession::kOtherGroupID;
  } else {
    mPriorityDependency = SDTSession::kFollowerGroupID; // unmarked followers
  }

  LOG3(("SDTStream::UpdatePriorityDependency %p "
        "classFlags %X depends on stream 0x%X\n",
        this, classFlags, mPriorityDependency));
}

void
SDTStream::SetRecvdFin(bool aStatus)
{
  mRecvdFin = aStatus ? 1 : 0;
  if (!aStatus)
    return;






}

void
SDTStream::SetSentFin(bool aStatus)
{
  mSentFin = aStatus ? 1 : 0;
  if (!aStatus)
    return;

/*  if (mState == OPEN || mState == RESERVED_BY_REMOTE) {
    mState = CLOSED_BY_LOCAL;
  } else if (mState == CLOSED_BY_REMOTE) {
    mState = CLOSED;
  }*/
}

void
SDTStream::SetRecvdReset(bool aStatus)
{
  mRecvdReset = aStatus ? 1 : 0;
  if (!aStatus)
    return;
//  mState = CLOSED;
}

void
SDTStream::SetSentReset(bool aStatus)
{
  mSentReset = aStatus ? 1 : 0;
  if (!aStatus)
    return;
//  mState = CLOSED;
}

//-----------------------------------------------------------------------------
// nsAHttpSegmentReader
//-----------------------------------------------------------------------------

nsresult
SDTStream::OnReadSegment(const char *buf,
                           uint32_t count,
                           uint32_t *countRead)
{
  LOG3(("SDTStream::OnReadSegment %p count=%d state=%x",
        this, count, mUpstreamState));

  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(mSegmentReader, "OnReadSegment with null mSegmentReader");

  nsresult rv = NS_ERROR_UNEXPECTED;
  uint32_t dataLength;

  switch (mUpstreamState) {
  case GENERATING_HEADERS:
    // The buffer is the HTTP request stream, including at least part of the
    // HTTP request header. This state's job is to build a HEADERS frame
    // from the header information. count is the number of http bytes available
    // (which may include more than the header), and in countRead we return
    // the number of those bytes that we consume (i.e. the portion that are
    // header bytes)

    if (!mRequestHeadersDone) {
      if (NS_FAILED(rv = ParseHttpRequestHeaders(buf, count, countRead))) {
        return rv;
      }
    }

    if (mRequestHeadersDone && !mOpenGenerated) {
      if (!mSession->TryToActivate(this)) {
        LOG3(("SDTStream::OnReadSegment %p cannot activate now. queued.\n", this));
        return *countRead ? NS_OK : NS_BASE_STREAM_WOULD_BLOCK;
      }
      if (NS_FAILED(rv = GenerateOpen())) {
        return rv;
      }
   }

    LOG3(("ParseHttpRequestHeaders %p used %d of %d. "
          "requestheadersdone = %d mOpenGenerated = %d\n",
          this, *countRead, count, mRequestHeadersDone, mOpenGenerated));
    if (mOpenGenerated) {
      AdjustInitialWindow();
      // TransmitFrame cannot block
      rv = TransmitFrame();
      ChangeState(SENDING_BODY);
      break;
    }
    MOZ_ASSERT(*countRead == count, "Header parsing not complete but unused data");
    break;

  case SENDING_BODY:
  {
    *countRead = 0;
    if (!mSession->StreamCanWrite(mStreamID)) {
      mBlockedOnRwin = true;
      return NS_BASE_STREAM_WOULD_BLOCK;
    }
    int32_t sdtStatus;
    nsresult rv = mSession->SetNextStreamToWrite(mStreamID, &sdtStatus);
    MOZ_ASSERT(NS_SUCCEEDED(rv));
/*    if (NS_FAILED(rv)) {
      LOG3(("SDTStream this=%p streamId=%d, SetNextStreamToWrite return %d.\n",
            this, mStreamID, rv));
      MOZ_ASSERT(0);
      return rv;
    }
*/
    mBlockedOnRwin = false;

    LOG3(("SDTStream %p id 0x%x request len remaining %" PRId64 ", "
          "count avail %u",
          this, mStreamID, mRequestBodyLenRemaining, count));
    if (!count && mRequestBodyLenRemaining) {
      return NS_BASE_STREAM_WOULD_BLOCK;
    }
    if (count > mRequestBodyLenRemaining) {
      return NS_ERROR_UNEXPECTED;
    }

    uint32_t transmittedCount;
    rv = mSession->OnReadSegment(buf, count,
                                 countRead);

    LOG(("SDTStream %p id 0x%x sent %u",
         rv, *countRead));

    if (NS_FAILED(rv)) {
      return rv;
    }

    mRequestBodyLenRemaining -= *countRead;

    // normalize a partial write with a WOULD_BLOCK into just a partial write
    // as some code will take WOULD_BLOCK to mean an error with nothing
    // written (e.g. nsHttpTransaction::ReadRequestSegment()
    if (rv == NS_BASE_STREAM_WOULD_BLOCK && *countRead)
      rv = NS_OK;

    if (!mRequestBodyLenRemaining) {
      NS_SUCCEEDED(mSession->CloseStream(mStreamID));
    }
    break;
  }
  case UPSTREAM_COMPLETE:
//    MOZ_ASSERT(mPushSource);
    rv = TransmitFrame();
    break;

  default:
    MOZ_ASSERT(false, "SDTStream::OnReadSegment non-write state");
    break;
  }

  return rv;
}

//-----------------------------------------------------------------------------
// nsAHttpSegmentWriter
//-----------------------------------------------------------------------------

nsresult
SDTStream::OnWriteSegment(char *buf,
                          uint32_t count,
                          uint32_t *countWritten)
{
  LOG3(("SDTStream::OnWriteSegment %p count=%d state=%x 0x%X\n",
        this, count, mUpstreamState, mStreamID));

  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);
  MOZ_ASSERT(mSegmentWriter);

/*  if (mPushSource) {
    nsresult rv;
    rv = mPushSource->GetBufferedData(buf, count, countWritten);
    if (NS_FAILED(rv))
      return rv;

    mSession->ConnectPushedStream(this);
    return NS_OK;
  }
*/
  // sometimes we have read data from the network and stored it in a pipe
  // so that other streams can proceed when the gecko caller is not processing
  // data events fast enough and flow control hasn't caught up yet. This
  // gets the stored data out of that pipe
  if (!mBypassInputBuffer && mSimpleBuffer.Available()) {
    *countWritten = mSimpleBuffer.Read(buf, count);
    MOZ_ASSERT(*countWritten);
    LOG3(("SDTStream::OnWriteSegment read from flow control buffer %p %x %d\n",
          this, mStreamID, *countWritten));
    return NS_OK;
  }

  // read from the network
  return mSegmentWriter->OnWriteSegment(buf, count, countWritten);
}

/// connect tunnels

void
SDTStream::ClearTransactionsBlockedOnTunnel()
{
  MOZ_ASSERT(PR_GetCurrentThread() == gSocketThread);

  if (!mIsTunnel) {
    return;
  }
  Unused << gHttpHandler->ConnMgr()->ProcessPendingQ(mTransaction->ConnectionInfo());
}

void
SDTStream::MapStreamToPlainText()
{
  RefPtr<SpdyConnectTransaction> qiTrans(mTransaction->QuerySpdyConnectTransaction());
  MOZ_ASSERT(qiTrans);
  mPlainTextTunnel = true;
  qiTrans->ForcePlainText();
}

void
SDTStream::MapStreamToHttpConnection()
{
  RefPtr<SpdyConnectTransaction> qiTrans(mTransaction->QuerySpdyConnectTransaction());
  MOZ_ASSERT(qiTrans);
  qiTrans->MapStreamToHttpConnection(mSocketTransport,
                                     mTransaction->ConnectionInfo());
}

} // namespace net
} // namespace mozilla
