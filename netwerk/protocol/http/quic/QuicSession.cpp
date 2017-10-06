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

#include "QuicSession.h"
#include "QuicSocket.h"
#include "nsHttpHandler.h"
#include "nsISocketTransport.h"
#include "MozQuic.h"

namespace mozilla {
namespace net {

NS_IMPL_ADDREF(QuicSession)
NS_IMPL_RELEASE(QuicSession)
NS_INTERFACE_MAP_BEGIN(QuicSession)
NS_INTERFACE_MAP_ENTRY_AMBIGUOUS(nsISupports, nsAHttpConnection)
NS_INTERFACE_MAP_END
    
QuicSession::QuicSession(nsISocketTransport *aSocketTransport, uint32_t version, bool attemptingEarlyData)
  : mSocketTransport(aSocketTransport)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  LOG3(("QuicSession::QuicSession %p", this));
  mSocket = nullptr;
  nsCOMPtr<nsIInterfaceRequestor> ir = do_QueryInterface(mSocketTransport);
  if (ir) {
    ir->GetInterface(NS_QUICSOCKET_IID, (void **) &mSocket);
  }
}

QuicSession::~QuicSession()
{
  // need to cleanup mstreamtransactionhash
}


class QuicStream : public nsAHttpSegmentReader, public nsAHttpSegmentWriter
{
public:
  NS_DECL_NSAHTTPSEGMENTREADER
  NS_DECL_NSAHTTPSEGMENTWRITER

  QuicStream(QuicSession *, nsAHttpTransaction *trans, mozquic_stream_t *stream)
    : mState(0)
    , mStream(stream)
    , mTransaction(trans)
    , mRecvdFin(false)
  {
  }
  ~QuicStream() {}

private:
  uint32_t mState;
  mozquic_stream_t *mStream;
  nsAHttpTransaction *mTransaction;
  bool mRecvdFin;
};

bool
QuicSession::AddStream(nsAHttpTransaction *aHttpTransaction,
                       int32_t aPriority,
                       bool aUseTunnel, nsIInterfaceRequestor *)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(!aUseTunnel); // todo.. interfacerequestor is for that
  MOZ_ASSERT(mSocket);
  // todo priority

  // integrity check
  if (mStreamTransactionHash.Get(aHttpTransaction)) {
    LOG3(("QuicSession %p New transaction already present\n", this));
    MOZ_ASSERT(false, "AddStream duplicate transaction pointer");
    return false;
  }

  if (!mConnection) {
    mConnection = aHttpTransaction->Connection();
    mSocket->SetConnection(mConnection);
  }
  aHttpTransaction->SetConnection(this);
  aHttpTransaction->OnActivated(true);

  mozquic_stream_t *stream = mSocket->NewStream();
  LOG3(("QuicSession::AddStream %p transaction %p ID %d\n", this, aHttpTransaction,
        mozquic_get_streamid(stream)));

  MOZ_ASSERT(stream);
  QuicStream *qs = new QuicStream(this, aHttpTransaction, stream);

  mStreamTransactionHash.Put(aHttpTransaction, qs);
  RefPtr<nsAHttpTransaction> foo(aHttpTransaction);
  nsAHttpTransaction *hm;
  foo.forget(&hm);

  if (!(aHttpTransaction->Caps() & NS_HTTP_ALLOW_KEEPALIVE) &&
      !aHttpTransaction->IsNullTransaction()) {
    LOG3(("QuicSession::AddStream %p transaction %p forces keep-alive off.\n",
          this, aHttpTransaction));
    DontReuse();
  }

  return true;
}

bool
QuicSession::CanReuse()
{
  // todo state
  return true;
}

bool
QuicSession::RoomForMoreStreams()
{
  // todo flow control
  return true;
}

uint32_t
QuicSession::WireVersion()
{
  return QUIC_EXPERIMENT_0;
}

bool
QuicSession::TestJoinConnection(const nsACString &hostname, int32_t port)
{
  return false;
  // todo - this is needed for coalescing
}

bool
QuicSession::JoinConnection(const nsACString &hostname, int32_t port)
{
    return false;
  // todo - this is needed for coalescing
    // can probably directly use the h2 code
}

uint32_t
QuicSession::ReadTimeoutTick(PRIntervalTime now)
{
  mSocket->IO();
  mConnection->ForceRecv();
  return 0; // this is awful - need poll() integration
  return UINT32_MAX;
}

PRIntervalTime
QuicSession::IdleTime()
{
  return 0; // todo
}

void
QuicSession::TransactionHasDataToWrite(nsAHttpTransaction *)
{
  // todo
}

void
QuicSession::TransactionHasDataToRecv(nsAHttpTransaction *)
{
  // todo
}

void
QuicSession::PrintDiagnostics (nsCString &log)
{
  // todo
}

void
QuicSession::SendPing()
{
  // todo
}
void
QuicSession::OnTransportStatus(nsITransport* aTransport,
                               nsresult aStatus, int64_t aProgress)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  // todo
}

void
QuicSession::Close(nsresult aReason)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(false);
  // todo
}

nsHttpConnectionInfo *
QuicSession::ConnectionInfo()
{
  MOZ_ASSERT(false);
//  RefPtr<nsHttpConnectionInfo> ci;
//  GetConnectionInfo(getter_AddRefs(ci));
//  return ci.get();
  return nullptr;
  // todo
}

void
QuicSession::GetSecurityCallbacks(nsIInterfaceRequestor **aOut)
{
  *aOut = nullptr;
}

bool
QuicSession::MaybeReTunnel(nsAHttpTransaction *)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  return false;
  // todo
}

// ReadSegments() is used to write data to the network. Generally, HTTP
// request data is pulled from the approriate transaction and
// converted to quic.

nsresult
QuicSession::ReadSegmentsAgain(nsAHttpSegmentReader *,
                               uint32_t count, uint32_t *countRead, bool *again)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  // we need some structure like h2 has to know what to write, but
  // maybe we can just merge with h2 later - so for now todo take the
  // debt and iterate the hash
  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    nsAHttpTransaction *trans = iter.Key();
    QuicStream *stream = iter.Data();
    nsresult rv = trans->ReadSegments(stream, count, countRead);
    if (rv == NS_BASE_STREAM_CLOSED) {
      iter.Remove();
      trans->Close(rv);
      trans->Release();
      *again = true;
      break;
    }
  }

  *again = false;
  return NS_OK;
}

nsresult
QuicSession::ReadSegments(nsAHttpSegmentReader *reader,
                           uint32_t count, uint32_t *countRead)
{
  bool again = false;
  return ReadSegmentsAgain(reader, count, countRead, &again);
}

// WriteSegments() is used to read data off the socket.
nsresult
QuicSession::WriteSegmentsAgain(nsAHttpSegmentWriter *writer,
                                uint32_t count, uint32_t *countWritten,
                                bool *again)
{
  *again = false;
  // we need some structure like h2 has to know what to write, but
  // maybe we can just merge with h2 later - so for now todo take the
  // debt and iterate the hash
  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    nsAHttpTransaction *trans = iter.Key();
    QuicStream *stream = iter.Data();
    nsresult rv = trans->WriteSegments(stream, count, countWritten);
    if (rv == NS_BASE_STREAM_CLOSED) {
      iter.Remove();
      trans->Close(rv);
      trans->Release();
      *again = true;
      break;
    }
  }
  return NS_OK;
}

nsresult
QuicSession::WriteSegments(nsAHttpSegmentWriter *writer,
                            uint32_t count, uint32_t *countWritten)
{
  bool again = false;
  return WriteSegmentsAgain(writer, count, countWritten, &again);
}

nsresult
QuicSession::Finish0RTT(bool aRestart, bool aAlpnChanged)
{
  MOZ_ASSERT(false); // todo
  return NS_OK;
}

void
QuicSession::SetFastOpenStatus(uint8_t aStatus)
{
// todo
}

void
QuicSession::SetConnection(nsAHttpConnection *)
{
  // This is unexpected
  MOZ_ASSERT(false, "QuicSession::SetConnection()");
}

void
QuicSession::SetProxyConnectFailed()
{
  MOZ_ASSERT(false, "QuicSession::SetProxyConnectFailed()");
}

bool
QuicSession::IsDone()
{
    // todo
  return false;
}

nsresult
QuicSession::Status()
{
  MOZ_ASSERT(false, "QuicSession::Status()");
  return NS_ERROR_UNEXPECTED;
}

uint32_t
QuicSession::Caps()
{
  MOZ_ASSERT(false, "QuicSession::Caps()");
  return 0;
}

void
QuicSession::SetDNSWasRefreshed()
{
  MOZ_ASSERT(false, "QuicSession::SetDNSWasRefreshed()");
}

nsHttpRequestHead *
QuicSession::RequestHead()
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(false,
             "QuicSession::RequestHead() "
             "should not be called after quic is setup");
  return NULL;
}

uint32_t
QuicSession::Http1xTransactionCount()
{
  return 0;
}

nsresult
QuicSession::TakeSubTransactions(
  nsTArray<RefPtr<nsAHttpTransaction> > &outTransactions)
{
  // Generally this cannot be done with >= http/2 as transactions are
  // started right away.

  LOG3(("QuicSession::TakeSubTransactions %p\n", this));

  MOZ_ASSERT(false);
  return NS_OK;
}

//-----------------------------------------------------------------------------
// Pass through methods of nsAHttpConnection
//-----------------------------------------------------------------------------

nsAHttpConnection *
QuicSession::Connection()
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  return mConnection;
}

nsresult
QuicSession::OnHeadersAvailable(nsAHttpTransaction *transaction,
                                 nsHttpRequestHead *requestHead,
                                 nsHttpResponseHead *responseHead, bool *reset)
{
  return mConnection->OnHeadersAvailable(transaction,
                                         requestHead,
                                         responseHead,
                                         reset);
}

bool
QuicSession::IsReused()
{
  return mConnection->IsReused();
}

nsresult
QuicSession::PushBack(const char *buf, uint32_t len)
{
  return mConnection->PushBack(buf, len);
}

void
QuicSession::DontReuse()
{
  LOG3(("QuicSession::DontReuse %p\n", this));
  fprintf(stderr,"TODO PRM01\n");
  // todo

}

void
QuicSession::CloseTransaction(nsAHttpTransaction *aTransaction,
                               nsresult aResult)
{
  MOZ_ASSERT(false);
  // todo
}

nsresult
QuicSession::TakeTransport(nsISocketTransport **,
                            nsIAsyncInputStream **, nsIAsyncOutputStream **)
{
  MOZ_ASSERT(false, "TakeTransport of QuicSession");
  return NS_ERROR_UNEXPECTED;
}

bool
QuicSession::IsPersistent()
{
  return true;
}

already_AddRefed<nsHttpConnection>
QuicSession::TakeHttpConnection()
{
  MOZ_ASSERT(false, "TakeHttpConnection of QuicSession");
  return nullptr;
}

already_AddRefed<nsHttpConnection>
QuicSession::HttpConnection()
{
  if (mConnection) {
    return mConnection->HttpConnection();
  }
  return nullptr;
}

void
QuicSession::TopLevelOuterContentWindowIdChanged(uint64_t windowId)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  // todo
}


nsresult
QuicStream::OnReadSegment(const char *buf, uint32_t count, uint32_t *countRead)
{
  // state machine which stops sending stuff at space #2
  // converts this to 0.9 :)
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  for (uint32_t i = 0 ; (i < count) && (mState < 2); i++ ) {
    if (buf[i] == ' ') {
      if (++mState == 2) {
	mozquic_send(mStream, (void *)buf, i, 0);
	mozquic_send(mStream, (void *)"\r\n", 2, 1);
      }
    }
  }
  if (mState < 2) {
    mozquic_send(mStream, (void *)buf, count, 0);
  }
  *countRead = count;
  return NS_OK;
}

nsresult
QuicStream::OnWriteSegment(char *buf, uint32_t count, uint32_t *countWritten)
{
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  *countWritten = 0;
  if (mState == 2) {
    // make up some response headers
    MOZ_ASSERT(count > 300); // TODO not a true assumption
    const char *tw = "HTTP/1.0 200 MEH\r\nX-Firefox-Spdy: hq-05\r\n\r\n";
    memcpy(buf, tw, strlen(tw));
    *countWritten = strlen(tw);
    ++mState;
    return NS_OK;
  }

  if (mRecvdFin) {
    mTransaction->Close(NS_OK);
    return NS_BASE_STREAM_CLOSED;
  }
  int fin;
  mozquic_recv(mStream, buf, count, countWritten, &fin);
  mRecvdFin = fin;
  if (*countWritten) {
    LOG3(("QuicSession::OnWriteSegment %p ok count=%d fin=%d\n",
          this, *countWritten, mRecvdFin));
    return NS_OK;
  }

  if (mRecvdFin) {
    LOG3(("QuicSession::OnWriteSegment %p closed count=%d fin=%d\n",
          this, *countWritten, mRecvdFin));
    return NS_BASE_STREAM_CLOSED;
  }
  LOG3(("QuicSession::OnWriteSegment %p wouldblock count=%d fin=%d\n",
        this, *countWritten, mRecvdFin));
  return NS_BASE_STREAM_WOULD_BLOCK;
}

}
}
