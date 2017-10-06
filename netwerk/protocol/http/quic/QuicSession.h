/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_QuicSession_h
#define mozilla_net_QuicSession_h

#include "ASpdySession.h"

#include "ASpdySession.h"
#include "nsAHttpConnection.h"

class nsISocketTransport;

namespace mozilla {
namespace net {

class QuicSocket;
class QuicStream;
class QuicSession final : public ASpdySession
                        , public nsAHttpConnection
{
  ~QuicSession();

public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSAHTTPTRANSACTION
  NS_DECL_NSAHTTPCONNECTION(mConnection)

  QuicSession(nsISocketTransport *, uint32_t version, bool attemptingEarlyData);

  MOZ_MUST_USE bool AddStream(nsAHttpTransaction *, int32_t,
                               bool, nsIInterfaceRequestor *) override;
  bool CanReuse() override;
  bool RoomForMoreStreams() override;
  uint32_t WireVersion() override;
  bool TestJoinConnection(const nsACString &hostname, int32_t port) override;
  bool JoinConnection(const nsACString &hostname, int32_t port) override;
  uint32_t  ReadTimeoutTick(PRIntervalTime now) override;
  PRIntervalTime IdleTime() override;

  void TransactionHasDataToWrite(nsAHttpTransaction *) override;
  void TransactionHasDataToRecv(nsAHttpTransaction *) override;

  void PrintDiagnostics (nsCString &log) override;

  void SendPing() override;
  MOZ_MUST_USE bool MaybeReTunnel(nsAHttpTransaction *) override;

  MOZ_MUST_USE nsresult ReadSegmentsAgain(nsAHttpSegmentReader *, uint32_t, uint32_t *, bool *) override final;
  MOZ_MUST_USE nsresult WriteSegmentsAgain(nsAHttpSegmentWriter *, uint32_t , uint32_t *, bool *) override final;
  MOZ_MUST_USE bool Do0RTT() override final { return false; } // todo
  MOZ_MUST_USE nsresult Finish0RTT(bool aRestart, bool aAlpnChanged) override final;
  void SetFastOpenStatus(uint8_t aStatus) override final;

private:
  nsISocketTransport        *mSocketTransport;
  QuicSocket                *mSocket;
  RefPtr<nsAHttpConnection> mConnection;

  nsDataHashtable<nsPtrHashKey<nsAHttpTransaction>, QuicStream *> mStreamTransactionHash;
};

} // namespace net
} // namespace mozilla

#endif // mozilla_net_QuicSession_h
