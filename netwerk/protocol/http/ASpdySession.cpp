/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// HttpLog.h should generally be included first
#include "HttpLog.h"

/*
  Currently supported are h2 and hq
*/

#include "nsHttp.h"
#include "nsHttpHandler.h"

#include "ASpdySession.h"
#include "PSpdyPush.h"
#include "Http2Push.h"
#include "Http2Session.h"
#include "MozQuic.h"
#include "mozilla/Telemetry.h"
#include "QuicSession.h"

namespace mozilla {
namespace net {

const char *ASpdySession::kH2Alpn = "h2";
const char *ASpdySession::kHQAlpn = MOZQUIC_ALPN;

ASpdySession *
ASpdySession::NewSpdySession(uint32_t version,
                             nsISocketTransport *aTransport,
                             bool attemptingEarlyData)
{
  // This is a necko only interface, so we can enforce version
  // requests as a precondition
  MOZ_ASSERT(version == HTTP_VERSION_2 ||
             version == QUIC_EXPERIMENT_0,
             "unsupported multistreamed transport");

  // Don't do a runtime check of IsSpdyV?Enabled() here because pref value
  // may have changed since starting negotiation. The selected protocol comes
  // from a list provided in the SERVER HELLO filtered by our acceptable
  // versions, so there is no risk of the server ignoring our prefs.

  Telemetry::Accumulate(Telemetry::SPDY_VERSION2, version);

  if (version == HTTP_VERSION_2) {
    return new Http2Session(aTransport, version, attemptingEarlyData);
  }

  MOZ_ASSERT(version == QUIC_EXPERIMENT_0);
//  return new Http2Session(aTransport, version, attemptingEarlyData);
  return new QuicSession(aTransport, version, attemptingEarlyData);
}

SpdyInformation::SpdyInformation()
{
  // highest index of enabled protocols is the
  // most preferred for ALPN negotiaton
  Version[0] = HTTP_VERSION_2;
  VersionString[0] = nsCString(ASpdySession::kH2Alpn);
  ALPNCallbacks[0] = Http2Session::ALPNCallback;
  IsQUIC[0] = false;

  Version[1] = QUIC_EXPERIMENT_0;
  VersionString[1] = nsCString(ASpdySession::kHQAlpn);
  ALPNCallbacks[1] = Http2Session::ALPNCallback;
  IsQUIC[1] = true;
}

bool
SpdyInformation::ProtocolEnabled(uint32_t index) const
{
  MOZ_ASSERT(index < kCount, "index out of range");

  switch (index) {
  case 0:
    return gHttpHandler->IsHttp2Enabled();
  case 1:
    return gHttpHandler->IsQUICEnabled();
  }
  return false;
}

nsresult
SpdyInformation::GetALPNIndex(const nsACString &alpnString,
                             uint32_t *result) const
{
  if (alpnString.IsEmpty())
    return NS_ERROR_FAILURE;

  for (uint32_t index = 0; index < kCount; ++index) {
    if (alpnString.Equals(VersionString[index])) {
      *result = index;
      return NS_OK;
    }
  }

  return NS_ERROR_FAILURE;
}

//////////////////////////////////////////
// SpdyPushCache
//////////////////////////////////////////

SpdyPushCache::~SpdyPushCache()
{
  mHashHttp2.Clear();
}

bool
SpdyPushCache::RegisterPushedStreamHttp2(const nsCString& key,
                                         Http2PushedStream *stream)
{
  LOG3(("SpdyPushCache::RegisterPushedStreamHttp2 %s 0x%X\n",
        key.get(), stream->StreamID()));
  if(mHashHttp2.Get(key)) {
    LOG3(("SpdyPushCache::RegisterPushedStreamHttp2 %s 0x%X duplicate key\n",
          key.get(), stream->StreamID()));
    return false;
  }
  mHashHttp2.Put(key, stream);
  return true;
}

Http2PushedStream *
SpdyPushCache::RemovePushedStreamHttp2(const nsCString& key)
{
  Http2PushedStream *rv = mHashHttp2.Get(key);
  LOG3(("SpdyPushCache::RemovePushedStreamHttp2 %s 0x%X\n",
        key.get(), rv ? rv->StreamID() : 0));
  if (rv)
    mHashHttp2.Remove(key);
  return rv;
}

Http2PushedStream *
SpdyPushCache::RemovePushedStreamHttp2ByID(const nsCString& key, const uint32_t& streamID)
{
  Http2PushedStream *rv = mHashHttp2.Get(key);
  LOG3(("SpdyPushCache::RemovePushedStreamHttp2ByID %s 0x%X 0x%X",
        key.get(), rv ? rv->StreamID() : 0, streamID));
  if (rv && streamID == rv->StreamID()) {
    mHashHttp2.Remove(key);
  } else {
    // Ensure we overwrite our rv with null in case the stream IDs don't match
    rv = nullptr;
  }
  return rv;
}

} // namespace net
} // namespace mozilla

