/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozquicinternal_h__
#define mozquicinternal_h__

#include "netinet/ip.h"

namespace mozilla { namespace net {

class MozQuic final
{
public:
  MozQuic() {}
  ~MozQuic() {}

  int StartConnection();
  int IO();
private:
};
}}

#ifdef __cplusplus
extern "C" {
#endif

struct mozquic_connection_t {
  int                 udp;
  //  struct sockaddr_in  v4addr;
  //  struct sockaddr_in6 v6addr;
  int                 isV6;
  char *originName;
  int originPort;
  int handleIO;
  mozilla::net::MozQuic *q;
};
struct mozquic_stream_t {
  void *ptr;
};

#ifdef __cplusplus
}
#endif
#endif
