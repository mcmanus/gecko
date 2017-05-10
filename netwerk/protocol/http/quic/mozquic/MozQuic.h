/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozquic_h__
#define mozquic_h__

/* This interface is straight C - the library implementation is not. */

#ifdef __cplusplus
extern "C" {
#endif

  enum {
    MOZQUIC_OK = 0,
    MOZQUIC_ERR_GENERAL = 1,
    MOZQUIC_ERR_INVALID = 2
  };

  struct mozquic_connection_t;
  struct mozquic_stream_t;
  struct mozquic_config_t 
  {
    int domain; // AF_INET or AF_INET6
//    const struct sockaddr *address;
    const char *originName;
    int originPort;
  };

  int mozquic_new_connection(mozquic_connection_t **outSession, mozquic_config_t *inConfig);
  int mozquic_destroy_connection(mozquic_connection_t *inSession);
  int mozquic_start_connection(mozquic_connection_t *inSession);

  int mozquic_osfd(mozquic_connection_t *inSession);
#ifdef __cplusplus
}
#endif

#endif

