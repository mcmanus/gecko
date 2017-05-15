/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozquic_h__
#define mozquic_h__

/* This interface is straight C - the library implementation is not. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

  enum {
    MOZQUIC_OK = 0,
    MOZQUIC_ERR_GENERAL = 1,
    MOZQUIC_ERR_INVALID = 2
  };


  typedef void mozquic_connection_t;

  struct mozquic_config_t 
  {
    int domain; // AF_INET or AF_INET6
//    const struct sockaddr *address;
    const char *originName;
    int originPort;
    int handleIO; // true if library should schedule read and write events

    void (*logging_callback)(mozquic_connection_t *, char *); // todo va arg
    int  (*transmit_callback)(mozquic_connection_t *, unsigned char *, uint32_t len);
    int  (*error_callback)(mozquic_connection_t *, uint32_t err, char *);

    // TLS API
    int (*perform_handshake_callback)(mozquic_connection_t *, int fd);
  };

  int mozquic_new_connection(mozquic_connection_t **outSession, mozquic_config_t *inConfig);
  int mozquic_destroy_connection(mozquic_connection_t *inSession);
  int mozquic_start_connection(mozquic_connection_t *inSession);


  ////////////////////////////////////////////////////
  // IO handlers
  // if library is handling IO this does not need to be called
  // otherwise call it to indicate IO should be handled
  int mozquic_IO(mozquic_connection_t *inSession);
  // todo need one to get the pollset

  int  mozquic_osfd(mozquic_connection_t *inSession);
  void mozquic_setosfd(mozquic_connection_t *inSession, int fd);

  // the mozquic application may either delegate TLS handling to the lib
  // or may imlement the TLS API : perform_handshake_callback and then
  // mozquic_handshake_complete(ERRORCODE)
  void mozquic_handshake_complete(mozquic_connection_t *session, int err);

#ifdef __cplusplus
}
#endif

#endif

