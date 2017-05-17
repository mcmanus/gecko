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
    MOZQUIC_ERR_INVALID = 2,
    MOZQUIC_ERR_MEMORY  = 3
  };


  typedef void mozquic_connection_t;

  struct mozquic_config_t 
  {
    const char *originName;
    int originPort;
    int handleIO; // true if library should schedule read and write events
    void *closure;

    void (*logging_callback)(void *, char *); // todo va arg
    int  (*send_callback)(void *, unsigned char *, uint32_t len);
    int  (*recv_callback)(void *, unsigned char *, uint32_t len, uint32_t *outLen);
    int  (*error_callback)(void *, uint32_t err, char *);

    // TLS API
    int (*handshake_input)(void *, unsigned char *data, uint32_t len);
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
  // or may imlement the TLS API : mozquic_handshake_input/output and then
  // mozquic_handshake_complete(ERRORCODE)
  void mozquic_handshake_output(mozquic_connection_t *session,
                                unsigned char *data, uint32_t data_len);
  void mozquic_handshake_complete(mozquic_connection_t *session, int err);

#ifdef __cplusplus
}
#endif

#endif

