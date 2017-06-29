/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "../MozQuic.h"

mozquic_connection_t *only_child = NULL;

#if 0
The sample/nss-config directory is a sample that can be passed
to mozquic_nss_config(). It contains a NSS database with a cert
and key for foo.example.com that is signed by a CA defined by CA.cert.der.
#endif

static int accept_new_connection(void *closure, mozquic_connection_t *nc)
{
  if (only_child) {
    mozquic_destroy_connection(only_child);
  }
  only_child = nc;
  return MOZQUIC_OK;
}

int main()
{
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  char *cdir = getenv ("MOZQUIC_NSS_CONFIG");
  if (mozquic_nss_config(cdir) != MOZQUIC_OK) {
    fprintf(stderr,"MOZQUIC_NSS_CONFIG FAILURE [%s]\n", cdir ? cdir : "");
    exit (-1);
  }
  
  memset(&config, 0, sizeof(config));
  config.originName = "foo.example.com"; // really the nickname in the nss db
  config.originPort = 4433;
  config.tolerateBadALPN = 1;
  config.handleIO = 0; // todo mvp

  mozquic_new_connection(&c, &config);
  mozquic_start_server(c, accept_new_connection);
  uint32_t i=0;
  do {
    usleep (1000); // this is for handleio todo
    if (!(i++ & 0xf)) {
      fprintf(stderr,".");
      fflush(stderr);
    }
    mozquic_IO(c);
    if (only_child) {
      mozquic_IO(only_child); // todo mvp do we need this?
    }
  } while (1);
  
}
