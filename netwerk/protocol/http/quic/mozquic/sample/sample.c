/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../MozQuic.h"

mozquic_connection_t *only_child = NULL;

static int accept_new_connection(void *closure, mozquic_connection_t *nc)
{
  if (only_child) {
    return MOZQUIC_ERR_GENERAL;
  }
  only_child = nc;
  return MOZQUIC_OK;
}

int main()
{
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  memset(&config, 0, sizeof(config));
  config.originName = "foo.example.com";
  config.originPort = 8443;
  config.handleIO = 0; // todo mvp

  mozquic_new_connection(&c, &config);
  mozquic_start_server(c, accept_new_connection);
  do {
    usleep (1000); // this is for handleio todo
    mozquic_IO(c);
    if (only_child) {
      mozquic_IO(only_child);
    }
  } while (1);
  
}
