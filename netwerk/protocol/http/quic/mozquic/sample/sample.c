/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <string.h>
#include "../MozQuic.h"

int main()
{
  struct mozquic_config_t config;
  mozquic_connection_t *c;

  memset(&config, 0, sizeof(config));
  config.originName = "foo.example.com";
  config.originPort = 8443;
  config.handleIO = 1;

  mozquic_new_connection(&c, &config);
//  mozquic_start_server(NULL, NULL);
}
