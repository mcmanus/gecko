# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# apt-get install libnss3-dev libnspr4-dev
# npm install gyp

#
# gyp --depth=. --generator-output=obj
# cd obj; make

# Make sure to set your NSS information in env.gypi if you
# are not using a pkg-config version (which currently does not exist
# as tls 1.3 -20 is required is currently on an unreleased DRAFT-19
# branch

{
  'includes': [
     'env.gypi',
  ],

  'targets': [
    {
     'target_name': 'server',
     'type': 'executable',
      'cflags': [ '-g', ],
      'sources': [
       'sample/server.c',
      ],
     'dependencies': [
       'mozquic.gyp:mozquic',
      ],
     'libraries': [
       '<(nss_link)', 
      ],
     },
      {
     'target_name': 'client',
     'type': 'executable',
      'cflags': [ '-g', ],
      'sources': [
       'sample/client.c',
      ],
     'dependencies': [
       'mozquic.gyp:mozquic',
      ],
     'libraries': [
       '<(nss_link)', 
      ],
     },
   ],
}

