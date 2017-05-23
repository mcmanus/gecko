# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# See the sample app in extra.gyp for an example outside firefox

{
  'targets': [
      {
     'target_name': 'mozquic',
     'type': 'static_library',
     'cflags': [ '-g', '<!@(pkg-config --cflags nss)', ],
     'cflags_mozilla': [ '$(NSPR_CFLAGS)', '$(NSS_CFLAGS)', ],
     'sources': [
         'fnv.c',
         'MozQuic.cpp',
         'MozQuicStream.cpp',
         'NSSHelper.cpp',
        ],
     },
   ],
}

