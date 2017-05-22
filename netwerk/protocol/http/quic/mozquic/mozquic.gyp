# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# To use the library outside of firefox
# npm install gyp
# gyp --depth=. --generator-output=obj
# cd obj; make
#
# See the sample app in extra.gyp for an example

{
  'targets': [
      {
     'target_name': 'mozquic',
     'type': 'static_library',
     'cflags': [
         '-g',
        ],
     'sources': [
         'fnv.c',
         'MozQuic.cpp',
         'MozQuicStream.cpp',
        ],
     },
   ],
}

