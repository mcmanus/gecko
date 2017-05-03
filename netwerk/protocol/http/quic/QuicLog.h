/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef QUIClog__h__
#define QUIClog__h__

#include "mozilla/Logging.h"

namespace mozilla {
namespace net {

extern LazyLogModule gQUICLog;

} // namespace net
} // namespace mozilla

#endif

// the macros are not in a namespace and unified builds require
// that they be undef'd at the end of cpp files for sanity.. so
/// do not put their declarations in ifndef guard bars
#define LOG(args) MOZ_LOG(mozilla::net::gQUICLog, mozilla::LogLevel::Debug, args)
#define QUIC_LOG_ENABLED() MOZ_LOG_TEST(mozilla::net::gQUICLog, mozilla::LogLevel::Debug)
