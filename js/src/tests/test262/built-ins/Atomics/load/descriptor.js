// |reftest| skip-if(!this.hasOwnProperty('Atomics')) -- Atomics is not enabled unconditionally
// Copyright 2015 Microsoft Corporation. All rights reserved.
// Copyright (C) 2017 Mozilla Corporation. All rights reserved.
// This code is governed by the license found in the LICENSE file.

/*---
esid: sec-atomics.load
description: Testing descriptor property of Atomics.load
includes: [propertyHelper.js]
features: [Atomics]
---*/

verifyWritable(Atomics, "load");
verifyNotEnumerable(Atomics, "load");
verifyConfigurable(Atomics, "load");

reportCompare(0, 0);
