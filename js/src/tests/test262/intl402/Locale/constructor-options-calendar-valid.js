// |reftest| skip -- Intl.Locale is not supported
// Copyright 2018 André Bargull; Igalia, S.L. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/*---
esid: sec-intl.locale
description: >
    Checks error cases for the options argument to the Locale
    constructor.
info: |
    Intl.Locale( tag [, options] )

    ...
    14. Let calendar be ? GetOption(options, "calendar", "string", undefined, undefined).
    ...

features: [Intl.Locale]
---*/

const validCalendarOptions = [
  ["abc", "en-u-ca-abc"],
  ["abcd", "en-u-ca-abcd"],
  ["abcde", "en-u-ca-abcde"],
  ["abcdef", "en-u-ca-abcdef"],
  ["abcdefg", "en-u-ca-abcdefg"],
  ["abcdefgh", "en-u-ca-abcdefgh"],
  ["12345678", "en-u-ca-12345678"],
  ["1234abcd", "en-u-ca-1234abcd"],
  ["1234abcd-abc123", "en-u-ca-1234abcd-abc123"],
];
for (const [calendar, expected] of validCalendarOptions) {
  let options = { calendar };
  assert.sameValue(
    new Intl.Locale('en', options).toString(),
    expected,
    `new Intl.Locale('en', options).toString() equals the value of ${expected}`
  );
  assert.sameValue(
    new Intl.Locale('en-u-ca-gregory', options).toString(),
    expected,
    `new Intl.Locale('en-u-ca-gregory', options).toString() equals the value of ${expected}`
  );
}

reportCompare(0, 0);
