/* vim:set ts=2 sw=2 sts=2 et: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Tests that the console waits for more input instead of evaluating
// when valid, but incomplete, statements are present upon pressing enter
// -or- when the user ends a line with shift + enter.

"use strict";

const TEST_URI = "http://example.com/browser/devtools/client/webconsole/" +
                 "test/mochitest/test-console.html";
const OPTOUT = Ci.nsITelemetry.DATASET_RELEASE_CHANNEL_OPTOUT;

const SHOULD_ENTER_MULTILINE = [
  {input: "function foo() {" },
  {input: "var a = 1," },
  {input: "var a = 1;", shiftKey: true },
  {input: "function foo() { }", shiftKey: true },
  {input: "function" },
  {input: "(x) =>" },
  {input: "let b = {" },
  {input: "let a = [" },
  {input: "{" },
  {input: "{ bob: 3343," },
  {input: "function x(y=" },
  {input: "Array.from(" },
  // shift + enter creates a new line despite parse errors
  {input: "{2,}", shiftKey: true },
];
const SHOULD_EXECUTE = [
  {input: "function foo() { }" },
  {input: "var a = 1;" },
  {input: "function foo() { var a = 1; }" },
  {input: '"asdf"' },
  {input: "99 + 3" },
  {input: "1, 2, 3" },
  // errors
  {input: "function f(x) { let y = 1, }" },
  {input: "function f(x=,) {" },
  {input: "{2,}" },
];

const SINGLE_LINE_DATA = {
  timestamp: null,
  category: "devtools.main",
  method: "execute_js",
  object: "webconsole",
  value: null,
  extra: {
    lines: "1"
  }
};

const DATA = [
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  SINGLE_LINE_DATA,
  {
    timestamp: null,
    category: "devtools.main",
    method: "execute_js",
    object: "webconsole",
    value: null,
    extra: {
      lines: "3"
    }
  }
];

add_task(async function() {
  // Let's reset the counts.
  Services.telemetry.clearEvents();

  // Ensure no events have been logged
  const snapshot = Services.telemetry.snapshotEvents(OPTOUT, true);
  ok(!snapshot.parent, "No events have been logged for the main process");

  const hud = await openNewTabAndConsole(TEST_URI);
  const { inputNode } = hud.jsterm;

  for (const {input, shiftKey} of SHOULD_ENTER_MULTILINE) {
    hud.jsterm.setInputValue(input);
    EventUtils.synthesizeKey("VK_RETURN", { shiftKey });

    const inputValue = hud.jsterm.getInputValue();
    is(inputNode.selectionStart, inputNode.selectionEnd, "selection is collapsed");
    is(inputNode.selectionStart, inputValue.length, "caret at end of multiline input");

    const inputWithNewline = input + "\n";
    is(inputValue, inputWithNewline, "Input value is correct");
  }

  for (const {input, shiftKey} of SHOULD_EXECUTE) {
    hud.jsterm.setInputValue(input);
    EventUtils.synthesizeKey("VK_RETURN", { shiftKey });

    await waitFor(() => !hud.jsterm.getInputValue());

    const inputValue = hud.jsterm.getInputValue();
    is(inputNode.selectionStart, 0, "selection starts/ends at 0");
    is(inputNode.selectionEnd, 0, "selection starts/ends at 0");
    is(inputValue, "", "Input value is cleared");
  }

  await hud.jsterm.execute("document.\nlocation.\nhref");

  checkEventTelemetry();
});

function checkEventTelemetry() {
  const snapshot = Services.telemetry.snapshotEvents(OPTOUT, true);
  const events = snapshot.parent.filter(event => event[1] === "devtools.main" &&
                                                  event[2] === "execute_js" &&
                                                  event[3] === "webconsole" &&
                                                  event[4] === null
  );

  for (const i in DATA) {
    const [ timestamp, category, method, object, value, extra ] = events[i];
    const expected = DATA[i];

    // ignore timestamp
    ok(timestamp > 0, "timestamp is greater than 0");
    is(category, expected.category, "category is correct");
    is(method, expected.method, "method is correct");
    is(object, expected.object, "object is correct");
    is(value, expected.value, "value is correct");

    is(extra.lines, expected.extra.lines, "lines is correct");
  }
}
