// ----------------------------------------------------------------------------
// Test whether an install succeeds using case-insensitive hashes
// This verifies bug 603021
function test() {
  Harness.installEndedCallback = install_ended;
  Harness.installsCompletedCallback = finish_test;
  Harness.setup();

  var pm = Services.perms;
  pm.add(makeURI("http://example.com/"), "install", pm.ALLOW_ACTION);

  var triggers = encodeURIComponent(JSON.stringify({
    "Unsigned XPI": {
      URL: TESTROOT + "amosigned.xpi",
      Hash: "sha1:EE95834AD862245A9EF99CCECC2A857CADC16404",
      toString() { return this.URL; }
    }
  }));
  gBrowser.selectedTab = BrowserTestUtils.addTab(gBrowser);
  gBrowser.loadURI(TESTROOT + "installtrigger.html?" + triggers);
}

function install_ended(install, addon) {
  install.cancel();
}

function finish_test(count) {
  is(count, 1, "1 Add-on should have been successfully installed");

  Services.perms.remove(makeURI("http://example.com"), "install");

  gBrowser.removeCurrentTab();
  Harness.finish();
}
