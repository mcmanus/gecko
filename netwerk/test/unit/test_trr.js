Cu.import("resource://gre/modules/NetUtil.jsm");

var prefs;
var origin;
var h2Port;

var dns = Cc["@mozilla.org/network/dns-service;1"].getService(Ci.nsIDNSService);
var threadManager = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
var mainThread = threadManager.currentThread;

const defaultOriginAttributes = {};

function run_test() {
  dump ("start!\n");

  var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
  h2Port = env.get("MOZHTTP2_PORT");
  Assert.notEqual(h2Port, null);
  Assert.notEqual(h2Port, "");

  // Set to allow the cert presented by our H2 server
  do_get_profile();
  prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

  prefs.setBoolPref("network.http.spdy.enabled", true);
  prefs.setBoolPref("network.http.spdy.enabled.http2", true);
  // make 'foo.example.com' equal localhost so that we can reach that DNS
  // server
  prefs.setCharPref("network.dns.localDomains", "foo.example.com");
  // Disable rcwn to make cache behavior deterministic.
  prefs.setBoolPref("network.http.rcwn.enabled", false);

  // use the h2 server as DOH provider
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns");
  // 0 - off, 1 - race, 2 TRR first, 3 TRR only, 4 shadow
  prefs.setIntPref("network.trr.mode", 2); // TRR first
  prefs.setBoolPref("network.trr.wait-for-portal", false);
  // don't confirm that TRR is working, just go!
  prefs.setCharPref("network.trr.confirmationNS", "skip");

  // The moz-http2 cert is for foo.example.com and is signed by CA.cert.der
  // so add that cert to the trust list as a signing cert.  // the foo.example.com domain name.
  let certdb = Cc["@mozilla.org/security/x509certdb;1"]
      .getService(Ci.nsIX509CertDB);
  addCertFromFile(certdb, "CA.cert.der", "CTu,u,u");
  do_test_pending();
  run_dns_tests();
}

function resetTRRPrefs() {
    prefs.clearUserPref("network.trr.mode");
    prefs.clearUserPref("network.trr.uri");
    prefs.clearUserPref("network.trr.wait-for-portal");
    prefs.clearUserPref("network.trr.useGET");
    prefs.clearUserPref("network.trr.confirmationNS");
}

registerCleanupFunction(() => {
    prefs.clearUserPref("network.http.spdy.enabled");
    prefs.clearUserPref("network.http.spdy.enabled.http2");
    prefs.clearUserPref("network.http.rcwn.enabled");
    prefs.clearUserPref("network.dns.localDomains");
    resetTRRPrefs();
});

function readFile(file) {
  let fstream = Cc["@mozilla.org/network/file-input-stream;1"]
                  .createInstance(Ci.nsIFileInputStream);
  fstream.init(file, -1, 0, 0);
  let data = NetUtil.readInputStreamToString(fstream, fstream.available());
  fstream.close();
  return data;
}

function addCertFromFile(certdb, filename, trustString) {
  let certFile = do_get_file(filename, false);
  let der = readFile(certFile);
  certdb.addCert(der, trustString);
}

function testsDone()
{
  dump("testDone\n");
  do_test_finished();
}

var test_answer="127.0.0.1";
var nexttest;

// check that we do lookup the name fine
var listenerFine = {
  onLookupComplete: function(inRequest, inRecord, inStatus) {
    Assert.notEqual(inRecord, null);
    var answer = inRecord.getNextAddrAsString();
    Assert.equal(answer, test_answer);
    do_test_finished();
    eval("test" + nexttest + "();");
  },
  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.nsIDNSListener) ||
        aIID.equals(Ci.nsISupports)) {
      return this;
    }
    throw Cr.NS_ERROR_NO_INTERFACE;
  }
};

// check that the name lookup fails
var listenerFails = {
  onLookupComplete: function(inRequest, inRecord, inStatus) {
    Assert.ok(!Components.isSuccessCode(inStatus));
    do_test_finished();
    eval("test" + nexttest + "();");
  },
  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.nsIDNSListener) ||
        aIID.equals(Ci.nsISupports)) {
      return this;
    }
    throw Cr.NS_ERROR_NO_INTERFACE;
  }
};

// verify basic A record
function test1()
{
  dump("execute test1\n");
  nexttest=2;
  prefs.setIntPref("network.trr.mode", 2); // TRR-first
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns");
  do_test_pending();
  dns.asyncResolve("bar.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// verify that the name was put in cache - it works with bad DNS URI
function test2()
{
  dump("execute test1\n");
  nexttest=3;
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/404");
  do_test_pending();
  dns.asyncResolve("bar.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// verify working credentials in DOH request
function test3()
{
  dump("execute test3\n");
  nexttest=4;
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-auth");
  prefs.setCharPref("network.trr.credentials", "user:password");
  do_test_pending();
  dns.asyncResolve("auth.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// verify failing credentials in DOH request
function test4()
{
  dump("execute test4\n");
  nexttest=6; // skips the push test for now
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-auth");
  prefs.setCharPref("network.trr.credentials", "evil:person");
  do_test_pending();
  dns.asyncResolve("wrong.example.com", 0, listenerFails, mainThread, defaultOriginAttributes);
}

// verify DOH push, part A
function test5()
{
  dump("execute test5\n");
  nexttest="5b";
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-push");
  do_test_pending();
  dns.asyncResolve("first.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

function test5b()
{
  dump("execute test5b\n");
  nexttest="sDone";
  // At this point the second host name should've been pushed and we can resolve it using
  // cache only. Set back the URI to a path that fails.
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/404");
  dump("test5b - resolve push.example.now please\n");
  test_answer="2018::2018";
  do_test_pending();
  dns.asyncResolve("push.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// verify AAAA entry
function test6()
{
  dump("execute test6\n");
  nexttest=7;
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-aaaa");
  test_answer="2020:2020::2020";
  do_test_pending();
  dns.asyncResolve("aaaa.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// verify RFC1918 address from the server is rejected
function test7()
{
  dump("execute test7\n");
  nexttest=8;
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-rfc1918");
  do_test_pending();
  dns.asyncResolve("rfc1918.example.com", 0, listenerFails, mainThread, defaultOriginAttributes);
}

// verify RFC1918 address from the server is fine when told so
function test8()
{
  dump("execute test8\n");
  nexttest=9;
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-rfc1918");
  prefs.setBoolPref("network.trr.allow-rfc1918", true);
  test_answer="192.168.0.1";
  do_test_pending();
  dns.asyncResolve("rfc1918.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

// use GET
function test9()
{
  dump("execute test9\n");
  nexttest="sDone";
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
  prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns-get");
  prefs.clearUserPref("network.trr.allow-rfc1918");
  prefs.setBoolPref("network.trr.useGET", true);
  test_answer="1.2.3.4";
  do_test_pending();
  dns.asyncResolve("get.example.com", 0, listenerFine, mainThread, defaultOriginAttributes);
}

function run_dns_tests()
{
  test1();
  //test5();
}
