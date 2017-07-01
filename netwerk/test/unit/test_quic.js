Cu.import("resource://testing-common/httpd.js");
Cu.import("resource://gre/modules/NetUtil.jsm");

// test1 uses alt-svc to bootstrap quic from h2, fetch same resource in a
// loop until the quic server (hardcoded on 4433 todo) responds

// test2 uses a proxy configuration to route all requests to a specific proxy
// (again hardcoded on 4433 todo) over quic

// ATTN: sync with testing/xpcshell/moz-http2/moz-http2.js and MozQuic.h
var alpnID = "hq-04";

var h2Port;
var quicPort = ":4433"; // todo
var prefs;
var spdypref;
var http2pref;
var quicpref;
var origin;

function run_test() {
  var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
  h2Port = env.get("MOZHTTP2_PORT");
  do_check_neq(h2Port, null);
  do_check_neq(h2Port, "");

  // Set to allow the cert presented by our H2 server
  do_get_profile();
  prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

  spdypref = prefs.getBoolPref("network.http.spdy.enabled");
  http2pref = prefs.getBoolPref("network.http.spdy.enabled.http2");
  quicpref = prefs.getBoolPref("network.http.quic.enabled");

  prefs.setBoolPref("network.http.spdy.enabled", true);
  prefs.setBoolPref("network.http.spdy.enabled.http2", true);
  prefs.setBoolPref("network.http.quic.enabled", true);
  prefs.setCharPref("network.dns.localDomains", "foo.example.com, alt1.example.com");

  // The moz-http2 cert is for {foo, alt1, alt2}.example.com and is signed by CA.cert.der
  // so add that cert to the trust list as a signing cert.
  let certdb = Cc["@mozilla.org/security/x509certdb;1"]
                  .getService(Ci.nsIX509CertDB);
  addCertFromFile(certdb, "CA.cert.der", "CTu,u,u");

  do_test_pending(); // matched in finished
  doTest1();
}

function resetPrefs() {
  prefs.setBoolPref("network.http.spdy.enabled", spdypref);
  prefs.setBoolPref("network.http.spdy.enabled.http2", http2pref);
  prefs.setBoolPref("network.http.originextension", quicpref);
  prefs.clearUserPref("network.dns.localDomains");
  prefs.clearUserPref("network.proxy.autoconfig_url");
  prefs.clearUserPref("network.proxy.type");
}

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

function makeChan(origin) {
  return NetUtil.newChannel({
    uri: origin,
    loadUsingSystemPrincipal: true
  }).QueryInterface(Ci.nsIHttpChannel);
}

var nextTest;
var forceReload = false;
var forceFailListener = false;
var iter =0;

var Listener = function() {};
Listener.prototype = {
  onStartRequest: function testOnStartRequest(request, ctx) {
    do_check_true(request instanceof Components.interfaces.nsIHttpChannel);

    if (!Components.isSuccessCode(request.status)) {
      do_throw("Channel should have a success code! (" + request.status + ")");
    }
    do_check_eq(request.responseStatus, 200);
  },

  onDataAvailable: function testOnDataAvailable(request, ctx, stream, off, cnt) {
    read_stream(stream, cnt);
  },

  onStopRequest: function testOnStopRequest(request, ctx, status) {
    do_check_true(Components.isSuccessCode(status));
    if (request.getResponseHeader("X-Firefox-Spdy") == alpnID) {
      do_check_eq(request.getResponseHeader("X-Firefox-Spdy"), alpnID);
      nextTest();
      do_test_finished();
    } else {
      dump ("waiting for quic - have " + request.getResponseHeader("X-Firefox-Spdy") + "\n");
      do_timeout(500, doTest);
    }
  }
};

var FailListener = function() {};
FailListener.prototype = {
  onStartRequest: function testOnStartRequest(request, ctx) {
    do_check_true(request instanceof Components.interfaces.nsIHttpChannel);
    do_check_false(Components.isSuccessCode(request.status));
  },
  onDataAvailable: function testOnDataAvailable(request, ctx, stream, off, cnt) {
    read_stream(stream, cnt);
  },
  onStopRequest: function testOnStopRequest(request, ctx, status) {
    do_check_false(Components.isSuccessCode(request.status));
    nextTest();
    do_test_finished();
  }
};

function testsDone()
{
  dump("testsDone\n");
   resetPrefs();
   do_test_finished();
}

function doTest()
{
  dump("execute doTest " + origin + "\n");
  var chan = makeChan(origin);
  var listener;
  if (!forceFailListener) {
    listener = new Listener();
  } else {
    listener = new FailListener();
  }
  forceFailListener = false;

  if (!forceReload) {
    chan.loadFlags = Ci.nsIChannel.LOAD_INITIAL_DOCUMENT_URI;
  } else {
    chan.loadFlags = Ci.nsIRequest.LOAD_FRESH_CONNECTION |
                     Ci.nsIChannel.LOAD_INITIAL_DOCUMENT_URI;
  }
  forceReload = false;
  chan.setRequestHeader("x-altsvc", quicPort, false);
  chan.asyncOpen2(listener);
}

function doTest1()
{
  dump("doTest1()\n");
  origin = "https://foo.example.com:" + h2Port + "/quic-bootstrap";
  nextTest = doTest2;
  do_test_pending();
  doTest();
}

function doTest2()
{
  dump("doTest2()\n");
  var pac = 'data:text/plain, function FindProxyForURL(url, host) {return "QUIC localhost:4443";}';
  origin = "https://foo.example.com:" + h2Port + "/quic-2";
  prefs.setIntPref("network.proxy.type", 2);
  prefs.setCharPref("network.proxy.autoconfig_url", pac);
  nextTest = testsDone;
  do_test_pending();
  doTest();
}
