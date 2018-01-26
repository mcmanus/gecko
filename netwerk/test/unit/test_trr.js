Cu.import("resource://testing-common/httpd.js");
Cu.import("resource://gre/modules/NetUtil.jsm");

var prefs;
var spdypref;
var http2pref;
var rcwnpref;
var modepref;
var uripref;
var portalpref;
var getpref;
var confirmationpref;
var origin;

function run_test() {
    dump ("start!\n");
    
    var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
    var h2Port = env.get("MOZHTTP2_PORT");
    Assert.notEqual(h2Port, null);
    Assert.notEqual(h2Port, "");

    // Set to allow the cert presented by our H2 server
    do_get_profile();
    prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

    spdypref = prefs.getBoolPref("network.http.spdy.enabled");
    http2pref = prefs.getBoolPref("network.http.spdy.enabled.http2");
    rcwnpref = prefs.getBoolPref("network.http.rcwn.enabled");

    modepref = prefs.getIntPref("network.trr.mode");
    uripref = prefs.getCharPref("network.trr.uri");
    portalpref = prefs.getBoolPref("network.trr.wait-for-portal");
    getpref = prefs.getBoolPref("network.trr.useGET");
    confirmationpref = prefs.getCharPref("network.trr.confirmationNS");
    
    prefs.setBoolPref("network.http.spdy.enabled", true);
    prefs.setBoolPref("network.http.spdy.enabled.http2", true);
    prefs.setCharPref("network.dns.localDomains", "foo.example.com, bar.example.com");
    // Disable rcwn to make cache behavior deterministic.
    prefs.setBoolPref("network.http.rcwn.enabled", false);

    // use the h2 server as DOH provider
    prefs.setCharPref("network.trr.uri", "https://foo.example.com:" + h2Port + "/dns");
    prefs.setIntPref("network.trr.mode", 3);
    prefs.setBoolPref("network.trr.wait-for-portal", false);

    // The moz-http2 cert is for foo.example.com and is signed by CA.cert.der
    // so add that cert to the trust list as a signing cert.  // the foo.example.com domain name.
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
    addCertFromFile(certdb, "CA.cert.der", "CTu,u,u");

    // get data from the same host we use as DOH server
    origin = "https://foo.example.com:" + h2Port;
    dump ("origin - " + origin + "\n");
    doTest1();
}

function resetTRRPrefs() {
    prefs.setIntPref("network.trr.mode", modepref);
    prefs.setCharPref("network.trr.uri", uripref);
    prefs.setBoolPref("network.trr.wait-for-portal", portalpref);
    prefs.setBoolPref("network.trr.useGET", getpref);
    prefs.setCharPref("network.trr.confirmationNS", confirmationpref);
}

function resetPrefs() {
    prefs.setBoolPref("network.http.spdy.enabled", spdypref);
    prefs.setBoolPref("network.http.spdy.enabled.http2", http2pref);
    prefs.setBoolPref("network.http.rcwn.enabled", rcwnpref);
    prefs.clearUserPref("network.dns.localDomains");
    resetTRRPrefs();
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

function makeChan(origin, path) {
  return NetUtil.newChannel({
    uri: origin + path,
    loadUsingSystemPrincipal: true
  }).QueryInterface(Ci.nsIHttpChannel);
}

var nextTest;
var expectPass = true;

var Listener = function() {};
Listener.prototype = {
  onStartRequest: function testOnStartRequest(request, ctx) {
    Assert.ok(request instanceof Components.interfaces.nsIHttpChannel);

 //   if (expectPass) {
 //     Assert.equal(request.responseStatus, 200);
 //   } else {
 //     Assert.equal(Components.isSuccessCode(request.status), false);
 //   }
  },

  onDataAvailable: function testOnDataAvailable(request, ctx, stream, off, cnt) {
    read_stream(stream, cnt);
  },

  onStopRequest: function testOnStopRequest(request, ctx, status) {
      Assert.equal(request.responseStatus, 200);
      nextTest();
      do_test_finished();
  }
};

function testsDone()
{
  dump("testDone\n");
  resetPrefs();
}

function doTest1()
{
  dump("execute doTest1 - basic TRR\n");
  do_test_pending();
  var chan = makeChan(origin, "/basic-trr");
  var listener = new Listener();
  nextTest = doTest2;
  chan.asyncOpen2(listener);
}

function doTest2()
{
  dump("execute doTest2 - cached DNS response\n");
  do_test_pending();
  var chan = makeChan(origin, "/trr-again");
  var listener = new Listener();
  nextTest = testsDone;
  chan.asyncOpen2(listener);
}
