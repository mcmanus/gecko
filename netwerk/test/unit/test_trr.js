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

XPCOMUtils.defineLazyGetter(this, "URL", function() {
  return "http://bar.example.com:" + httpserver.identity.primaryPort;
});

var httpserver = new HttpServer();
var testPathBase = "/trr";

function run_test() {
    dump ("start!\n");

    var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
    var h2Port = env.get("MOZHTTP2_PORT");
    Assert.notEqual(h2Port, null);
    Assert.notEqual(h2Port, "");

    httpserver.start(-1);

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
    //prefs.setBoolPref("network.trr.useGET", true);

    // The moz-http2 cert is for foo.example.com and is signed by CA.cert.der
    // so add that cert to the trust list as a signing cert.  // the foo.example.com domain name.
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
    addCertFromFile(certdb, "CA.cert.der", "CTu,u,u");

    // get data from bar.example.com which will only resolve fine via DOH as
    // the native resolver won't know about it
    origin = "https://localhost:" + httpserver.identity.primaryPort;
    dump ("origin - " + origin + "\n");
    do_test_pending();
    test(1);
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

function setupChannel(url)
{
  var chan = NetUtil.newChannel({
    uri: URL + url,
    loadUsingSystemPrincipal: true
  });
  var httpChan = chan.QueryInterface(Components.interfaces.nsIHttpChannel);
  return httpChan;
}

function testsDone()
{
  dump("testDone\n");
  httpserver.stop(do_test_finished);
}

function test_setup1()
{
}

function handler1(metadata, response)
{
  response.seizePower();
  response.write("HTTP/1.1 200 OK\r\n");
  response.write("Content-Type: text/plain\r\n");
  response.write("Content-Length: 9\r\n");
  response.write("\r\n");
  response.write("blablabla");
  response.finish();
}

function completeTest1(request, data, ctx)
{
  Assert.equal(request.status, Components.results.NS_OK);
  test(2);
}

function test_setup2()
{
  prefs.setIntPref("network.trr.mode", 3); // TRR-only
}

function handler2(metadata, response)
{
  response.seizePower();
  response.write("HTTP/1.1 200 OK\r\n");
  response.write("Content-Type: text/plain\r\n");
  response.write("Content-Length: 9\r\n");
  response.write("\r\n");
  response.write("blablabla");
  response.finish();
}

function completeTest2(request, data, ctx)
{
  Assert.equal(request.status, Components.results.NS_OK);
  testsDone();
}


function test(num)
{
  dump("execute test " + num + "\n");
  eval("test_setup" + num + "();");
  var testPath = testPathBase + num;
  httpserver.registerPathHandler(testPath, "handler" + num);
  var channel = setupChannel(testPath);
  flags = 0;
  channel.asyncOpen2(new ChannelListener(eval("completeTest" + num),
                                         channel, flags));
}
