//
// GET
//

Cu.import("resource://testing-common/httpd.js");
Cu.import("resource://gre/modules/Services.jsm");


function run_test() {
  var channel = setupChannel1();
  channel.requestMethod = "GET";
    channel.asyncOpen(new ChannelListener(checkRequest1, channel, CL_EXPECT_GZIP), null);
  do_test_pending();
}

function setupChannel1(path) {
  var ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
    return ios.newChannel2(
	"http://www.ducksong.com/misc/8k.txt",
                               "",
                               null,
                               null,      // aLoadingNode
                               Services.scriptSecurityManager.getSystemPrincipal(),
                               null,      // aTriggeringPrincipal
                               Ci.nsILoadInfo.SEC_NORMAL,
                               Ci.nsIContentPolicy.TYPE_OTHER)
                   .QueryInterface(Ci.nsIHttpChannel);
}

function checkRequest1x(request, data, context) {
    do_test_finished();
}

function checkRequest1(request, data, context) {
  var channel = setupChannel2();
  channel.requestMethod = "GET";
  channel.asyncOpen(new ChannelListener(checkRequest2, channel), null);
}

function setupChannel2(path) {
  var ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
  return ios.newChannel2(
	"https://www.ducksong.com/misc/sl.gif",
                               "",
                               null,
                               null,      // aLoadingNode
                               Services.scriptSecurityManager.getSystemPrincipal(),
                               null,      // aTriggeringPrincipal
                               Ci.nsILoadInfo.SEC_NORMAL,
                               Ci.nsIContentPolicy.TYPE_OTHER)
                   .QueryInterface(Ci.nsIHttpChannel);
}

function checkRequest2(request, data, context) {
    do_test_finished();
}
