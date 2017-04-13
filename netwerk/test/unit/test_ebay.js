Cu.import("resource://testing-common/httpd.js");
Cu.import("resource://gre/modules/NetUtil.jsm");

function makeChan(origin) {
  return NetUtil.newChannel({
    uri: origin,
    loadUsingSystemPrincipal: true
  }).QueryInterface(Ci.nsIHttpChannel);
}

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
    do_test_finished();
  }
};

function doTest(origin)
{
  dump("execute doTest " + origin + "\n");
  var chan = makeChan(origin);
  var listener;
  listener = new Listener();
  do_test_pending();
  chan.asyncOpen2(listener);
}

function run_test() {
    do_test_pending();
    doTest("https://i2.ebayimg.com/images/g/KUUAAOSwQjNW-sRx/s-l200.jpg");
    doTest("https://i1.ebayimg.com/images/g/ZuwAAOSwdGFYuzE2/s-l500.jpg");
doTest("https://i.ebayimg.com/images/g/OfgAAOSwdGFYynrD/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/cOEAAOSw32lYthwc/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/BewAAOSw44BYbEJS/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/PcIAAOSwnHZYU06o/s-l500.jpg");
doTest("https://i2.ebayimg.com/images/g/U7EAAOSwdGFYry-~/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/N6cAAOSwTM5YvxXL/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/uMsAAOSwuLZY5ona/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/UGwAAOSw2xRYfRxB/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/DWYAAOSwo4pYX52e/s-l500.jpg");
doTest("https://i3.ebayimg.com/images/g/7TcAAOSwx6pYpukY/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/nBAAAOSwLF1X5EAO/s-l500.jpg");
doTest("https://i3.ebayimg.com/images/g/yz0AAOSwt5hYi1yz/s-l500.jpg");
doTest("https://i.ebayimg.com/images/g/LFUAAOSw5cNYmIg6/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/R5IAAOSwTA9X6nmt/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/SA8AAOSw~AVYtIo~/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/i~oAAMXQUpZRYzQ4/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/KUUAAOSwQjNW-sRx/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/ZuwAAOSwdGFYuzE2/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/nkAAAOSw32lYztWc/s-l500.jpg");
doTest("https://i2.ebayimg.com/images/g/s~8AAOSwzgBYyTU~/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/ZrMAAOSw32lYtMGB/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/DcIAAOSwpLNX~qZz/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/7TUAAOSwjDZYaMGA/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/p24AAOSwOgdYrFG7/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/RtYAAOSwopRYZfVC/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/~tMAAOSwx2dYIoOE/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/dIgAAOSw32lYyk-O/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/OB4AAOSwImRYlf6m/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/K74AAOSwnbZYHsFO/s-l500.jpg");
doTest("https://i3.ebayimg.com/images/g/hgMAAOSw1x1UPnqb/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/6ZcAAOSwzhVWrz~u/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/4~kAAOSw--1WshwE/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/sqoAAOSw8vZXM3vp/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/K3MAAOSwpP9Y7W5J/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/8KEAAOSwCU1Ysy5n/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/xF4AAOSwXYtYsy6P/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/e10AAOSw4CFYtggF/s-l500.jpg");
doTest("https://i.ebayimg.com/images/g/-2oAAOSwB-1YwCth/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/IMUAAOSwTuJYwHEp/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/k5AAAOSwx2dYG2FS/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/BOgAAOSwARZXku3i/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/1eQAAOSw2gxYnDLw/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/wBMAAOSwV0RXqzp~/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/aq8AAOSw1DtXHYJE/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/bQoAAOSwwbdWIr2q/s-l500.jpg");
doTest("https://i3.ebayimg.com/images/g/vugAAOSwi4lXPLAx/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/DWMAAOSw9r1WCzdW/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/Iz8AAOSwVFlUIvsj/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/XoQAAOSwqu9VIsE6/s-l500.jpg");
doTest("https://i2.ebayimg.com/images/g/zUYAAOSw9GhYbUqP/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/40MAAOSw4DJYin-q/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/vg8AAOSwgQ9V0bCd/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/0cUAAOSwfVpYt0Ef/s-l500.jpg");
doTest("https://i.ebayimg.com/images/g/S3sAAOSw4A5YvaAQ/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/o9QAAOSwOgdY0uxn/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/ZBoAAOSwWxNYu3na/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/IhUAAOSwQPlV~FqD/s-l500.jpg");
doTest("https://i2.ebayimg.com/images/g/aRkAAOSw1x1UOwus/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/diIAAOSwnDxUgP4b/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/hYYAAMXQhpdRyfzJ/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/bDEAAOSwo4pYLQD7/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/X3gAAOSw9NdXtgrB/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/frwAAOSwQItULo43/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/4QwAAOSw32lYnSly/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/nVoAAOSw32lYvtEY/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/lUQAAOSw-0xYkqye/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/yTYAAOSwq7JUJXSH/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/GMoAAOSw-0xYhkYH/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/VkgAAOSwAF5UZYdz/s-l140.jpg");
doTest("https://i.ebayimg.com/images/g/gmAAAOSwsW9Y0ZLn/s-l300.jpg");
doTest("https://i.ebayimg.com/images/g/yCoAAOSw32lY0spS/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/tKkAAOSw2gxYra7C/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/LbAAAOSwd4tT46zf/s-l140.jpg");
doTest("https://i2.ebayimg.com/images/g/vXEAAOSwWxNY0tjH/s-l300.jpg");
doTest("https://i3.ebayimg.com/images/g/jv8AAOSwbwlXBZ3d/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/c24AAOSwTuJYwJEd/s-l200.png");
doTest("https://i2.ebayimg.com/images/g/8K0AAOSwCU1YswwU/s-l300.jpg");
doTest("https://i2.ebayimg.com/images/g/yX0AAOSwj85YLwK6/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/gzIAAOSwImRYGPGd/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/F0cAAOSwA3dYNLne/s-l300.jpg");
doTest("https://i3.ebayimg.com/images/g/F44AAOSwNnRYhlwJ/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/-skAAOSwB-1Yy-kI/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/fs8AAOSwpoJXDlZC/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/GfAAAOSwal5YIw0R/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/tQ8AAOSwqrtWnQqK/s-l300.jpg");
doTest("https://i3.ebayimg.com/images/g/bW4AAOSwc1FXbmBZ/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/5GwAAOSwx2dYGhii/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/Ra4AAOSwol5Y2b5s/s-l300.jpg");
doTest("https://i.ebayimg.com/images/g/Dm8AAOSw44BYgo7P/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/q~8AAOSw9GhYfo1Y/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/2qcAAOSwuxFY0rXE/s-l300.jpg");
doTest("https://i3.ebayimg.com/images/g/mK0AAOSwCU1Y0zs-/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/plgAAOSwNSxVZ2fy/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/~ogAAOSwhQhYzcZv/s-l300.jpg");
doTest("https://i3.ebayimg.com/images/g/DWkAAOSw-itXqPQr/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/IuQAAOSwYXVYy-gH/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/np4AAOSwhQhY7nXr/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/~gkAAOSwpP9Y5mpJ/s-l200.png");
doTest("https://i2.ebayimg.com/images/g/IFIAAOSw-0xYNQKo/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/hAkAAOSwrddY7jyO/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/SmYAAOSwDKtY07gt/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/Qq8AAOSwiDFYPL~0/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/fYgAAOSwax5Y0qFc/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/RigAAOSwuxFYvzr9/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/PG4AAOSwSlBY0pDu/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/LXsAAOSwc49Y7lkv/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/H2gAAOSw32lY2iHG/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/fO0AAOSwo0JWIP5n/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/ImgAAOSwrhlXTxWa/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/e~wAAOSwl9BWJdf6/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/UEAAAOSwaB5XqkYv/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/oZUAAOSw03lY7Toa/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/-MUAAOSweW5VAJnW/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/TLYAAOSw3utY7Wrg/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/4Y0AAOSwU8hY5TD1/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/yVkAAOSwYIxX~Ia3/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/sj8AAOSwdGFY0Dy6/s-l200.jpg");
doTest("https://i3.ebayimg.com/images/g/F8kAAOSwB-1Y7nGL/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/~3cAAOSw4A5YolDa/s-l200.jpg");
doTest("https://i.ebayimg.com/images/g/8M0AAOSwFe5X0Ev3/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/aKcAAOSw4DJYi7qc/s-l200.jpg");
doTest("https://i1.ebayimg.com/images/g/YigAAOSwqu9VDGFG/s-l200.jpg");
doTest("https://i2.ebayimg.com/images/g/fbcAAOSwfC9XPeWT/s-l500.jpg");
doTest("https://i1.ebayimg.com/images/g/jQIAAOSwax5YpGWu/s-l200.jpg");
    do_test_finished();
}
