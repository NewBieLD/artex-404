// okhttp_log — 打印 OkHttp 每个请求/响应的明文(方法、URL、头、体)。
// 参数:url=子串过滤(只打印 URL 含该子串的请求),如 {"url":"/api"}。
// 适用 OkHttp3/4 网络库;自定义 socket/自研协议看不到。
// 来源:全链哨兵 11ee8e99 内建脚本(实战修复版)。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
Java.perform(function () {
  var filter = sp("url", "");
  var Builder = Java.use("okhttp3.Request$Builder");
  Builder.build.overload().implementation = function () {
    var req = this.build();
    try {
      var url = req.url().toString();
      if (filter === "" || url.indexOf(filter) >= 0) {
        console.log("[okhttp] " + req.method() + " " + url);
        var body = req.body();
        if (body !== null) {
          var buf = Java.use("okio.Buffer").$new();
          body.writeTo(buf);
          console.log("[okhttp][body] " + buf.readUtf8());
        }
      }
    } catch (e) { console.log("[okhttp][err] " + e); }
    return req;
  };
  console.log("[*] okhttp request logger installed" + (filter ? " (url contains '" + filter + "')" : ""));
});
