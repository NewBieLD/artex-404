// ssl_pinning_bypass — 通用证书校验绕过:TrustManager/HostnameVerifier/OkHttp
// CertificatePinner(含 4.x check$okhttp)/NetworkSecurityConfig 一起打。
// Java 层通用;native 层 pinning 请另跑 native_ssl_bypass.js。
// 来源:全链哨兵 11ee8e99 内建脚本(实战修复版,含 OkHttp 4.x Kotlin 改名 hook)。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
Java.perform(function () {
  var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  var SSLContext = Java.use("javax.net.ssl.SSLContext");
  var TrustManager = Java.registerClass({
    name: "com.sentinel.TrustAll",
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function () {},
      checkServerTrusted: function () {},
      getAcceptedIssuers: function () { return []; },
    },
  });
  SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
    .implementation = function (km, tm, sr) {
      console.log("[*] SSLContext.init -> trust all");
      this.init(km, [TrustManager.$new()], sr);
    };
  var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
  var VerifyAll = Java.registerClass({
    name: "com.sentinel.VerifyAll",
    implements: [HostnameVerifier],
    methods: { verify: function () { return true; } },
  });
  try {
    Java.use("javax.net.ssl.HttpsURLConnection").setHostnameVerifier.implementation = function (v) {
      this.setHostnameVerifier(VerifyAll.$new());
    };
  } catch (e) {}
  try {
    var pinner = Java.use("okhttp3.CertificatePinner");
    pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
      console.log("[*] OkHttp CertificatePinner.check bypassed: " + arguments[0]);
    };
  } catch (e) {}
  try {
    // OkHttp 4.x: the Kotlin compiler renamed check to check$okhttp.
    Java.use("okhttp3.CertificatePinner")["check$okhttp"].overload(
      "java.lang.String",
      "kotlin.jvm.functions.Function0",
      "java.util.Set",
    ).implementation = function (hostname) {
      console.log("[*] OkHttp check$okhttp bypassed: " + hostname);
    };
  } catch (e) {}
  try {
    // NetworkSecurityConfig: stop rejecting user-added CAs.
    var NSC = Java.use("android.security.net.config.NetworkSecurityTrustManager");
    NSC.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.net.Socket")
      .implementation = function () {};
  } catch (e) {}
  console.log("[*] SSL pinning bypass installed");
});
