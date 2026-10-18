// native_ssl_bypass — native 层证书校验绕过:hook libssl/boringssl 的
// SSL_CTX_set_verify/SSL_set_verify 置 no-op、SSL_get_verify_result 恒返 0。
// 覆盖 Unity/xlua/自编译 curl/部分 Flutter;纯 Java 层校验用 ssl_pinning_bypass.js。
// 来源:全链哨兵 11ee8e99 内建脚本。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
(function () {
  ["libssl.so", "libcrypto.so", "libconscrypt_jni.so"].forEach(function (lib) {
    var mod = Process.findModuleByName(lib);
    if (!mod) return;
    ["SSL_CTX_set_verify", "SSL_set_verify"].forEach(function (fn) {
      var addr = Module.findExportByName(lib, fn);
      if (addr) {
        Interceptor.replace(addr, new NativeCallback(function () {}, "void", ["pointer", "int", "pointer"]));
        console.log("[*] " + lib + "!" + fn + " -> no-op");
      }
    });
    var gv = Module.findExportByName(lib, "SSL_get_verify_result");
    if (gv) {
      Interceptor.replace(gv, new NativeCallback(function () { return 0; }, "long", ["pointer"]));
      console.log("[*] " + lib + "!SSL_get_verify_result -> X509_V_OK");
    }
  });
  console.log("[*] native ssl bypass installed");
})();
