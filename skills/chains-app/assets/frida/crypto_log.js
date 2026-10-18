// crypto_log — 打印 javax.crypto 的算法、密钥与明文(Cipher 与 Mac 的 doFinal),
// 用于还原自定义加解密。参数:alg=算法子串过滤(如 "AES"、"DES"、"HmacSHA256")。
// 来源:全链哨兵 11ee8e99 内建脚本(Cipher 无公开 opmode getter,改为 init 记录)。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
Java.perform(function () {
  var algFilter = sp("alg", "");
  function b64(bytes) {
    return Java.use("android.util.Base64").encodeToString(bytes, 2);
  }
  function logCipher(cipher, input, result) {
    try {
      var alg = cipher.getAlgorithm();
      if (algFilter !== "" && alg.indexOf(algFilter) < 0) return;
      var mode = cipher._sentinelMode === 1 ? "ENCRYPT" : cipher._sentinelMode === 2 ? "DECRYPT" : "UNKNOWN";
      console.log("[crypto] " + alg + " " + mode);
      console.log("[crypto][in ] " + b64(input));
      console.log("[crypto][out] " + b64(result));
    } catch (e) {}
  }
  // Cipher has no public opmode getter: remember it from init. The first
  // init overload takes opmode as its own first argument, the spec variants as
  // their second.
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
    this._sentinelMode = opmode;
    try { console.log("[crypto][key] " + this.getAlgorithm() + " " + b64(key.getEncoded())); } catch (e) {}
    return this.init(opmode, key);
  };
  Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation =
    function (opmode, key, spec) {
      this._sentinelMode = opmode;
      try { console.log("[crypto][key] " + this.getAlgorithm() + " " + b64(key.getEncoded())); } catch (e) {}
      try { console.log("[crypto][spec] " + spec); } catch (e) {}
      return this.init(opmode, key, spec);
    };
  Cipher.doFinal.overload("[B").implementation = function (input) {
    var result = this.doFinal(input);
    logCipher(this, input, result);
    return result;
  };
  try {
    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload("[B").implementation = function (input) {
      var result = this.doFinal(input);
      try {
        var alg = this.getAlgorithm();
        if (algFilter === "" || alg.indexOf(algFilter) >= 0) {
          console.log("[mac] " + alg + " in=" + b64(input) + " out=" + b64(result));
        }
      } catch (e) {}
      return result;
    };
  } catch (e) {}
  console.log("[*] crypto logger installed" + (algFilter ? " (alg contains '" + algFilter + "')" : ""));
});
