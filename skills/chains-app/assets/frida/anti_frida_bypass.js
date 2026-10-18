// anti_frida_bypass — 反调试/反 frida 绕过:ptrace 恒 0、strstr 拦
// frida/gum/gadget 字符串、27042 端口 connect 探测失效。app 闪退或自行检测到
// frida 时先跑这个(放在脚本列表第一个)。
// 来源:全链哨兵 11ee8e99 内建脚本。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
(function () {
  var ptrace = Module.findExportByName(null, "ptrace");
  if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function () { return 0; }, "long", ["int", "int", "pointer", "pointer"]));
    console.log("[*] ptrace -> 0");
  }
  var strstr = Module.findExportByName(null, "strstr");
  if (strstr) {
    var needles = ["frida", "gum-js", "gadget", "linjector"];
    Interceptor.attach(strstr, {
      onEnter: function (args) { this.needleStr = Memory.readCString(args[1]); },
      onLeave: function (ret) {
        if (!this.needleStr) return;
        for (var i = 0; i < needles.length; i++) {
          if (this.needleStr.indexOf(needles[i]) >= 0) { ret.replace(ptr(0)); return; }
        }
      },
    });
    console.log("[*] strstr filter installed");
  }
  var connect = Module.findExportByName(null, "connect");
  if (connect) {
    Interceptor.attach(connect, {
      onEnter: function (args) {
        // sockaddr_in: family(u16), port(u16, big-endian). 27042 = 0x69A2.
        this.blocked =
          Memory.readU16(args[1]) === 2 &&
          Memory.readU8(args[1].add(2)) === 0x69 &&
          Memory.readU8(args[1].add(3)) === 0xa2;
        if (this.blocked) console.log("[*] blocked connect to 27042 (frida port probe)");
      },
      onLeave: function (ret) { if (this.blocked) ret.replace(-1); },
    });
  }
  console.log("[*] anti-frida bypass installed");
})();
