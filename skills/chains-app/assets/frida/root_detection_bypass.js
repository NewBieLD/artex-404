// root_detection_bypass — 常见 root 检测绕过:File.exists 拦 su/magisk/ksu
// 路径、Runtime.exec 单参数与 String[] 两种都拦、build tag 改 release-keys、
// PackageManager 隐藏 magisk/supersu/kernelsu 包名。
// 来源:全链哨兵 11ee8e99 内建脚本(实战修复版,含 KernelSU 路径)。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
Java.perform(function () {
  var File = Java.use("java.io.File");
  var paths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk",
    "/system/bin/magisk", "/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ksud",
    "/system/bin/busybox", "/debug_ramdisk", "/su/bin/su"];
  File.$init.overload("java.lang.String").implementation = function (path) {
    for (var i = 0; i < paths.length; i++) if (path === paths[i]) path = "/nonexistent";
    return this.$init(path);
  };
  var Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
    if (cmd.indexOf("which") >= 0 && (cmd.indexOf("su") >= 0 || cmd.indexOf("magisk") >= 0)) {
      console.log("[*] blocked exec: " + cmd);
      return this.exec("echo");
    }
    return this.exec(cmd);
  };
  Runtime.exec.overload("[Ljava.lang.String;").implementation = function (argv) {
    for (var i = 0; i < argv.length; i++) {
      var a = argv[i];
      if (a === "su" || a === "which" || a.indexOf("magisk") >= 0 || a.indexOf("busybox") >= 0) {
        console.log("[*] blocked exec[]: " + argv.join(" "));
        return this.exec("echo");
      }
    }
    return this.exec(argv);
  };
  var Build = Java.use("android.os.Build");
  Build.TAGS.value = "release-keys";
  try {
    var PM = Java.use("android.app.ApplicationPackageManager");
    var hidden = ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser", "me.weishu.kernelsu"];
    PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
      if (hidden.indexOf(pkg) >= 0) {
        console.log("[*] hid package from getPackageInfo: " + pkg);
        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
      }
      return this.getPackageInfo(pkg, flags);
    };
  } catch (e) {}
  console.log("[*] root detection bypass installed");
});
