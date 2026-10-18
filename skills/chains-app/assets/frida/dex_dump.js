// dex_dump — 内存脱壳(FRIDA-DEXDump 风格):扫描进程内存中的 dex magic 并
// 落盘到 /data/local/tmp/sentinel-unpack/。配合 spawn 模式在壳解密完成后收集;
// 抽取壳(函数体 nop)dump 出的方法体仍是空的。
// 说明:平台 droid_unpack 工具内嵌的就是这份脚本;单独手动跑时经
// device_exec + 隧道 frida 使用。源自哨兵 11ee8e99,有一处刻意偏离:去掉了
// Java.perform 包裹(其唯一职责是 mkdir,已由工具 root 预建目录承接)——
// frida 17.24.1 + Android 16 组合下,加载期执行 Java.perform 会直接杀死
// spawn 会话(真机 8/8 复现,纯 gum 操作不受影响)。
var SENTINEL_PARAMS = {};
function sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }
(function () {
  var SAVE_DIR = "/data/local/tmp/sentinel-unpack";
  var dumped = {};
  var count = 0;
  function dumpDex(addr) {
    try {
      var magic = new Uint8Array(Memory.readByteArray(addr, 4));
      if (magic[0] !== 0x64 || magic[1] !== 0x65 || magic[2] !== 0x78 || magic[3] !== 0x0a) return;
      var fileSize = Memory.readU32(addr.add(32));
      if (fileSize < 112 || fileSize > 120 * 1024 * 1024) return;
      var key = addr.toString() + ":" + fileSize;
      if (dumped[key]) return;
      dumped[key] = true;
      var path = SAVE_DIR + "/classes_" + addr.toString(16) + "_" + fileSize + ".dex";
      var f = new File(path, "wb");
      f.write(Memory.readByteArray(addr, fileSize));
      f.close();
      count++;
      console.log("[dexdump] saved " + path);
    } catch (e) {}
  }
  function scan() {
    var ranges = Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-"));
    ranges.forEach(function (range) {
      if (range.size < 112 || range.size > 120 * 1024 * 1024) return;
      try {
        Memory.scan(range.base, range.size, "64 65 78 0a 30 33", {
          onMatch: function (addr) { dumpDex(addr); },
          onComplete: function () {},
        });
      } catch (e) {}
    });
  }
  setTimeout(scan, 500);
  setTimeout(scan, 8000);
  setTimeout(function () { console.log("[dexdump] finished, " + count + " dex saved to " + SAVE_DIR); }, 9000);
})();
