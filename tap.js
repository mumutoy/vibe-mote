/*
 * 遥控器 HID 报文旁路（Frida 脚本，挂在 WUDFHost.exe 里）
 *
 * 原理：BLE HID（HOGP）在 Windows 上是 UMDF 驱动，跑在 WUDFHost.exe 中。
 * 驱动通过 ntdll!NtDeviceIoControlFile + IOCTL 0x80018483 把 GATT 特征
 * （= HID 输入报告）读上来，报告就在这次调用的**输出缓冲区**里。
 * 在那个缓冲区上抄一份，就绕开了整个 HID 映射层。
 *
 * 只做两件事：
 *   1. 把 3 字节的遥控器报告送给 Python（内容有变化才送，避免空闲帧刷屏）
 *   2. 把「已被映射的键」的 usage 原地写 0 —— 驱动以为没按键，原生动作
 *      不再发生，于是不会「原生 + 映射」双发（音量键就不会顺带调音量）
 *
 * 为什么只认 3 字节：同一个 WUDFHost 还服务别的蓝牙键鼠，它们吐 9 字节
 * 键盘报告，混在一起。遥控器是纯 Consumer Control，固定 3 字节。
 */
const READ_IOCTL = 0x80018483;

let lastRaw = null;
let sent = 0;
let total = 0;
let blockCount = 0;
let blockUsages = {};

function toHex(ptr, len) {
  const b = new Uint8Array(ptr.readByteArray(len));
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, "0");
    if (i + 1 < b.length) s += " ";
  }
  return s;
}

/* 若这份报告是「已被映射的键」，把 usage 两字节写 0，抹掉原生动作。 */
function nullify(ptr, len) {
  if (ptr.isNull() || len !== 3) return;
  try {
    const b = new Uint8Array(ptr.readByteArray(3));
    if (b[0] !== 0x02) return;                 // 不是遥控器那份报告
    const usage = b[1] | (b[2] << 8);
    if (!usage || !blockUsages[usage]) return;
    ptr.writeByteArray([0x00, 0x00]);          // usage_lo / usage_hi = 0
    blockCount++;
  } catch (e) {
    /* 写失败就算了：最坏情况是原生动作也会发生一次 */
  }
}

recv(function (msg) {
  if (msg && msg.type === "block") {
    const next = {};
    (msg.usages || []).forEach(function (u) { next[u >>> 0] = true; });
    blockUsages = next;
    send({ kind: "block_ack", count: Object.keys(next).length });
  }
});

const ntdll = Process.findModuleByName("ntdll.dll");
const target = ntdll ? ntdll.findExportByName("NtDeviceIoControlFile") : null;
if (target === null) {
  send({ kind: "error", message: "没找到 ntdll!NtDeviceIoControlFile" });
} else {
  send({ kind: "ready", pid: Process.id });
  Interceptor.attach(target, {
    onEnter(args) {
      // 0=FileHandle 1=Event 2=ApcRoutine 3=ApcContext 4=IoStatusBlock
      // 5=IoControlCode 6=InBuf 7=InLen 8=OutBuf 9=OutLen
      total++;
      if (args[5].toUInt32() === READ_IOCTL) {
        this.cap = true;
        this.out = args[8];
        this.outLen = args[9].toUInt32();
      }
    },
    onLeave(retval) {
      if (!this.cap) return;
      this.cap = false;
      // 只认 3 字节 + 成功返回；其它长度是同一宿主里别的蓝牙键鼠
      if (retval.toUInt32() !== 0 || this.outLen !== 3 || this.out.isNull()) return;
      let raw;
      try {
        raw = toHex(this.out, 3);
      } catch (e) {
        return;
      }
      if (raw !== lastRaw) {           // 内容有变化才上报：空闲帧不再刷屏
        lastRaw = raw;
        sent++;
        send({ kind: "report", raw: raw });
      }
      // 快照已发出，现在才可以安全改写输出缓冲区
      nullify(this.out, this.outLen);
    }
  });
}

// 轻量心跳：只给 Python 做健康判断用（20 秒一次，可忽略不计）
setInterval(function () {
  send({ kind: "hb", total: total, sent: sent, blocked: blockCount });
}, 20000);
