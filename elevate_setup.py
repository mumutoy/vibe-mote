# -*- coding: utf-8 -*-
"""一次性优化（需要管理员，由主程序用 UAC 拉起 —— **只会弹这一次**）。

干三件事：

 1. **清掉 Frida 的历史残留**。Frida 每次挂载不属于自己的进程时，都会尝试注册
    一个临时服务 `frida-<pid>-x86/x86_64` 来注入；注册服务需要管理员，于是每
    次尝试都会弹一次 UAC；没批准或中途中断就留下一条死服务。残留会随重启不断累积，
    攒到几十条服务 + 一堆 frida-helper 进程都很常见。

 2. **装一个「最高权限 + 登录时触发」的计划任务来做开机自启**。
    为什么不用更简单的 HKCU Run 项：普通权限启动时，Frida 装它的助手要提权，
    于是**每次开机都要弹一次 UAC**。改成最高权限的计划任务后，开机由任务计划
    程序以管理员身份静默启动 —— Frida 要的权限都是现成的，**再也不会弹**。

 3. 删掉 HKCU Run 里的普通权限自启项，避免两份同时启动抢遥控器的蓝牙通道。

过程写进同目录的 elevate_setup.log，非提权的主程序会读它并显示给你看。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import winreg
import xml.sax.saxutils as sx

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "elevate_setup.log")
XML = os.path.join(HERE, "_task.xml")
TASK_NAME = "VibeMote"
VBS = os.path.join(HERE, "启动遥控器.vbs")
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
CREATE_NO_WINDOW = 0x08000000


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _dec(b: bytes) -> str:
    """子进程输出编码不能写死：schtasks/sc 吐 GBK，python 子进程吐 UTF-8。
    写死一个就会把中文变成「涓嶅彲鐢」那种乱码。"""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return p.returncode, _dec(p.stdout or b"") + _dec(p.stderr or b"")
    except Exception as e:
        return -1, repr(e)


# ---------------------------------------------------------------- 1. 清残留
def cleanup_frida():
    total_killed = 0
    for exe in ("frida-helper-x86.exe", "frida-helper-x86_64.exe"):
        rc, out = run(["taskkill", "/IM", exe, "/F"])
        killed = out.lower().count("success") + out.count("成功")
        total_killed += killed
    if total_killed:
        log(f"已结束 {total_killed} 个 frida-helper 进程")
    else:
        log("没有 frida-helper 进程在跑")

    names = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services") as k:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError as e:
        log(f"读服务列表失败：{e}")
        return
    targets = [n for n in names if n.lower().startswith("frida-")]
    log(f"发现 {len(targets)} 条 frida-* 残留服务，开始删除…")
    ok = 0
    for n in targets:
        rc, _ = run(["sc.exe", "delete", n])
        if rc == 0:
            ok += 1
    log(f"已删除 {ok}/{len(targets)} 条")


# ---------------------------------------------------------------- 2. 装任务
def task_xml(run_level="HighestAvailable"):
    user = os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")
    # ★ 必须带 `--boot`：它标记"这一份是开机自启拉起来的"，
    #   程序靠它关掉"首次启动自动拉起虚拟声卡安装器"那条路（见 app.py 里 auto_ok 的注释）。
    #   漏了的话，开机时如果声卡不在了就会在开机那一刻弹安装器 + UAC —— 那正是
    #   用户最不想要的"开机弹窗"。
    args = sx.escape(f'"{VBS}" --silent --boot')
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>VibeMote - Google TV remote bridge (voice key + key mapping)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT8S</Delay>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>false</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{sx.escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{run_level}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>{args}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def install_task(run_level="HighestAvailable", name=TASK_NAME):
    # 任务定义用 UTF-16 写，schtasks 读 XML 时按声明解码，中文路径不会乱
    with open(XML, "w", encoding="utf-16") as f:
        f.write(task_xml(run_level))
    rc, out = run(["schtasks", "/create", "/tn", name, "/xml", XML, "/f"])
    head = (out or "").strip().splitlines()
    log(f"计划任务：返回码 {rc}  {' / '.join(head[:2]) if head else ''}")
    try:
        os.remove(XML)
    except OSError:
        pass
    return rc == 0


# ---------------------------------------------------------------- 3. 清 Run 项
def remove_run_entry():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            try:
                winreg.DeleteValue(k, TASK_NAME)
                log("已删除 HKCU Run 里的自启项（改用计划任务，避免两份同时启动）")
            except FileNotFoundError:
                log("HKCU Run 里本来就没有自启项")
    except OSError as e:
        log(f"处理 Run 项失败（不影响计划任务）：{e}")


# ------------------------------------------------------- 4. 用新代码重启客户端
UI_PORT = 8787


def port_owners(port):
    """谁正在监听这个端口（解析 netstat，不依赖任何第三方库）。"""
    rc, out = run(["netstat", "-ano"])
    pids = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}") \
                and parts[3].upper() == "LISTENING":
            try:
                pids.append(int(parts[4]))
            except ValueError:
                pass
    return sorted(set(pids))


def restart_client():
    """结束旧客户端，再用计划任务拉起当前目录里的新代码。

    为什么必须由管理员进程来做：客户端自己是最高权限跑的，**普通权限杀不掉它**
    （Stop-Process / taskkill 在普通权限下都是 Access is denied）。所以「换了代码怎么
    生效」这件事，正好借这一次提权一起办掉；之后想重启，用界面「状态 → 重启」
    即可 —— 应用内的 restart-app 动作会以自身权限拉起新实例并接管，不再需要 UAC。
    """
    old = port_owners(UI_PORT)
    if not old:
        log("没有正在运行的客户端（跳过重启）")
    for pid in old:
        log(f"结束旧客户端 PID {pid}")
        run(["taskkill", "/PID", str(pid), "/T", "/F"])
    for _ in range(40):
        if not port_owners(UI_PORT):
            break
        time.sleep(0.25)
    rc, out = run(["schtasks", "/run", "/tn", TASK_NAME])
    log(f"用计划任务重新启动客户端：返回码 {rc}")
    for _ in range(40):
        if port_owners(UI_PORT):
            log(f"客户端已起来（PID {port_owners(UI_PORT)}），界面 http://127.0.0.1:{UI_PORT}/")
            return True
        time.sleep(0.5)
    log("客户端没在 20 秒内起来，可双击「启动遥控器.vbs」手动拉起")
    return False


def reset_bluetooth():
    """禁用再启用蓝牙电台 —— 拆掉"被系统 HID 攥住"的那条 BLE 连接。

    BLE 外设只接受**一个**连接。Windows 的 HID 栈有时会把那条唯一的连接攥住不放，
    遥控器因此不再广播，而程序要自己建一条 GATT 连接才能收语音 → "永远连不上"
    （表现：日志一直刷连接超时，但按键还有用）。拔电池/关开蓝牙开关能解开，
    这个动作等于"用代码关开一次蓝牙电台"。
    """
    # 蓝牙电台是 USB 上的（如 Intel USB\VID_8087&PID_0033）；BTHLE\ 那些是设备，不能停
    ps = (
        "$d = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InstanceId -like 'USB*' -and $_.Status -eq 'OK' });"
        "if ($d.Count -eq 0) { Write-Output 'NO-RADIO'; exit 3 };"
        "foreach ($x in $d) {"
        " Write-Output ('禁用 ' + $x.FriendlyName);"
        " Disable-PnpDevice -InstanceId $x.InstanceId -Confirm:$false -ErrorAction Stop;"
        " Start-Sleep -Seconds 3;"
        " Write-Output ('启用 ' + $x.FriendlyName);"
        " Enable-PnpDevice -InstanceId $x.InstanceId -Confirm:$false -ErrorAction Stop }"
        "Write-Output 'OK'"
    )
    rc, out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                  timeout=120)
    for line in (out or "").splitlines():
        if line.strip():
            log("  " + line.strip())
    return rc == 0 and "OK" in (out or "")


def main():
    # 只重置蓝牙电台（不动自启/任务）：给界面上那个「重置蓝牙电台」按钮用
    if "--reset-bt" in sys.argv:
        try:
            open(LOG, "w", encoding="utf-8").close()
        except Exception:
            pass
        log("=== 重置蓝牙电台 ===")
        if not is_admin():
            log("✗ 当前不是管理员，什么都没做。请从界面点按钮并在 UAC 里点「是」。")
            log("DONE")
            return 1
        log("管理员权限 ✓（期间蓝牙设备会短暂断开，几秒后自动恢复）")
        ok = reset_bluetooth()
        log("✓ 已重置，等待自动重连…" if ok else "✗ 重置失败（可以手动：设置 → 蓝牙开关关开一次）")
        log("DONE")
        return 0 if ok else 1
    try:
        open(LOG, "w", encoding="utf-8").close()
    except Exception:
        pass
    log("=== 一次性优化开始 ===")
    if not is_admin():
        log("✗ 当前不是管理员，什么都没做。请从界面点「一键优化」并在 UAC 里点「是」。")
        log("DONE")
        return 1
    log("管理员权限 ✓")
    cleanup_frida()
    if install_task():
        remove_run_entry()
        log("✓ 开机自启已改为「最高权限计划任务」：以后开机静默以管理员身份启动，")
        log("  Frida 需要的权限现成，**不会再弹任何 UAC**。")
    else:
        log("✗ 计划任务没建成。可以只做第一步（清残留）也不影响使用；")
        log("  自启仍走 HKCU Run（那种方式每次开机 Frida 可能要你授权一次）。")
    restart_client()
    log("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
