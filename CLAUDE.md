# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目

VibeMote：把 Google TV / Chromecast 蓝牙遥控器变成 Windows 的「按住说话 + 快捷键」设备。
纯用户态单进程 Python 程序，网页控制台只监听 `127.0.0.1:8787`。约 9 个源文件、第三方依赖仅 3 个（bleak / sounddevice / cffi），按键映射可选依赖 frida。

**没有测试套件、没有 linter**。验证方式见下面「命令」一节。

## 命令

```powershell
# 环境准备（依赖装进包内 .venv，不污染系统 Python）
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt        # 语音必需
.venv\Scripts\python.exe -m pip install -r requirements-keys.txt   # 按键映射可选（frida，约 130MB）

# 运行（生产入口是双击 启动遥控器.vbs；开发时直接跑）
.venv\Scripts\python.exe app.py              # 起服务并开浏览器
.venv\Scripts\python.exe app.py --silent     # 只起服务不开浏览器
.venv\Scripts\python.exe app.py --no-start   # 只开界面，不启动语音/按键角色
.venv\Scripts\python.exe app.py --selftest   # 验证全部模块可 import（改完 import 结构必跑）

# 冒烟测试：确认服务活着、看依赖/蓝牙状态
Invoke-RestMethod http://127.0.0.1:8787/api/state | ConvertTo-Json -Depth 5
# 环境体检（逐项列出依赖/声卡/蓝牙/权限/自启哪层断了）
Invoke-RestMethod -Uri http://127.0.0.1:8787/api/action -Method Post -ContentType "application/json" -Body '{"action":"check"}'

# 卸载/清理脚本（默认什么都不勾；先 --dry-run 看清单）
.venv\Scripts\python.exe uninstall.py --dry-run
```

`client.log`（程序目录）是排障第一入口：`pythonw` 下 stdout 为 None，所有日志从第一行起落盘。

## 架构

### 启动链

`启动遥控器.vbs`（找解释器顺序：`python.txt` → `.venv\` → `runtime\` → 常见安装位置 → PATH）→ `pythonw.exe app.py`（隐藏窗口）→ 界面 `http://127.0.0.1:8787`。单实例锁用 127.0.0.1 端口 49741。

### 三条硬规矩（app.py 文件头，改代码前先读）

1. **单进程**：语音和按键都在本进程线程里跑，不 Popen 子进程（唯一例外是装依赖的 pip，显式加 `CREATE_NO_WINDOW`）——为的是绝不弹控制台黑框。
2. **只监听 127.0.0.1**：安全且不触发防火墙弹窗。
3. **配置以后端 `config.json` 为准**：前端不许用 localStorage 缓存配置再推回来（历史 bug 冲掉过用户配置）。写 config.json 只用 `CONFIG_LOCK`（定义在 i18n.py，app.py 和 i18n.py 两处写入共享这一把锁）。

### 模块地图

| 文件 | 职责 |
|---|---|
| `app.py`（~3100 行） | 入口 + 全部装配：HTTP 服务（stdlib `ThreadingHTTPServer`）、`Bus` 日志环/SSE、配置、pip 装依赖（多镜像轮询）、VB-CABLE 安装、千问开关、自启/计划任务、`Roles` 角色管理、环境体检 |
| `voice.py` | 语音链路：bleak 蓝牙 GATT → ATVV 私有服务 → 纯 Python 音频（IMA ADPCM 解码 + 线性插值升采样 + AGC，**不用 numpy**）→ sounddevice → 虚拟声卡 |
| `keys.py` + `tap.js` | 按键链路：Frida 注入 `WUDFHost.exe`（蓝牙 HID 驱动宿主）钩 `NtDeviceIoControlFile` 的 IOCTL `0x80018483`，抄 HID 输出缓冲区；映射的键在钩子里原地清位（消灭原生动作双发），再 `SendInput` 合成。VK 键码表 / `KEYEVENTF_EXTENDEDKEY` 特例也在这里 |
| `profiles.py` | 预设方案表：应用（WorkBuddy / Codex / 通用）× 输入法 → 整套 14 键映射。改默认键位改这里，数据来源都注明了出处 |
| `i18n.py` | 极简 `L(zh, en)`：只翻「后端产生、要显示在界面上的消息」。内部诊断流水**保持中文**（排障用，刻意不双语）。语言存 `config.json` 的 `lang` |
| `web/index.html`（~3700 行） | 界面，单文件、零外部资源、离线可用，自带前端 I18N 字典 |
| `elevate_setup.py` | 「一键优化」：清 frida 残留 + 把自启换成最高权限计划任务（之后不再弹 UAC） |
| `uninstall.py` | 清理/卸载，逐项勾选（item id：task/run/kill/frida_helper/frida_svc/venv/pycache/pythontxt/logs/config/qwen/cable），执行顺序固定：先断自启 → 杀进程 → 删文件 |

### 两条链路是完全独立的功能（别混为一谈）

- **语音**：普通蓝牙 GATT 连接（ATVV 服务 ab5e0001：控制 ab5e0002 / 音频 ab5e0003 / 状态 ab5e0004），**不需要管理员**。缺 bleak 时不可用。
- **按键映射**：靠 Frida 注入 + 未公开 IOCTL，要一次提权，frida 锁定 `>=17.18,<18`。**缺 frida 时优雅降级**（语音照常，`keys.ready=false`，日志说明）。
- `voice.py` / `keys.py` 在 app.py 里**延迟导入**——依赖没装时界面也必须能起来。新增模块请保持这个模式。
- 铁律：遥控器 BLE 通道同一时间只允许一个客户端。开新会话前必须把上一条关干净，否则服务表里 ATVV 整个消失（日志报「缺少 ATVV 特征」）。

### HTTP API 安全模型

POST 一律过两道闸：Host/Origin 白名单 + 强制 `application/json`（防 `mode:'no-cors'` 的 drive-by CSRF）。常用动作：`start/stop/restart/check/scan/apply-profile/install-deps/install-keys/install-all/autostart/qwen-inject/set-lang/install-cable/setup-elevated/reset-bt/restart-app/elevate/test-voice/clear-log/uninstall`。

## 修改须知（本仓库特有的坑）

- **`启动遥控器.vbs` 必须纯 ASCII + CRLF**（wscript 用系统 ANSI 代码页解析，中文注释会炸，且 `.gitattributes` 已钉死 eol）。改它别加中文。
- **双语文档成对维护**：`README.md`/`README.en.md`、`说明.md`/`说明.en.md`、`AGENTS.md`/`AGENTS.en.md`。改了中文版要同步英文版。`CHANGELOG.md` 目前只有中文。
- `AGENTS.md` 是给外部 AI 助手看的**安装手册**（面向终端用户），与本文件（面向开发者）受众不同。
- 代码注释密度高、大量解释「为什么」——这是刻意风格，改代码时保持同等密度，别删背景说明。
- pip 镜像表 `PIP_MIRRORS` 在 app.py 顶部：腾讯云 → 中科大 → 阿里云 → 华为云 → 清华 TUNA → 官方。**TUNA 返回空索引只能排最后，网易 163 停止同步不要收录**。
- 运行时产物一律不提交（gitignore 已覆盖）：`config.json`（含用户蓝牙地址 + 整套键位）、`client.log`、`.venv/`、`runtime/`（离线包内置 Python，~200MB）、`wheels/`、`_*`。
- 界面上「全部安装」装的是 pip 包，**装不回** `runtime\` 里的 Python 发行版——清理工具因此刻意不提供删 runtime 的选项，别加。
