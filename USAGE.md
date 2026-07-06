# Frida 16.2.1 魔改版 — 使用说明

基于 [frida-magic1798](https://github.com/q99266/frida-magic1798) 方案，将 Frida **16.2.1** 的 D-Bus 命名空间改为 `re.nginx`，脚本 RPC 改为 `nginx:rpc`，并对 server 二进制做反检测后处理。

## 目录结构

```
D:\cursorwork\frida-magic162\
├── build/                          # CI 下载产物解压目录（本地）
│   ├── frida-server-processed      # Android arm64 server
│   └── frida-client-windows-amd64/ # 魔改 Python 客户端
├── post_process.py                 # server 二进制后处理
├── tools/
│   ├── patch-frida-client.py       # 魔改 pip 版 frida 客户端
│   ├── deploy-server.ps1           # 推送 server 到手机
│   ├── setup-forward.ps1           # adb forward
│   ├── frida-launcher-v2.sh        # 设备端 stealth 启动器
│   └── run-frida-patched.ps1       # 使用魔改客户端运行 frida CLI
└── USAGE.md
```

## 一、下载构建产物

GitHub Actions 构建完成后，在本机执行：

```powershell
cd D:\cursorwork\frida-magic162
mkdir build -Force

# 查看最近一次 workflow run
gh run list --repo q99266/frida-magic162 --limit 3

# 下载全部 artifact（需 run-id）
gh run download <RUN_ID> --repo q99266/frida-magic162 --dir build
```

产物说明：

| Artifact | 内容 |
|----------|------|
| `frida-server-android-arm64` | 魔改后的 `frida-server-processed`（推送到手机用） |
| `frida-client-windows-amd64` | `tools/frida-patched/frida/` 整包（Windows Python 3.11） |

若未安装 GitHub CLI，可在仓库 **Actions → 最新成功 run → Artifacts** 页面手动下载。

## 二、本地魔改客户端（可选，不依赖 CI）

若已安装官方 `frida==16.2.1`：

```powershell
pip install frida==16.2.1 frida-tools
cd D:\cursorwork\frida-magic162
python tools\patch-frida-client.py --output-dir tools\frida-patched
```

之后通过 `PYTHONPATH` 使用魔改客户端，不覆盖 site-packages：

```powershell
$env:PYTHONPATH = "D:\cursorwork\frida-magic162\tools\frida-patched"
frida-ps -H 127.0.0.1:27100
```

或使用封装脚本：

```powershell
.\tools\run-frida-patched.ps1 frida-ps -H 127.0.0.1:27100
```

## 三、部署 server 到 Android（root）

```powershell
cd D:\cursorwork\frida-magic162

# 设备序列号按 adb devices 修改
$dev = "8B2X12JUD"
$server = "build\frida-server-android-arm64\frida-server-processed"
# 若 artifact 解压路径不同，改为实际路径，例如 build\frida-server-processed

.\tools\deploy-server.ps1 -ServerPath $server -Device $dev -ListenMode unix
```

默认 **unix abstract socket** 监听（进程 cmdline 无 `-l`，降低检测面）。`deploy-server.ps1` 会：

1. 推送 server + `frida-launcher-v2.sh` 到 `/data/local/tmp/`
2. 以 `APP_LISTEN=unix:<随机名>` 启动
3. 执行 `adb forward tcp:27100 localabstract:<socket>`

## 四、验证连接

```powershell
$env:PYTHONPATH = "D:\cursorwork\frida-magic162\tools\frida-patched"
frida-ps -H 127.0.0.1:27100
frida -H 127.0.0.1:27100 -n com.ubrmb.app -e "console.log('ok')"
```

## 五、与 17.9.8 魔改版的差异

| 项目 | 16.2.1 (本仓库) | 17.9.8 (frida-magic1798) |
|------|-----------------|---------------------------|
| D-Bus 接口版本 | `HostSession**16**` | `HostSession**17**` |
| 构建系统 | `make` + releng SDK | meson `configure` + NDK |
| server 输出名 | 后处理仍为 `frida-server-processed` | `app-server` → 后处理 |
| zymbiote | 无 | 有（需 helper.dex 修复） |
| 客户端 | `pip install frida==16.2.1` + patch | `pip install frida==17.9.8` + patch |

**不可混用**：16.2.1 魔改 server 必须配 16.2.1 魔改客户端；与 17.9.8 互不兼容。

## 六、魔改原理摘要

**Server 源码**

- `session.vala` / `frida-helper-types.vala`：`re.frida.*` → `re.nginx.*`（等长替换）
- `server.vala`：`DEFAULT_DIRECTORY=re.nginx.server`；支持环境变量 `APP_LISTEN`（配合 launcher 隐藏 `-l`）

**Server 二进制 (`post_process.py`)**

- 导出符号 `frida_agent_main` 随机重命名
-  scrub `.rodata` 中 `frida`/`gumjs` 等特征串
- 等长替换 `re.frida.` → `re.nginx.`、`frida:rpc` → `nginx:rpc` 等
- 移除 `.comment` / debug 段

**客户端 (`patch-frida-client.py`)**

- `_frida.pyd`：`re.frida.` → `re.nginx.`
- `core.py`：`frida:rpc` → `nginx:rpc`

## 七、重新触发 GitHub 构建

```powershell
gh workflow run "Build Frida 16.2.1 Anti-Detection" --repo q99266/frida-magic162
gh run watch --repo q99266/frida-magic162
```

## 八、故障排查

| 现象 | 处理 |
|------|------|
| `unable to connect` | 检查 `adb forward --list`；重新 `deploy-server.ps1` |
| `Protocol error` / 版本不匹配 | 确认 client/server 均为 **16.2.1** 魔改包 |
| attach 后 `Java is not defined` | 目标 App 加固导致，与 frida 版本无关；用 native hook |
| server 启动后立即退出 | `adb shell su -c cat /data/local/tmp/.launcher.log` |

## 九、停止 server

```powershell
adb -s 8B2X12JUD shell su -c "pkill -f frida-server; pkill -f app-server; rm -f /data/local/tmp/.listen"
adb forward --remove-all
```

---

构建仓库：<https://github.com/q99266/frida-magic162>  
参考方案：`D:\claudework\frida-magic1798`
