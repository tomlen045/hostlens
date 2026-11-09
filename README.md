# hostlens — known_hosts 透视镜

回答两个问题：**这台机器记过谁、记的还健不健康。**

零依赖单文件 Python CLI（stdlib only），解析 `~/.ssh/known_hosts`，明文条目和
`|1|` 哈希条目都能透视（哈希条目用 HMAC-SHA1 纯 stdlib 还原，按主机名照查不误）。

hostlens 是自研运维透镜套件的第 5 件：

> **porteye**（谁在听）→ **callhome**（谁打电话回家）→ **authguard**（谁想进来）
> → **envlens**（SSH 配置怎么连）→ **hostlens**（known_hosts 记了谁、健不健康）

envlens 管的是「ssh 连之前怎么配置」，hostlens 管的是「连过的主机留下了什么痕迹、
这些痕迹还可不可信」。两个工具背靠背，SSH 这块就闭环了。

## 为什么需要它

known_hosts 是 SSH 的信任底账：你第一次连一台机器，它把对方公钥记下来；之后每次
连接，SSH 拿底账对暗号，对不上就甩你一脸：

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

大多数人此刻的肌肉记忆是删掉那行再连。**这行警告恰恰是 known_hosts 唯一一次
真正替你挡攻击的时刻**——可能是重装系统，也可能是 DNS 劫持/中间人。底账平时
没人看，出事才想起来，而它自己也会烂：权限放宽、同 key 到处克隆、弱算法 key
躺了五年、垃圾行堆了一屏。

hostlens 把体检变成一条命令。

## 安装

```bash
git clone https://github.com/tomlen045/hostlens.git
cd hostlens
# 可选：加个 alias
alias hostlens='python3 /path/to/hostlens/hostlens.py'
hostlens --version
```

零依赖，Python 3.8+ 自带 stdlib 就够。不需要 pip，不需要 venv。

## 四板斧

### explain：这台机器在我这儿的底账

```bash
$ hostlens explain web1.example
hostlens explain web1.example — 2 条生效条目：
  L1    ssh-ed25519 SHA256:5fbe4c6f79ea5692 plain
  L2    ssh-ed25519 SHA256:92661cbdd8b61a43 plain
```

哈希条目（`|1|salt|hash`）按主机名照样查得到——hostlens 用 HMAC-SHA1
（key=salt, msg=hostname）逐条比对还原，与 OpenSSH 换算方式一致：

```bash
$ hostlens explain git.example
hostlens explain git.example — 1 条生效条目：
  L7    ssh-ed25519 SHA256:92661cbdd8b61a43 hashed(|1|)
```

带端口的条目、`@cert-authority`/`@revoked` 标记都认。

### audit：全量体检，一条命令分级报告

```bash
$ hostlens audit
[CRIT] EN-12 权限 644 过宽（组/其他可读）→ chmod 600 ~/.ssh/known_hosts
[CRIT] EN-05 主机 web1.example 有 2 条不同 key（silent host key change 嫌疑）
[WARN] EN-06 同一 key (ssh-ed25519 AAAA…) 复用在 4 台主机（克隆/镜像嫌疑）
[WARN] EN-09 6 条明文主机名/IP 暴露（可被字典还原）→ ssh-keygen -H -f ~/.ssh/known_hosts
[WARN] EN-10 1 条弱算法 key（ssh-rsa，SHA-1 签名）建议重新收集主机 key
[WARN] EN-11 第 8 行解析失败（字段不足 3 个）: 这一行是垃圾
[INFO] EN-14 1 条带非标端口条目（[host]:port 形式）
共 7 条发现（CRIT 2 / WARN 4 / INFO 1）
```

**有 CRIT 退出码非 0**，直接接 cron / CI：

```bash
hostlens audit || echo "known_hosts 有红色警报"
```

### dupes：谁和谁共用一把钥匙

```bash
$ hostlens dupes
hostlens dupes — 2 组同 key 复用：
  ssh-ed25519 AAAAC3NzaC1l… → 198.18.0.10, a.example, b.example, web1.example（行 2,3,4,6）
  ssh-ed25519 AAAAC3NzaC1l… → web1.example, |1| 哈希主机名（行 1,7）
```

同一把主机 key 躺在多台主机名下面，可能是合理的（同机多域名），更可能是
镜像/克隆或者当初复制粘贴大扫除留下的。批量部署的机器一把 key 全网通吃，
攻破一台等于攻破全部。

### accept + diff：给信任底账拍快照，变化说人话

```bash
$ hostlens accept --note "重装系统后重建"
基线已写入 ~/.hostlens/baseline.json（7 条条目）备注: 重装系统后重建
$ hostlens diff
hostlens diff — 与基线相比 4 处变化：
  · 主机 git.example 新增 ssh-ed25519 key
  · 主机 z.example 新增 ssh-ed25519 key
  · 主机 web1.example 的 ssh-ed25519 key 消失了
  · 主机 |1| 哈希 的 ssh-ed25519 key 消失了
```

不是裸 diff，是「哪台主机新增了什么类型的 key、哪台的 key 消失了」的人话。
基线是 append-only JSON，crontab 里每周 `hostlens accept` 一次就是审计轨迹。

### 机器可读

```bash
hostlens explain git.example --json
hostlens audit --json
```

## 19 条不变量（selftest 全绿）

`hostlens selftest` 对合成 fixture（全部 `*.example` / `198.18.x.x` RFC2544
保留段虚构主机、合成 key）逐条断言，19/19 全绿才算可用：

| # | 不变量 |
|---|--------|
| EN-01 | explain/audit/dupes 只读不写盘，解析类子命令前后文件字节级一致 |
| EN-02 | 明文条目解析出主机/keytype/blob，行号精确 |
| EN-03 | `\|1\|` 哈希条目按主机名可查：HMAC-SHA1(key=salt, msg=hostname) 与 OpenSSH 一致 |
| EN-04 | 同主机多条不同 key = CRIT（EN-05 silent host key change），退出码非 0 |
| EN-05 | 同 key 多主机 = WARN 克隆镜像（EN-06），退出码非 0 |
| EN-06 | 权限 644 = CRIT（EN-12）；chmod 600 后复检干净、退出码 0 |
| EN-07 | 明文主机名/IP 暴露计数 = WARN（EN-09），给出 ssh-keygen -H 处置命令 |
| EN-08 | 弱算法 ssh-rsa/ssh-dss = WARN（EN-10） |
| EN-09 | 垃圾行/字段不足逐条报行号与原因（EN-11）；注释与空行不算垃圾 |
| EN-10 | `[host]:2222` 带端口条目正确解析并统计（EN-14） |
| EN-11 | 文件不存在 = CRIT（EN-13），退出码非 0 |
| EN-12 | 哈希条目对陌生主机名零误报 |
| EN-13 | `@cert-authority`/`@revoked` 标记正确识别 |
| EN-14 | 坏 base64 blob 进垃圾行，绝不 crash |
| EN-15 | dupes 报告含主机列表与行号 |
| EN-16 | diff 输出人话（「新增/消失」），绝无裸 diff 符号 |
| EN-17 | snapshot 与条目顺序无关（快照可比对） |
| EN-18 | CRLF / 尾随空白容错 |
| EN-19 | 空文件/全注释文件 = 0 条目 0 垃圾 |

## 诚实边界

- **known_hosts 没有时间戳。** 每一行只有主机名和 key，没有「什么时候记下的」。
  hostlens 能发现「变了」，回答不了「什么时候被谁改的」。想要时间轴，用
  `accept` 定期拍快照，diff 就是你的时间轴。
- hostlens 读 key blob 算指纹，但不验证 key 的数学结构（比如 RSA 模数合法性）——
  那是 `ssh-keygen -l -f` 的活。
- 审计建议只到文件层面。要机器级的 sshd 配置审计，是套件下一步的活。

## 套件兄弟

| 工具 | 回答的问题 |
|------|-----------|
| porteye | 谁在我的机器上听端口 |
| callhome | 谁在往外打电话回家 |
| authguard | 谁想进来（登录/爆破面） |
| envlens | SSH 配置到底会怎么连 |
| **hostlens** | **known_hosts 记了谁、健不健康** |

## License

MIT
