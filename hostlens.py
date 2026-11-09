#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hostlens — known_hosts 透视镜。回答两个问题：这台机器记过谁、记的还健不健康。

零依赖单文件 CLI：解析 ~/.ssh/known_hosts（明文条目 + |1| 哈希条目，
HMAC-SHA1 纯 stdlib 还原），audit 全量体检分级，explain 按主机名查所有生效
条目（hashed 条目也能查），dupes 跨主机同 key 复用报告，accept 入基线、
diff 语义化报变化（人话，不是裸 diff）。

子命令：
    explain <host>       该主机所有生效条目（key类型/SHA256指纹/plain或hashed/行号）
    audit [path]         全量体检（exit 0 干净 / 1 有 CRIT 或 WARN / 2 环境错误）
    dupes [path]         跨主机同 key 复用报告
    accept [--note]      当前解析入基线（JSON 只追加）
    diff                 当前 vs 基线，语义化报告
    selftest             19 条不变量自测（EN-01 起）
    --json               机器可读输出（配合 explain/audit/dupes/diff）

只读承诺（EN-01）：explain/audit/dupes/diff 绝不写任何文件；
唯一写盘 = accept 的基线 JSON + selftest 的临时目录。
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

VERSION = "1.1.0"
TOOL = "hostlens"

# 弱算法 key 类型（WARN）
WEAK_KEY_TYPES = {"ssh-rsa", "ssh-dss"}


# ------------------------------------------------------------ parsing --

def parse_known_hosts(path):
    """解析 known_hosts → (entries, junk_lines)。
    entry: {"line", "hosts"(原始标记串), "hostlist"(拆好的每台), "keytype",
            "keyblob"(b64), "fingerprint", "hashed"(bool), "salt", "digest",
            "ports"(每台的 (host, port) 列表), "parse_error"}
    junk: {"line", "lineno", "reason"}"""
    entries, junk = [], []
    p = Path(os.path.expanduser(str(path)))
    if not p.is_file():
        return entries, junk, "missing"
    for lineno, raw in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 已知 hosts 行支持标记：@cert-authority / @revoked
        marker = None
        if line.startswith("@"):
            parts = line.split(None, 2)
            if parts[0] in ("@cert-authority", "@revoked") and len(parts) >= 2:
                marker = parts[0][1:]
                line = line[len(parts[0]):].strip()
            else:
                junk.append({"line": raw, "lineno": lineno, "reason": "未知 @ 标记"})
                continue
        fields = line.split()
        if len(fields) < 3:
            junk.append({"line": raw, "lineno": lineno, "reason": "字段不足 3 个"})
            continue
        hosts_field, keytype, keyblob = fields[0], fields[1], fields[2]
        # keyblob 合法性：必须是 base64 且能解出 keytype 一致性交给指纹步骤
        hashed, salt_b64, digest_b64 = False, None, None
        if hosts_field.startswith("|1|"):
            parts = hosts_field.split("|")
            if len(parts) != 4 or parts[0] != "" or parts[1] != "1" or not parts[2] or not parts[3]:
                junk.append({"line": raw, "lineno": lineno, "reason": "哈希条目格式损坏"})
                continue
            hashed, salt_b64, digest_b64 = True, parts[2], parts[3]
        try:
            blob = base64.b64decode(keyblob, validate=True)
        except Exception:
            junk.append({"line": raw, "lineno": lineno, "reason": "key blob 不是合法 base64"})
            continue
        fp = hashlib.sha256(blob).hexdigest()[:16]
        ent = {"line": lineno, "marker": marker, "hosts_field": hosts_field,
               "keytype": keytype, "keyblob": keyblob, "fingerprint": fp,
               "hashed": hashed, "salt": salt_b64, "digest": digest_b64,
               "ports": [], "parse_error": None}
        if hashed:
            ent["ports"] = [("hashed", None)]
        else:
            for h in hosts_field.split(","):
                if h.startswith("[") and "]" in h:
                    host, port = h[1:].split("]", 1)
                    port = port.lstrip(":")
                    ent["ports"].append((host, port))
                else:
                    ent["ports"].append((h, None))
        entries.append(ent)
    return entries, junk, None


def hashed_hostname_matches(salt_b64, digest_b64, hostname):
    """EN-03：|1| 条目 = HMAC-SHA1(key=salt, msg=hostname)。大小写敏感（openssh 原语义）。"""
    try:
        salt = base64.b64decode(salt_b64)
        digest = base64.b64decode(digest_b64)
    except Exception:
        return False
    return hmac.compare_digest(hmac.new(salt, hostname.encode(), hashlib.sha1).digest(), digest)


def entry_matches_host(ent, host):
    """一个条目是否命中目标主机。hashed 条目走 HMAC 还原（EN-03）。
    host 不带端口形式与 [h]:p 形式都试。"""
    if ent["hashed"]:
        cands = [host]
        if not host.startswith("["):
            cands.append("[%s]" % host)
            cands.append("[%s]:22" % host)
        return any(hashed_hostname_matches(ent["salt"], ent["digest"], c) for c in cands)
    for h, _ in ent["ports"]:
        if h == host:
            return True
        # [host]:port 条目在无端口查询时也算该主机（端口信息单独展示）
        if h.startswith("[") and host in (h[1:].split("]", 1)[0],):
            return True
    return False


def entries_for_host(entries, host):
    return [e for e in entries if entry_matches_host(e, host)]


def key_of(ent):
    """同主机多 key 判重键：keytype + keyblob（EN-05 silent change 判定）。"""
    return (ent["keytype"], ent["keyblob"])


def describe_port(h, p):
    if h == "hashed":
        return "|1| 哈希主机名"
    return "[%s]:%s" % (h, p) if p else h


# ------------------------------------------------------------ audit --

def audit(path="~/.ssh/known_hosts"):
    """全量体检。返回 (findings, entries, junk, exit_code)。
    findings: [{"level", "code", "msg"}]"""
    findings = []
    p = Path(os.path.expanduser(str(path)))
    if not p.is_file():
        findings.append({"level": "CRIT", "code": "EN-13", "msg": "文件不存在: %s" % p})
        return findings, [], [], 1
    entries, junk, err = parse_known_hosts(p)
    # 权限（EN-12）
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        findings.append({"level": "CRIT", "code": "EN-12",
                         "msg": "权限 %o 过宽（组/其他可读）→ chmod 600 %s" % (mode, p)})
    elif mode & 0o022:
        findings.append({"level": "CRIT", "code": "EN-12",
                         "msg": "权限 %o 过宽（组/其他可写）→ chmod 600 %s" % (mode, p)})
    elif mode != 0o600:
        findings.append({"level": "CRIT", "code": "EN-12",
                         "msg": "权限 %o 不是 600 → chmod 600 %s" % (mode, p)})
    # 同主机多条不同 key（EN-05: silent host key change 信号）
    by_host = {}
    for e in entries:
        if e["hashed"]:
            hosts = ["|1| hashed"]
        else:
            hosts = sorted({h for h, _ in e["ports"]})
        for h in hosts:
            by_host.setdefault(h, []).append(e)
    for h, ents in sorted(by_host.items()):
        keys = {key_of(e) for e in ents}
        if len(keys) > 1:
            fps = ", ".join(sorted({e["fingerprint"] for e in ents}))
            findings.append({"level": "CRIT", "code": "EN-05",
                             "msg": "主机 %s 有 %d 条不同 key（silent host key change 嫌疑）: %s"
                                    % (h, len(keys), fps)})
    # 同 key 多主机（EN-06 克隆镜像）
    by_key = {}
    for e in entries:
        by_key.setdefault(key_of(e), set()).update(
            [describe_port(h, pt) for h, pt in e["ports"]] if not e["hashed"] else ["|1| hashed"])
    for k, hosts in sorted(by_key.items(), key=lambda kv: sorted(kv[1])):
        if len(hosts) > 1:
            findings.append({"level": "WARN", "code": "EN-06",
                             "msg": "同一 key (%s %s) 复用在 %d 台主机（克隆/镜像嫌疑）: %s"
                                    % (k[0], k[1][:12], len(hosts), ", ".join(sorted(hosts)))})
    # 明文主机名/IP 暴露（EN-09）
    plain = sum(1 for e in entries if not e["hashed"])
    if plain > 0:
        findings.append({"level": "WARN", "code": "EN-09",
                         "msg": "%d 条明文主机名/IP 暴露（可被字典还原）→ ssh-keygen -H -f %s"
                                % (plain, p)})
    # 弱算法（EN-10）
    weak = [e for e in entries if e["keytype"] in WEAK_KEY_TYPES]
    if weak:
        findings.append({"level": "WARN", "code": "EN-10",
                         "msg": "%d 条弱算法 key（%s，SHA-1 签名）建议重新收集主机 key"
                                % (len(weak), "/".join(sorted({e['keytype'] for e in weak})))})
    # 垃圾行（EN-11）
    for j in junk:
        findings.append({"level": "WARN", "code": "EN-11",
                         "msg": "第 %d 行解析失败（%s）: %s" % (j["lineno"], j["reason"], j["line"][:60])})
    # 带端口条目统计（EN-14，INFO）
    ported = [e for e in entries if any(pt for _, pt in e["ports"])]
    if ported:
        n = sum(len([pt for _, pt in e["ports"] if pt]) for e in ported)
        findings.append({"level": "INFO", "code": "EN-14",
                         "msg": "%d 条带非标端口条目（[host]:port 形式）" % n})
    # 空文件
    if not entries and not junk:
        findings.append({"level": "INFO", "code": "EN-15",
                         "msg": "文件存在但没有任何条目"})
    crit = any(f["level"] == "CRIT" for f in findings)
    return findings, entries, junk, (1 if crit else (0 if not findings else 1))


def print_audit(findings, path):
    if not findings:
        print("hostlens audit: %s — 干净" % path)
        print("  0 条发现。known_hosts 目前健康。")
        return
    icon = {"CRIT": "[CRIT]", "WARN": "[WARN]", "INFO": "[INFO]"}
    for f in findings:
        print("%s %s %s" % (icon[f["level"]], f["code"], f["msg"]))
    n_crit = sum(1 for f in findings if f["level"] == "CRIT")
    print("共 %d 条发现（CRIT %d / WARN %d / INFO %d）" % (
        len(findings), n_crit,
        sum(1 for f in findings if f["level"] == "WARN"),
        sum(1 for f in findings if f["level"] == "INFO")))


# ------------------------------------------------------------ dupes --

def dupes(path="~/.ssh/known_hosts"):
    entries, junk, _ = parse_known_hosts(path)
    by_key = {}
    for e in entries:
        by_key.setdefault(key_of(e), []).append(e)
    groups = []
    for k, ents in by_key.items():
        if len(ents) < 2:
            continue
        hosts = sorted({describe_port(h, pt) for e in ents for h, pt in e["ports"]} if not ents[0]["hashed"]
                       else {"|1| hashed"})
        groups.append({"keytype": k[0], "fp_prefix": k[1][:12], "fingerprint": ents[0]["fingerprint"],
                       "hosts": hosts, "lines": sorted(e["line"] for e in ents)})
    groups.sort(key=lambda g: g["hosts"])
    return groups


# ------------------------------------------------------------ baseline --

def baseline_path():
    return Path(os.path.expanduser("~/.hostlens/baseline.json"))


def snapshot(entries, junk, path):
    return {"version": VERSION, "path": str(path),
            "entries": sorted([{"hosts_field": e["hosts_field"], "keytype": e["keytype"],
                                "keyblob": e["keyblob"], "hashed": e["hashed"],
                                "marker": e["marker"]} for e in entries],
                              key=lambda x: (x["hosts_field"], x["keyblob"])),
            "junk_count": len(junk)}


def load_baseline():
    bp = baseline_path()
    if not bp.is_file():
        return None
    return json.loads(bp.read_text(encoding="utf-8"))


def semantic_diff(old, new):
    """EN-08：语义化 diff（人话）。返回 [str]。"""
    out = []
    def idx(snap):
        return {(e["hosts_field"], e["keytype"], e["keyblob"]) for e in snap["entries"]}
    oi, ni = idx(old), idx(new)
    for k in sorted(ni - oi):
        hosts, kt, _ = k
        out.append("主机 %s 新增 %s key" % (_pretty_hosts(hosts), kt))
    for k in sorted(oi - ni):
        hosts, kt, _ = k
        out.append("主机 %s 的 %s key 消失了" % (_pretty_hosts(hosts), kt))
    if new["junk_count"] != old["junk_count"]:
        out.append("解析失败行从 %d 变成 %d" % (old["junk_count"], new["junk_count"]))
    return out


def _pretty_hosts(hosts_field):
    if hosts_field.startswith("|1|"):
        return "|1| 哈希"
    return hosts_field


# ------------------------------------------------------------ selftest --

def selftest():
    """19 条不变量 EN-01 ~ EN-19，对合成 fixture 全绿才算通过。"""
    tmp = tempfile.mkdtemp(prefix="hostlens-selftest-")
    results = []

    def check(en, name, fn):
        try:
            fn()
            results.append((en, name, True, ""))
        except Exception as ex:
            results.append((en, name, False, str(ex)))

    # fixture：全部虚构 *.example / 198.18.x.x（RFC 2544 保留段）；合成 key（无任何真实凭据）
    K_ED = "AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 43  # 合法 base64 的合成串（形似 ed25519）
    K_ED2 = "AAAAC3NzaC1lZDI1NTE5AAAAI" + "B" * 43
    K_RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABgQ" + "C" * 62   # 合法 base64 的合成串（形似 rsa）

    def w(name, content):
        p = Path(tmp) / name
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o600)
        return str(p)

    def gen_hashed(host, salt=b"0123456789abcdef"):
        d = hmac.new(salt, host.encode(), hashlib.sha1).digest()
        return "|1|%s|%s" % (base64.b64encode(salt).decode(), base64.b64encode(d).decode())

    # EN-01 只读承诺
    def en01():
        f = w("kh1", "web1.example ssh-ed25519 %s\n" % K_ED)
        before = Path(f).read_bytes()
        entries, junk, err = parse_known_hosts(f)
        entries_for_host(entries, "web1.example")
        audit(f)
        dupes(f)
        assert Path(f).read_bytes() == before, "解析类子命令改了文件"

    check("EN-01", "explain/audit/dupes 只读不写盘", en01)

    # EN-02 明文条目解析
    def en02():
        f = w("kh2", "web1.example ssh-ed25519 %s\n" % K_ED)
        entries, junk, err = parse_known_hosts(f)
        assert len(entries) == 1 and not junk and err is None
        assert entries[0]["keytype"] == "ssh-ed25519"
        assert entries[0]["ports"] == [("web1.example", None)]
    check("EN-02", "明文条目解析出主机/keytype/blob", en02)

    # EN-03 哈希条目 HMAC-SHA1 还原 + explain 按主机名查得到
    def en03():
        h = gen_hashed("web2.example")
        f = w("kh3", "%s ssh-ed25519 %s\n" % (h, K_ED))
        entries, _, _ = parse_known_hosts(f)
        assert entries[0]["hashed"] is True
        hits = entries_for_host(entries, "web2.example")
        assert len(hits) == 1, "HMAC 还原失败"
        assert entries_for_host(entries, "other.example") == []
    check("EN-03", "|1| 哈希条目按主机名可查（HMAC-SHA1）", en03)

    # EN-04 同主机多不同 key → CRIT EN-05
    def en04():
        f = w("kh4", "web3.example ssh-ed25519 %s\nweb3.example ssh-ed25519 %s\n"
              % (K_ED, K_ED2))
        fs, _, _, code = audit(f)
        crit = [x for x in fs if x["code"] == "EN-05" and x["level"] == "CRIT"]
        assert crit, "缺 EN-05 CRIT"
        assert code == 1
    check("EN-04", "同主机多 key = CRIT silent change（EN-05）", en04)

    # EN-05 同 key 多主机 → WARN 克隆镜像（EN-06）
    def en05():
        f = w("kh5", "a.example ssh-ed25519 %s\nb.example ssh-ed25519 %s\n" % (K_ED, K_ED))
        fs, _, _, code = audit(f)
        assert any(x["code"] == "EN-06" and x["level"] == "WARN" for x in fs)
        assert code == 1  # 有 WARN 也非 0
    check("EN-05", "同 key 多主机 = WARN 克隆镜像（EN-06）", en05)

    # EN-06 权限 644 → CRIT；600 → 干净
    def en06():
        f = w("kh6", "c.example ssh-ed25519 %s\n" % K_ED)
        os.chmod(f, 0o644)
        fs, _, _, code = audit(f)
        assert any(x["code"] == "EN-12" and x["level"] == "CRIT" for x in fs)
        assert code == 1
        os.chmod(f, 0o600)
        fs, _, _, code = audit(f)
        assert not any(x["code"] == "EN-12" for x in fs)
    check("EN-06", "644 权限 = CRIT（EN-12）；600 复检干净", en06)

    # EN-07 明文暴露计数 WARN（EN-09）
    def en07():
        f = w("kh7", "d.example ssh-ed25519 %s\n198.18.0.1 ssh-ed25519 %s\n"
              % (K_ED, K_ED2))
        fs, _, _, _ = audit(f)
        assert any(x["code"] == "EN-09" for x in fs)
    check("EN-07", "明文主机名/IP 暴露 = WARN（EN-09）", en07)

    # EN-08 弱算法 ssh-rsa → WARN（EN-10）
    def en08():
        f = w("kh8", "e.example ssh-rsa %s\n" % K_RSA)
        fs, _, _, _ = audit(f)
        assert any(x["code"] == "EN-10" and x["level"] == "WARN" for x in fs)
    check("EN-08", "ssh-rsa 弱算法 = WARN（EN-10）", en08)

    # EN-09 垃圾行逐条报（EN-11）
    def en09():
        f = w("kh9", "f.example ssh-ed25519 %s\n这一行是垃圾\ng.example\n# 注释不算\n\n"
              % K_ED)
        entries, junk, err = parse_known_hosts(f)
        assert len(entries) == 1
        assert len(junk) == 2, "垃圾行应为 2 条，实际 %d" % len(junk)
        assert junk[0]["lineno"] == 2 and junk[1]["lineno"] == 3
    check("EN-09", "垃圾行/字段不足逐条报，注释与空行不算（EN-11）", en09)

    # EN-10 [host]:port 条目解析与统计（EN-14）
    def en10():
        f = w("kh10", "[h1.example]:2222 ssh-ed25519 %s\n" % K_ED)
        entries, _, _ = parse_known_hosts(f)
        assert entries[0]["ports"] == [("h1.example", "2222")]
        fs, _, _, _ = audit(f)
        assert any(x["code"] == "EN-14" and x["level"] == "INFO" for x in fs)
    check("EN-10", "[host]:2222 带端口条目解析+统计（EN-14）", en10)

    # EN-11 文件不存在 = CRIT
    def en11():
        fs, _, _, code = audit(str(Path(tmp) / "nope"))
        assert any(x["code"] == "EN-13" for x in fs) and code == 1
    check("EN-11", "文件不存在 = CRIT EN-13", en11)

    # EN-12 哈希条目对错误主机名不误报
    def en12():
        h = gen_hashed("web9.example")
        f = w("kh12", "%s ssh-ed25519 %s\n" % (h, K_ED))
        entries, _, _ = parse_known_hosts(f)
        assert entries_for_host(entries, "web99.example") == []
    check("EN-12", "哈希条目对陌生主机名零误报", en12)

    # EN-13 marker 条目识别
    def en13():
        f = w("kh13", "@cert-authority *.example ssh-ed25519 %s\n"
              "@revoked bad.example ssh-ed25519 %s\n" % (K_ED, K_ED2))
        entries, _, _ = parse_known_hosts(f)
        assert entries[0]["marker"] == "cert-authority"
        assert entries[1]["marker"] == "revoked"
    check("EN-13", "@cert-authority/@revoked 标记识别", en13)

    # EN-14 坏 base64 → 垃圾行不 crash
    def en14():
        f = w("kh14", "g.example ssh-ed25519 !!!not-base64!!!\n")
        entries, junk, _ = parse_known_hosts(f)
        assert len(entries) == 0 and len(junk) == 1
    check("EN-14", "坏 base64 blob → 垃圾行不 crash（EN-11）", en14)

    # EN-15 dupes 报告结构与行号
    def en15():
        f = w("kh15", "a.example ssh-ed25519 %s\nb.example ssh-ed25519 %s\n"
              % (K_ED, K_ED))
        gs = dupes(f)
        assert len(gs) == 1 and set(gs[0]["hosts"]) == {"a.example", "b.example"}
        assert gs[0]["lines"] == [1, 2]
    check("EN-15", "dupes 跨主机同 key 报告含主机+行号", en15)

    # EN-16 diff 语义化：新增/消失都是人话
    def en16():
        f1 = w("kh16a", "x.example ssh-ed25519 %s\n" % K_ED)
        f2 = w("kh16b", "x.example ssh-ed25519 %s\ny.example ssh-ed25519 %s\n"
               % (K_ED2, K_ED))
        e1, j1, _ = parse_known_hosts(f1)
        e2, j2, _ = parse_known_hosts(f2)
        d = semantic_diff(snapshot(e1, j1, "a"), snapshot(e2, j2, "b"))
        assert any("新增" in s and "y.example" in s for s in d), d
        assert any("消失" in s for s in d), d
        assert not any(s.startswith("@@") or s.startswith("-") or s.startswith("+") for s in d)
    check("EN-16", "diff 输出人话（新增/消失），非裸 diff", en16)

    # EN-17 snapshot 与 entry 顺序无关
    def en17():
        a = w("kh17a", "m.example ssh-ed25519 %s\nn.example ssh-ed25519 %s\n" % (K_ED, K_ED2))
        b = w("kh17b", "n.example ssh-ed25519 %s\nm.example ssh-ed25519 %s\n" % (K_ED2, K_ED))
        ea, ja, _ = parse_known_hosts(a)
        eb, jb, _ = parse_known_hosts(b)
        assert snapshot(ea, ja, "same") == snapshot(eb, jb, "same")
    check("EN-17", "snapshot 与条目顺序无关", en17)

    # EN-18 CRLF / 尾随空白容错
    def en18():
        f = w("kh18", "p.example ssh-ed25519 %s   \r\n" % K_ED)
        entries, junk, _ = parse_known_hosts(f)
        assert len(entries) == 1 and not junk
    check("EN-18", "CRLF/尾随空白容错", en18)

    # EN-19 空文件 + 全注释文件 → 0 条目 0 垃圾
    def en19():
        f1 = w("kh19a", "")
        f2 = w("kh19b", "# only a comment\n\n")
        for f in (f1, f2):
            entries, junk, _ = parse_known_hosts(f)
            assert entries == [] and junk == []
    check("EN-19", "空文件/全注释 = 0 条目 0 垃圾", en19)

    ok = sum(1 for _, _, s, _ in results if s)
    for en, name, s, msg in results:
        print("%s %s %s%s" % ("PASS" if s else "FAIL", en, name, ("" if s else "  -> " + msg)))
    print("selftest: %d/%d 全绿" % (ok, len(results)))
    return 0 if ok == len(results) else 1


# ------------------------------------------------------------ cli --

def main():
    ap = argparse.ArgumentParser(prog=TOOL, description="known_hosts 透视镜")
    ap.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    sub = ap.add_subparsers(dest="cmd")

    def sub_add(*a, **kw):
        p = sub.add_parser(*a, **kw)
        p.add_argument("--json", action="store_true", help="机器可读输出")
        return p

    sp_ex = sub_add("explain", help="按主机名查所有生效条目")
    sp_ex.add_argument("host")
    sp_ex.add_argument("--file", default="~/.ssh/known_hosts")
    sp_au = sub_add("audit", help="全量体检")
    sp_au.add_argument("path", nargs="?", default="~/.ssh/known_hosts")
    sp_du = sub_add("dupes", help="跨主机同 key 复用")
    sp_du.add_argument("path", nargs="?", default="~/.ssh/known_hosts")
    sp_ac = sub_add("accept", help="当前解析入基线")
    sp_ac.add_argument("--note", default="")
    sp_ac.add_argument("--file", default="~/.ssh/known_hosts")
    sp_df = sub_add("diff", help="当前 vs 基线")
    sp_df.add_argument("--file", default="~/.ssh/known_hosts")
    sub_add("selftest", help="19 条不变量自测")

    args = ap.parse_args()
    J = args.json

    if args.cmd == "selftest":
        sys.exit(selftest())

    if args.cmd == "explain":
        entries, _, err = parse_known_hosts(args.file)
        if err == "missing":
            print("文件不存在: %s" % args.file)
            sys.exit(2)
        hits = entries_for_host(entries, args.host)
        if J:
            print(json.dumps({"host": args.host, "entries": [
                {"line": h["line"], "keytype": h["keytype"], "fingerprint": h["fingerprint"],
                 "hashed": h["hashed"], "marker": h["marker"],
                 "ports": [describe_port(a, b) for a, b in h["ports"]]} for h in hits]},
                ensure_ascii=False, indent=2))
            sys.exit(0 if hits else 1)
        if not hits:
            print("hostlens explain %s：known_hosts 里没有这台主机的记录" % args.host)
            sys.exit(1)
        print("hostlens explain %s — %d 条生效条目：" % (args.host, len(hits)))
        for h in hits:
            tag = "hashed(|1|)" if h["hashed"] else "plain"
            mk = " [%s]" % h["marker"] if h["marker"] else ""
            for hp, pt in (h["ports"] if not h["hashed"] else [("hashed", None)]):
                print("  L%-4d %-9s %s %s%s%s" % (
                    h["line"], h["keytype"], "SHA256:" + h["fingerprint"], tag, mk,
                    ("  端口 " + pt) if pt else ""))
        sys.exit(0)

    if args.cmd == "audit":
        fs, entries, junk, code = audit(args.path)
        if J:
            print(json.dumps({"findings": fs, "exit": code}, ensure_ascii=False, indent=2))
        else:
            print_audit(fs, args.path)
        sys.exit(code)

    if args.cmd == "dupes":
        gs = dupes(args.path)
        if J:
            print(json.dumps({"groups": gs}, ensure_ascii=False, indent=2))
            sys.exit(0)
        if not gs:
            print("hostlens dupes：没有跨主机复用的 key。")
            sys.exit(0)
        print("hostlens dupes — %d 组同 key 复用：" % len(gs))
        for g in gs:
            print("  %s %s… → %s（行 %s）" % (g["keytype"], g["fp_prefix"],
                  ", ".join(g["hosts"]), ",".join(map(str, g["lines"]))))
        sys.exit(1)

    if args.cmd == "accept":
        entries, junk, err = parse_known_hosts(args.file)
        if err == "missing":
            print("文件不存在: %s" % args.file)
            sys.exit(2)
        snap = snapshot(entries, junk, args.file)
        if args.note:
            snap["note"] = args.note
        bp = baseline_path()
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
        print("基线已写入 %s（%d 条条目）%s" % (bp, len(snap["entries"]),
              ("备注: " + args.note) if args.note else ""))
        sys.exit(0)

    if args.cmd == "diff":
        old = load_baseline()
        if old is None:
            print("还没有基线。先跑: hostlens accept")
            sys.exit(2)
        entries, junk, err = parse_known_hosts(args.file)
        if err == "missing":
            print("文件不存在: %s" % args.file)
            sys.exit(2)
        new = snapshot(entries, junk, args.file)
        changes = semantic_diff(old, new)
        if J:
            print(json.dumps({"changes": changes}, ensure_ascii=False, indent=2))
            sys.exit(0 if not changes else 1)
        if not changes:
            print("hostlens diff：与基线一致，没有变化。")
            sys.exit(0)
        print("hostlens diff — 与基线相比 %d 处变化：" % len(changes))
        for c in changes:
            print("  · " + c)
        sys.exit(1)

    ap.print_help()


if __name__ == "__main__":
    main()
