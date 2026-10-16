#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 口径确认探针 —— 一次读完 pcap，回答《数据口径定义书》§9 的 5 个待确认项。

确认项:
  1. 172.2.0.0/24 的对端构成（对端是内部段还是公网段）
  2. SLL2 interface index 分布（接口数量与各自流量）
  3. 内部 <-> 公网 双向拆分占比（补齐五类方向口径）
  4. 服务端口 (9092/9093/9094/5052/5053/27017/514/443/80) 的 src/dst 内外部构成
  5. 等量高位端口组 (50316/35326/45780/...) 的来源主机

附带（同一次读盘顺手落下来，避免二次读 36 GB）:
  · 修正聚合键后的主机画像 host_profile_v2.csv（取外层 IP，消除 "A,B" 伪主机）
  · 修正后的主机总数 / 集中度 / 基尼系数

用法:
  caffeinate -is python probe_caliber.py "/Volumes/Extreme SSD/ST5290_pcap"/cap_20260920_*.pcap \
      --out ../双周3_报告/probe_caliber
"""
import argparse, csv, glob, ipaddress, json, math, os, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "ip.proto", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
          "vlan.id", "sll.ifindex"]
CST = timezone(timedelta(hours=8))

DECLARED_INTERNAL = ["172.2.0.0/16"]          # 平台声明为内部（非 RFC1918）
SERVICE_PORTS = ["443", "80", "9092", "9093", "9094", "5052", "5053", "27017", "514"]
WATCH_PORTS = ["50316", "35326", "45780", "55529", "60328", "32962", "33048", "64219", "50395"]
PEER_CAP = 5000                                # 扇出上限（原 200 截断失真）
PORT_CAP = 5000

_EXTRA = [ipaddress.ip_network(c) for c in DECLARED_INTERNAL]


def cls(ip):
    """int / ext / loop / skip"""
    if not ip:
        return "skip"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "skip"
    if a.version == 6:
        return "v6"
    if a.is_loopback:
        return "loop"
    if a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved:
        return "skip"
    if str(a).startswith("0."):
        return "skip"
    if any(a in n for n in _EXTRA):
        return "int"
    if a.is_private:
        return "int"
    return "ext"


def probe(path):
    st = {
        "file": os.path.basename(path), "size_bytes": os.path.getsize(path),
        "packets": 0, "bytes": 0, "first_ts": None, "last_ts": None,
        "multi_val_pkts": 0, "multi_examples": Counter(), "v6_pkts": 0,
        "dir": Counter(), "dir_bytes": Counter(),               # 5 类方向
        "ifidx": Counter(), "ifidx_bytes": Counter(), "ifidx_mix": defaultdict(Counter),
        "svc": defaultdict(Counter), "svc_bytes": defaultdict(Counter),   # 端口 -> (src,dst) class 组合
        "watch_src": defaultdict(Counter),                       # 等量端口组 -> 源 IP
        "z172_peer": Counter(), "z172_peer_bytes": Counter(), "z172_cls": Counter(),
        "hosts": defaultdict(lambda: {"txp": 0, "txb": 0, "rxp": 0, "rxb": 0,
                                      "peers": set(), "ports": set(), "pc": Counter()}),
        "svc_unknown": Counter(),
    }
    cmd = [TSHARK, "-r", path, "-T", "fields"] + [x for f in FIELDS for x in ("-e", f)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1 << 22)
    nf = len(FIELDS)
    for line in proc.stdout:
        p = line.rstrip("\n").split("\t")
        if len(p) < nf:
            p += [""] * (nf - len(p))
        ts, flen, src, dst, v6src, v6dst, proto, tsport, tdport, usport, udport, vlan, ifidx = p
        if not ts:
            continue
        try:
            t = float(ts); flen = int(flen) if flen else 0
        except ValueError:
            continue
        st["packets"] += 1; st["bytes"] += flen
        if st["first_ts"] is None or t < st["first_ts"]: st["first_ts"] = t
        if st["last_ts"] is None or t > st["last_ts"]: st["last_ts"] = t
        if v6src or v6dst:
            st["v6_pkts"] += 1
        if "," in src or "," in dst:
            st["multi_val_pkts"] += 1
            if len(st["multi_examples"]) < 20:
                st["multi_examples"][f"{src} -> {dst}"] += 1
        # 修正聚合键：多层封装时取最外层 IP
        src = src.split(",")[0].strip()
        dst = dst.split(",")[0].strip()
        proto = proto.split(",")[0].strip()
        cs, cd = cls(src), cls(dst)
        dport = (tdport or udport or "").split(",")[0]
        key = f"{cs}-{cd}"
        if cs in ("int", "ext", "loop") and cd in ("int", "ext", "loop"):
            st["dir"][key] += 1; st["dir_bytes"][key] += flen
            if ifidx:
                st["ifidx"][ifidx] += 1; st["ifidx_bytes"][ifidx] += flen
                st["ifidx_mix"][ifidx][key] += 1
        # 172.2.0.0/24 对端构成
        for me, other in ((src, dst), (dst, src)):
            if me.startswith("172.2.0."):
                st["z172_peer"][other] += 1; st["z172_peer_bytes"][other] += flen
                st["z172_cls"][cls(other)] += 1
        # 服务端口 / 观察端口
        if dport in SERVICE_PORTS:
            st["svc"][dport][key] += 1; st["svc_bytes"][dport][key] += flen
        elif dport in WATCH_PORTS:
            if src: st["watch_src"][dport][src] += 1
        # 主机画像
        if src and cs != "skip":
            h = st["hosts"][src]
            h["txp"] += 1; h["txb"] += flen
            if len(h["peers"]) < PEER_CAP and dst: h["peers"].add(dst)
            if dport:
                if len(h["ports"]) < PORT_CAP: h["ports"].add(dport)
                h["pc"][dport] += 1
                if len(h["pc"]) > 2000: h["pc"] = Counter(dict(h["pc"].most_common(1000)))
        if dst and cd != "skip":
            h = st["hosts"][dst]
            h["rxp"] += 1; h["rxb"] += flen
            if len(h["peers"]) < PEER_CAP and src: h["peers"].add(src)
            if dport:
                if len(h["ports"]) < PORT_CAP: h["ports"].add(dport)
                h["pc"][dport] += 1
                if len(h["pc"]) > 2000: h["pc"] = Counter(dict(h["pc"].most_common(1000)))
    proc.stdout.close(); rc = proc.wait()
    st["tshark_rc"] = rc
    return st


def entropy(h):
    c = h["pc"]; tot = sum(c.values())
    if tot <= 0 or len(c) <= 1: return 0.0
    H = -sum((v / tot) * math.log2(v / tot) for v in c.values())
    return round(H / math.log2(len(c)), 4)


def gini(shares):
    v = sorted(shares); n = len(v)
    if n == 0: return 0.0
    s = sum(v) or 1
    cum = 0.0
    for i, x in enumerate(v, 1): cum += i * x
    return round((2 * cum) / (n * s) - (n + 1) / n, 4)


def host_rows(st):
    tot = sum(h["txb"] + h["rxb"] for h in st["hosts"].values()) or 1
    rows = []
    for ip, h in st["hosts"].items():
        tb = h["txb"] + h["rxb"]
        rows.append([ip, cls(ip), h["txp"], h["txb"], h["rxp"], h["rxb"], tb,
                     round(tb / (h["txp"] + h["rxp"]), 1) if (h["txp"] + h["rxp"]) else 0,
                     round(h["txb"] / h["rxb"], 3) if h["rxb"] else "",
                     len(h["peers"]), len(h["ports"]), entropy(h),
                     round(tb / tot * 100, 4)])
    rows.sort(key=lambda r: -r[6])
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = []
    for pat in a.pcaps: files += sorted(glob.glob(pat)) or [pat]
    grand = {"dir": Counter(), "dir_bytes": Counter(), "ifidx": Counter(),
             "ifidx_bytes": Counter(), "svc": defaultdict(Counter), "svc_bytes": defaultdict(Counter),
             "watch_src": defaultdict(Counter), "z172_peer": Counter(), "z172_peer_bytes": Counter(),
             "z172_cls": Counter(), "multi_val_pkts": 0, "v6_pkts": 0, "packets": 0, "bytes": 0}
    per_file = []
    all_host_rows = []
    for f in files:
        sys.stderr.write(f"[caliber] probing {os.path.basename(f)} ...\n"); sys.stderr.flush()
        st = probe(f)
        rows = host_rows(st)
        # 逐文件落主机画像
        base = os.path.splitext(os.path.basename(f))[0]
        d = os.path.join(a.out, base); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "host_profile_v2.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["ip", "class", "tx_pkts", "tx_bytes", "rx_pkts", "rx_bytes", "total_bytes",
                        "bytes_per_pkt", "tx_rx_ratio", "peers", "ports", "port_entropy_norm", "byte_share_pct"])
            w.writerows(rows)
        shares = [r[6] for r in rows]; tot = sum(shares) or 1
        n = len(shares)
        top1 = sum(sorted(shares, reverse=True)[:max(1, n // 100)]) / tot * 100
        top10 = sum(sorted(shares, reverse=True)[:max(1, n // 10)]) / tot * 100
        summary = {
            "file": st["file"], "packets": st["packets"], "bytes": st["bytes"],
            "duration_sec": round(st["last_ts"] - st["first_ts"], 1) if st["first_ts"] else None,
            "hosts_real": n, "multi_val_pkts": st["multi_val_pkts"], "ipv6_pkts": st["v6_pkts"],
            "direction_pkts": dict(st["dir"]), "direction_bytes": dict(st["dir_bytes"]),
            "ifindex_pkts": dict(st["ifidx"]), "ifindex_bytes": dict(st["ifidx_bytes"]),
            "gini": gini(shares), "top1pct_share": round(top1, 2), "top10pct_share": round(top10, 2),
            "tshark_rc": st["tshark_rc"],
        }
        per_file.append(summary)
        with open(os.path.join(d, "caliber_summary.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, ensure_ascii=False, indent=1)
        for k in grand:
            if isinstance(grand[k], Counter):
                grand[k].update(st[k] if k in st else {})
            elif isinstance(grand[k], defaultdict):
                for kk, vv in st[k].items(): grand[k][kk].update(vv)
            else:
                grand[k] += st.get(k, 0)
        all_host_rows += rows
        del st

    # 合并主机画像（同 IP 求和，对端/端口取最大）
    merged = {}
    for r in all_host_rows:
        ip = r[0]
        if ip not in merged:
            merged[ip] = r[:]
        else:
            m = merged[ip]
            m[2] += r[2]; m[3] += r[3]; m[4] += r[4]; m[5] += r[5]; m[6] += r[6]
            m[9] = max(m[9], r[9]); m[10] = max(m[10], r[10]); m[11] = max(m[11], r[11])
    tot = sum(m[6] for m in merged.values()) or 1
    for m in merged.values():
        m[7] = round(m[6] / (m[2] + m[4]), 1) if (m[2] + m[4]) else 0
        m[12] = round(m[6] / tot * 100, 4)
    mrows = sorted(merged.values(), key=lambda r: -r[6])
    with open(os.path.join(a.out, "host_profile_v2_merged.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "class", "tx_pkts", "tx_bytes", "rx_pkts", "rx_bytes", "total_bytes",
                    "bytes_per_pkt", "tx_rx_ratio", "peers", "ports", "port_entropy_norm", "byte_share_pct"])
        w.writerows(mrows)
    shares = [m[6] for m in mrows]; n = len(shares)
    srt = sorted(shares, reverse=True)
    agg = {
        "files": per_file,
        "merged": {
            "hosts_real": n,
            "total_bytes": sum(shares),
            "gini": gini(shares),
            "top1pct_share": round(sum(srt[:max(1, n // 100)]) / tot * 100, 2),
            "top10pct_share": round(sum(srt[:max(1, n // 10)]) / tot * 100, 2),
            "top100_share": round(sum(srt[:100]) / tot * 100, 2),
            "class_hosts": dict(Counter(m[1] for m in mrows)),
            "class_bytes": {k: round(v / 1e9, 2) for k, v in
                            Counter({k: 0 for k in set(m[1] for m in mrows)}).items()},
        },
        "direction_pkts": dict(grand["dir"]), "direction_bytes": dict(grand["dir_bytes"]),
        "ifindex_pkts": dict(grand["ifidx"]), "ifindex_bytes": dict(grand["ifidx_bytes"]),
        "service_ports": {p: dict(grand["svc"][p]) for p in SERVICE_PORTS if grand["svc"][p]},
        "service_ports_bytes": {p: dict(grand["svc_bytes"][p]) for p in SERVICE_PORTS if grand["svc_bytes"][p]},
        "watch_port_src_top": {p: dict(grand["watch_src"][p].most_common(15)) for p in WATCH_PORTS},
        "z172_peer_class": dict(grand["z172_cls"]),
        "z172_peer_top": dict(grand["z172_peer"].most_common(30)),
        "z172_peer_bytes_top": {k: v for k, v in grand["z172_peer_bytes"].most_common(15)},
        "multi_val_pkts": grand["multi_val_pkts"], "ipv6_pkts": grand["v6_pkts"],
        "packets": grand["packets"], "bytes": grand["bytes"],
    }
    # 类字节
    cb = Counter()
    for m in mrows: cb[m[1]] += m[6]
    agg["merged"]["class_bytes"] = {k: round(v / 1e9, 2) for k, v in cb.items()}
    with open(os.path.join(a.out, "caliber_all_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(agg, fh, ensure_ascii=False, indent=1)
    print(json.dumps(agg, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
