#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 数据探针 —— 只读一次 pcap，输出 schema / 质量 / 分布 报告。

用途：在正式分析之前，先把"这份数据是什么"搞清楚，产出可直接充当双周 1 里程碑的
      「数据字典 + 初步描述统计」。不写中间大文件（磁盘友好）。

用法:
  python probe_pcap.py <pcap 路径> [更多 pcap...] [--out 输出目录]
示例:
  python probe_pcap.py "/Volumes/Extreme SSD/ST5290_pcap/cap_20260920_111416.pcap" \
      --out ~/Desktop/HERMES/ST5290_CloudTrafficProject/双周3_报告/probe

输出（全部为小文件）:
  probe_report.md       人读报告（时间跨度/协议/主机/端口/包长/方向/质量）
  probe_summary.json    机读汇总（供后续管线读字段口径）
  per_second.csv        秒级序列（包数/字节数/独立源目的数）
  top_hosts.csv         主机画像 TOP100（收发包数/字节/对端数/端口数/内外网）
  top_ports.csv         目的端口 TOP50
  pktlen_hist.csv       包长直方图（64B 分箱）
  top_conversations.csv 会话 TOP50（按字节）

实现要点:
  · tshark 流式输出字段（-T fields），Python 逐行聚合；单次读取，不落中间数据
  · 支持 SLL2（Linux `tcpdump -i any`）与以太网抓包；VLAN 缺失时如实记录
  · 主机分类：本机回环 / 内网(RFC1918) / 外网；会话表用 heavy-hitter 剪枝控制内存
"""
import argparse
import csv
import ipaddress
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "vlan.id"]
PROTO_NAME = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6", "47": "GRE", "50": "ESP", "132": "SCTP"}
PAIR_PRUNE_AT = 500_000        # 会话表超过此规模就剪枝（保留出现 >1 次的）
EXTRA_INTERNAL = []            # 由 --internal-prefix 追加（如平台用的 172.2.0.0/16 非 RFC1918 私网段）


def ip_class(ip):
    """返回 loopback / internal / external / unknown
    注意：RFC1918 之外的内网段（实测平台用 172.2.0.0/16）必须用 --internal-prefix 显式声明，
    否则会被判成 external —— 这会直接影响"内部↔外部"方向的统计口径。"""
    if not ip:
        return "unknown"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_private:            # 10/8、172.16/12、192.168/16、fc00::/7
        return "internal"
    if any(a in n for n in EXTRA_INTERNAL):
        return "internal"
    return "external"


def bins64(n):
    return (n // 64) * 64


def probe(path):
    st = {
        "file": os.path.basename(path), "path": path, "size_bytes": os.path.getsize(path),
        "packets": 0, "bytes": 0, "first_ts": None, "last_ts": None, "vlan_packets": 0,
        "proto": Counter(), "per_sec": defaultdict(lambda: [0, 0]), "per_min": defaultdict(lambda: [0, 0]),
        "hosts": defaultdict(lambda: {"tx_pkts": 0, "tx_bytes": 0, "rx_pkts": 0, "rx_bytes": 0,
                                      "ports": set(), "peers": set(), "ports_c": Counter(),
                                      "protos": Counter(), "first_ts": None, "last_ts": None}),
        "src_set": set(), "dst_set": set(), "pktlen": Counter(), "dports": Counter(),
        "pairs": defaultdict(int), "pair_bytes": defaultdict(int),
        "flows": {"internal-internal": 0, "internal-external": 0, "loopback": 0, "external-external": 0},
    }
    cmd = [TSHARK, "-r", path, "-T", "fields"] + [x for f in FIELDS for x in ("-e", f)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 22)
    assert proc.stdout is not None
    n = 0
    for line in proc.stdout:
        p = line.rstrip("\n").split("\t")
        if len(p) < len(FIELDS):
            p += [""] * (len(FIELDS) - len(p))
        ts, flen, src, dst, proto, tsport, tdport, usport, udport, vlan = p[:10]
        if not ts:
            continue
        try:
            t = float(ts); flen = int(flen) if flen else 0
        except ValueError:
            continue
        n += 1
        st["packets"] += 1
        st["bytes"] += flen
        if st["first_ts"] is None or t < st["first_ts"]:
            st["first_ts"] = t
        if st["last_ts"] is None or t > st["last_ts"]:
            st["last_ts"] = t
        if vlan:
            st["vlan_packets"] += 1
        st["proto"][PROTO_NAME.get(proto, proto or "non-IP")] += 1
        sec = int(t)
        for store in (st["per_sec"], st["per_min"]):
            key = sec if store is st["per_sec"] else sec - sec % 60
            store[key][0] += 1
            store[key][1] += flen
        st["pktlen"][bins64(flen)] += 1
        dport = tdport or udport
        if dport:
            st["dports"][dport] += 1
        if src:
            st["src_set"].add(src)
            h = st["hosts"][src]
            h["tx_pkts"] += 1; h["tx_bytes"] += flen
            if len(h["peers"]) < 200 and dst:
                h["peers"].add(dst)
            if dport:
                h["ports"].add(dport); h["ports_c"][dport] += 1
                if len(h["ports_c"]) > 2000:                       # 控制内存：只留高频 1000 个端口
                    h["ports_c"] = Counter(dict(h["ports_c"].most_common(1000)))
            if proto:
                h["protos"][proto] += 1
            if h["first_ts"] is None or t < h["first_ts"]:
                h["first_ts"] = t
            h["last_ts"] = t
        if dst:
            st["dst_set"].add(dst)
            h = st["hosts"][dst]
            h["rx_pkts"] += 1; h["rx_bytes"] += flen
            if len(h["peers"]) < 200 and src:
                h["peers"].add(src)
            if dport:
                h["ports"].add(dport); h["ports_c"][dport] += 1
                if len(h["ports_c"]) > 2000:
                    h["ports_c"] = Counter(dict(h["ports_c"].most_common(1000)))
            if proto:
                h["protos"][proto] += 1
            if h["first_ts"] is None or t < h["first_ts"]:
                h["first_ts"] = t
            h["last_ts"] = t
        cs, cd = ip_class(src), ip_class(dst)
        if cs == "loopback" or cd == "loopback":
            st["flows"]["loopback"] += 1
        elif cs == "internal" and cd == "internal":
            st["flows"]["internal-internal"] += 1
        elif cs == "external" and cd == "external":
            st["flows"]["external-external"] += 1
        else:
            st["flows"]["internal-external"] += 1
        if src and dst:
            key = (src, dst)
            st["pairs"][key] += 1
            st["pair_bytes"][key] += flen
            if len(st["pairs"]) > PAIR_PRUNE_AT:      # heavy-hitter 剪枝
                st["pairs"] = defaultdict(int, {k: v for k, v in st["pairs"].items() if v > 1})
                st["pair_bytes"] = defaultdict(int, {k: v for k, v in st["pair_bytes"].items() if v > 1})
    proc.stdout.close()
    proc.wait()
    st["proc_rc"] = proc.returncode
    st["parsed_lines"] = n
    return st


def ts_str(t):
    return datetime.fromtimestamp(t, tz=timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " CST" if t else "-"


def write_outputs(st, outdir):
    os.makedirs(outdir, exist_ok=True)
    dur = (st["last_ts"] - st["first_ts"]) if st["first_ts"] and st["last_ts"] else 0
    summary = {
        "file": st["file"], "size_gb": round(st["size_bytes"] / 1e9, 2),
        "packets": st["packets"], "bytes": st["bytes"],
        "first_ts": ts_str(st["first_ts"]), "last_ts": ts_str(st["last_ts"]),
        "duration_sec": round(dur, 1),
        "avg_pps": round(st["packets"] / dur, 1) if dur else None,
        "avg_mbps": round(st["bytes"] * 8 / dur / 1e6, 1) if dur else None,
        "avg_pkt_len": round(st["bytes"] / st["packets"], 1) if st["packets"] else None,
        "unique_src": len(st["src_set"]), "unique_dst": len(st["dst_set"]),
        "vlan_packets": st["vlan_packets"],
        "protocol": dict(st["proto"].most_common()),
        "direction": st["flows"],
        "host_classes": dict(Counter(ip_class(h) for h in set(st["hosts"]))),
        "tshark_rc": st["proc_rc"],
    }
    # 注意：summary 的落盘必须在所有指标计算完之后（集中度在主机会话表之后才算），
    # 所以这里不写盘，统一放到 write_outputs 末尾再 dump。

    with open(os.path.join(outdir, "per_second.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["unix_sec", "time_cst", "packets", "bytes"])
        for k in sorted(st["per_sec"]):
            v = st["per_sec"][k]
            w.writerow([k, ts_str(k), v[0], v[1]])

    with open(os.path.join(outdir, "top_hosts.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["ip", "class", "tx_pkts", "tx_bytes", "rx_pkts", "rx_bytes",
                                       "total_bytes", "peers_seen", "dst_ports_seen"])
        top = sorted(st["hosts"].items(), key=lambda kv: -(kv[1]["tx_bytes"] + kv[1]["rx_bytes"]))[:100]
        for ip, h in top:
            w.writerow([ip, ip_class(ip), h["tx_pkts"], h["tx_bytes"], h["rx_pkts"], h["rx_bytes"],
                        h["tx_bytes"] + h["rx_bytes"], len(h["peers"]), len(h["ports"])])

    # ---- 全量主机画像（支撑"人群/群体结构"分析：所有主机，不只 Top100）----
    def port_entropy(h):
        c = h["ports_c"]
        tot = sum(c.values())
        if tot <= 0 or len(c) <= 1:
            return 0.0
        import math
        H = -sum((v / tot) * math.log2(v / tot) for v in c.values())
        return round(H / math.log2(len(c)), 4)          # 归一化到 [0,1]

    rows = []
    tot_bytes_all = sum(h["tx_bytes"] + h["rx_bytes"] for h in st["hosts"].values()) or 1
    for ip, h in st["hosts"].items():
        tb_ = h["tx_bytes"] + h["rx_bytes"]
        act = (h["last_ts"] - h["first_ts"]) if (h["first_ts"] and h["last_ts"]) else 0
        rows.append([ip, ip_class(ip), h["tx_pkts"], h["tx_bytes"], h["rx_pkts"], h["rx_bytes"], tb_,
                     round(tb_ / (h["tx_pkts"] + h["rx_pkts"]), 1) if (h["tx_pkts"] + h["rx_pkts"]) else 0,
                     round(h["tx_bytes"] / h["rx_bytes"], 3) if h["rx_bytes"] else "",
                     len(h["peers"]), len(h["ports"]), port_entropy(h),
                     h["protos"].most_common(1)[0][0] if h["protos"] else "",
                     round(act, 1), round(tb_ / tot_bytes_all * 100, 4)])
    rows.sort(key=lambda r: -r[6])
    with open(os.path.join(outdir, "host_profile.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "class", "tx_pkts", "tx_bytes", "rx_pkts", "rx_bytes", "total_bytes",
                    "bytes_per_pkt", "tx_rx_ratio", "peers_seen", "dst_ports_seen",
                    "port_entropy_norm", "top_proto", "active_sec", "byte_share_pct"])
        w.writerows(rows)

    # 集中度：主机字节占比的集中程度。
    # 注意命名：top1_pct_* / top10_pct_* 是"前 1%/10% 的主机"；top100_hosts_share_abs 是
    # "前 100 台主机"（绝对台数）——后者是绝对值，不参与百分位单调性比较。
    tot_b = sum(r[6] for r in rows) or 1
    sorted_b = sorted((r[6] for r in rows), reverse=True)
    n = len(sorted_b) or 1
    def share(pct):
        k = max(1, int(n * pct))
        return round(sum(sorted_b[:k]) / tot_b * 100, 2)
    summary["hosts_total"] = n
    summary["host_concentration"] = {"top1_pct_hosts_share": share(0.01),
                                     "top10_pct_hosts_share": share(0.10),
                                     "top100_hosts_share_abs": round(sum(sorted_b[:100]) / tot_b * 100, 2)}
    # 所有指标算完后再落盘（含 hosts_total / host_concentration）
    json.dump(summary, open(os.path.join(outdir, "probe_summary.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    with open(os.path.join(outdir, "top_ports.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["dst_port", "packets"])
        for p, c in st["dports"].most_common(50):
            w.writerow([p, c])

    with open(os.path.join(outdir, "pktlen_hist.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["len_bin", "packets"])
        for b in sorted(st["pktlen"]):
            w.writerow([f"{b}-{b+63}", st["pktlen"][b]])

    with open(os.path.join(outdir, "top_conversations.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["src", "dst", "packets", "bytes"])
        for (a, b), c in sorted(st["pair_bytes"].items(), key=lambda kv: -kv[1])[:50]:
            w.writerow([a, b, st["pairs"].get((a, b), 0), c])

    # ---------- 人读报告 ----------
    L = []
    L.append(f"# 数据探针报告 — {st['file']}\n")
    L.append(f"- 文件大小：**{st['size_bytes']/1e9:.2f} GB**")
    L.append(f"- 包数：**{st['packets']:,}** ｜ 字节：**{st['bytes']:,}**")
    L.append(f"- 时间范围：**{ts_str(st['first_ts'])} → {ts_str(st['last_ts'])}**（时长 **{dur:.1f} 秒**）")
    L.append(f"- 平均速率：**{summary['avg_pps']} 包/秒**，**{summary['avg_mbps']} Mbps** ｜ 平均包长 **{summary['avg_pkt_len']} B**")
    L.append(f"- 独立源 IP：**{len(st['src_set'])}** ｜ 独立目的 IP：**{len(st['dst_set'])}**")
    L.append(f"- VLAN 标签包：**{st['vlan_packets']:,}**（{'无 VLAN → 无法直接区分租户' if st['vlan_packets']==0 else '存在 VLAN 标签'}）\n")

    L.append("## 1. 协议构成\n")
    L.append("| 协议 | 包数 | 占比 |")
    L.append("|---|---|---|")
    for p, c in st["proto"].most_common():
        L.append(f"| {p} | {c:,} | {c/st['packets']*100:.2f}% |")
    L.append("")
    L.append("## 2. 流量方向（按 IP 类别）\n")
    L.append("| 类型 | 包数 | 占比 |")
    L.append("|---|---|---|")
    for k, v in st["flows"].items():
        L.append(f"| {k} | {v:,} | {v/st['packets']*100:.2f}% |")
    L.append("\n（loopback = 本机回环 127.0.0.0/8；internal = RFC1918 内网；external = 公网）\n")
    L.append("## 3. 主机画像 TOP 15（按总字节）\n")
    L.append("| IP | 类别 | 发送包 | 发送字节 | 接收包 | 接收字节 | 对端数 | 目的端口数 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for ip, h in sorted(st["hosts"].items(), key=lambda kv: -(kv[1]["tx_bytes"] + kv[1]["rx_bytes"]))[:15]:
        L.append(f"| {ip} | {ip_class(ip)} | {h['tx_pkts']:,} | {h['tx_bytes']:,} | {h['rx_pkts']:,} | {h['rx_bytes']:,} | {len(h['peers'])} | {len(h['ports'])} |")
    L.append("\n## 4. 目的端口 TOP 15\n")
    L.append("| 端口 | 包数 | 占比 | 常见服务 |")
    L.append("|---|---|---|---|")
    wellknown = {"443": "HTTPS", "80": "HTTP", "22": "SSH", "53": "DNS", "3306": "MySQL",
                 "6379": "Redis", "8123": "ClickHouse HTTP", "9000": "ClickHouse native",
                 "5432": "PostgreSQL", "8080": "HTTP alt", "123": "NTP", "445": "SMB"}
    for p, c in st["dports"].most_common(15):
        L.append(f"| {p} | {c:,} | {c/st['packets']*100:.2f}% | {wellknown.get(p,'')} |")
    L.append("\n## 5. 包长分布（64B 分箱，前 12）\n")
    L.append("| 分箱 | 包数 | 占比 |")
    L.append("|---|---|---|")
    for b in sorted(st["pktlen"], key=lambda x: -st["pktlen"][x])[:12]:
        c = st["pktlen"][b]
        L.append(f"| {b}-{b+63} | {c:,} | {c/st['packets']*100:.2f}% |")
    L.append("\n## 6. 会话 TOP 10（按字节）\n")
    L.append("| 源 | 目的 | 包数 | 字节 |")
    L.append("|---|---|---|---|")
    for (a, b), c in sorted(st["pair_bytes"].items(), key=lambda kv: -kv[1])[:10]:
        L.append(f"| {a} | {b} | {st['pairs'].get((a,b),0):,} | {c:,} |")
    L.append(f"\n---\n*tshark 返回码：{st['proc_rc']}｜聚合行数：{st['parsed_lines']:,}｜生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    open(os.path.join(outdir, "probe_report.md"), "w", encoding="utf-8").write("\n".join(L))
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--out", default=os.path.expanduser("~/Desktop/HERMES/ST5290_CloudTrafficProject/双周3_报告/probe"))
    ap.add_argument("--internal-prefix", action="append", default=[], metavar="CIDR",
                    help="额外视为内网的网段（可重复），如 --internal-prefix 172.2.0.0/16")
    a = ap.parse_args()
    EXTRA_INTERNAL.extend(ipaddress.ip_network(c, strict=False) for c in a.internal_prefix)
    if EXTRA_INTERNAL:
        print(f"[probe] 额外内网段: {[str(n) for n in EXTRA_INTERNAL]}", flush=True)
    summaries = []
    for p in a.pcaps:
        if not os.path.exists(p):
            print(f"跳过（不存在）: {p}"); continue
        print(f"[probe] 开始读 {os.path.basename(p)} ({os.path.getsize(p)/1e9:.2f} GB) …", flush=True)
        st = probe(p)
        sub = os.path.join(a.out, os.path.splitext(os.path.basename(p))[0])
        s = write_outputs(st, sub)
        summaries.append(s)
        print(f"[probe] 完成 {st['file']}: {st['packets']:,} 包, {s['duration_sec']}s, "
              f"{s['avg_pps']} pps, VLAN={st['vlan_packets']}, 输出 → {sub}", flush=True)
    if summaries:
        # 合并式写入：多次运行（如分批跑文件）不会互相覆盖 —— 按文件名去重更新
        dst = os.path.join(a.out, "all_files_summary.json")
        merged = {}
        if os.path.exists(dst):
            try:
                for s in json.load(open(dst, encoding="utf-8")):
                    merged[s["file"]] = s
            except Exception:
                pass
        for s in summaries:
            merged[s["file"]] = s
        out_list = [merged[k] for k in sorted(merged)]
        json.dump(out_list, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[probe] 汇总 {len(out_list)} 个文件 → {dst}", flush=True)


if __name__ == "__main__":
    main()
