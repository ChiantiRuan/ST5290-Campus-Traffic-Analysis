#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 深读探针 —— 一遍读盘，产出 A1/A2/A3/A4 四组结果。

A1 域名层      ：DNS 查询名 / TLS SNI / HTTP Host 与 User-Agent
A3 会话级画像  ：会话时长分布、单会话字节 Top（大象流）
A4 会话发起方  ：首包/TCP SYN 判定发起方 → 客户侧"客户端型 vs 资源型"
A2 主机级周期  ：内网主机秒级序列的 CV 与周期图峰值（对比随机基线）

口径：内部=10/8 ∪ 172.2/16；loopback 单列；非 IP 与不可解析地址跳过；聚合键取最外层 IP。
限制（必须写进报告）：DNS/SNI 只能看到"问过名字/亮明身份"的连接；会话表做了剪枝
（丢弃 <3 包的短流），故时长分布偏向多包会话；17 分钟窗口内无法谈日内规律。

用法:
  caffeinate -is python probe_deep.py "/Volumes/Extreme SSD/ST5290_pcap"/cap_*.pcap \
      --out ../双周4_报告/deep_probe
"""
import argparse, csv, glob, ipaddress, json, math, os, subprocess, sys, time
from collections import Counter, defaultdict

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags",
          "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
          "tls.handshake.extensions_server_name", "tls.handshake.type",
          "http.host", "http.user_agent"]
DECLARED_INTERNAL = [ipaddress.ip_network("172.2.0.0/16")]
FLOW_CAP = 1_200_000
BADNAME = ("", "-", "(null)")


def cls(ip):
    if not ip:
        return "skip"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "skip"
    if a.version != 4:
        return "skip"
    if a.is_loopback:
        return "loop"
    if a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved:
        return "skip"
    if str(a).startswith("0."):
        return "skip"
    if any(a in n for n in DECLARED_INTERNAL) or a.is_private:
        return "int"
    return "ext"


def first(v):
    return v.split(",")[0].strip() if v else ""


def probe(path):
    st = {
        "file": os.path.basename(path), "packets": 0, "bytes": 0,
        "dns": Counter(), "dns_type": Counter(), "dns_rcode": Counter(),
        "sni": Counter(), "tls_type": Counter(),
        "host": Counter(), "ua": Counter(),
        "flows": {}, "flow_pruned": 0,
        "host_sec": defaultdict(Counter), "host_win": {}, "host_pkts": Counter(),
        "init_matrix": Counter(), "init_bytes": Counter(),
        "tls_no_sni": 0,
    }
    cmd = [TSHARK, "-r", path, "-T", "fields"] + [x for f in FIELDS for x in ("-e", f)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1 << 22)
    nf = len(FIELDS)
    flows = st["flows"]
    for line in proc.stdout:
        p = line.rstrip("\n").split("\t")
        if len(p) < nf:
            p += [""] * (nf - len(p))
        ts, flen, src, dst, proto, tsport, tdport, usport, udport, flags, \
            dqname, dqtype, drcode, sni, tlstype, hhost, hua = p
        if not ts:
            continue
        try:
            t = float(ts); flen = int(flen) if flen else 0
        except ValueError:
            continue
        st["packets"] += 1; st["bytes"] += flen
        src = src.split(",")[0].strip(); dst = dst.split(",")[0].strip()
        cs, cd = cls(src), cls(dst)

        # ---- A1 域名层 ----
        # 注意：dns.qry.name 在"查询"和"响应"两类包里都出现，故此处计入的是
        # "名称出现次数" ≈ 查询数的 2 倍（唯一名数不受影响）。仅统计查询侧请加
        # dns.flags.response==False 过滤（见 probe_segattr.py 的修法）。
        if dqname:
            for nm in dqname.split(","):
                nm = nm.strip().rstrip(".").lower()
                if nm and nm not in BADNAME and not nm.endswith(".arpa"):
                    st["dns"][nm] += 1
            if dqtype:
                st["dns_type"][dqtype.split(",")[0]] += 1
            if drcode:
                st["dns_rcode"][drcode.split(",")[0]] += 1
        if sni and "1" in tlstype.split(","):        # ClientHello
            for nm in sni.split(","):
                nm = nm.strip().rstrip(".").lower()
                if nm and nm not in BADNAME:
                    st["sni"][nm] += 1
        elif tlstype and "1" in tlstype.split(","):
            st["tls_no_sni"] += 1
        if tlstype:
            for x in tlstype.split(","):
                st["tls_type"][x] += 1
        if hhost:
            for nm in hhost.split(","):
                st["host"][nm.strip().lower()] += 1
        if hua:
            st["ua"][hua[:120]] += 1

        if cs in ("skip",) or cd in ("skip",):
            continue
        dport = (tdport or udport or "").split(",")[0]
        sport = (tsport or usport or "").split(",")[0]

        # ---- A2 主机秒级序列（只对内部主机）----
        if cs == "int":
            key = (src, st["file"][-6:])
            st["host_sec"][key][int(t)] += 1
            st["host_pkts"][src] += 1
            w = st["host_win"].get(src)
            st["host_win"][src] = (min(w[0], t), max(w[1], t)) if w else (t, t)

        # ---- A3/A4 会话表 ----
        if proto == "6":
            pa, pb = (src, sport), (dst, dport)
        else:
            pa, pb = (src, sport), (dst, dport)
        if pa > pb:
            pa, pb = pb, pa
        k = (proto, pa[0], pa[1], pb[0], pb[1])
        f = flows.get(k)
        syn = ack = False
        if flags:
            try:
                v = int(flags.split(",")[0], 16); syn = bool(v & 0x02); ack = bool(v & 0x10)
            except ValueError:
                pass
        if f is None:
            if len(flows) > FLOW_CAP:
                keep = {kk: vv for kk, vv in flows.items() if vv[2] >= 3}
                st["flow_pruned"] += len(flows) - len(keep); flows = st["flows"] = keep
            flows[k] = [t, t, 1, flen, src if not (syn and not ack) else src, 0]
            if syn and not ack:
                flows[k][5] = 1
        else:
            f[1] = t; f[2] += 1; f[3] += flen
            if syn and not ack and not f[5]:
                f[4] = src; f[5] = 1
    proc.stdout.close(); proc.wait()
    st["tshark_rc"] = proc.returncode
    return st


def dur_hist(rows):
    bins = [0.001, 0.01, 0.1, 1, 10, 60, 300]
    h = Counter()
    for r in rows:
        d = r[5]
        for b in bins:
            if d < b:
                h["< %s s" % b] += 1; break
        else:
            h[">= %ss" % bins[-1]] += 1
    return h


def periodicity(host_sec, host_pkts, min_secs=30, min_mean=2.0):
    """返回 [(ip, seg, active_secs, mean_pps, cv, top_period_s, peak_ratio)]"""
    import numpy as np
    out = []
    for (ip, seg), c in host_sec.items():
        if len(c) < min_secs:
            continue
        lo, hi = min(c), max(c)
        n = hi - lo + 1
        if n > 4000:
            continue
        arr = np.zeros(n)
        for s, v in c.items():
            arr[s - lo] = v
        m = arr.mean()
        if m < min_mean:
            continue
        cv = float(arr.std() / m)
        x = arr - m
        pw = np.abs(np.fft.rfft(x)) ** 2
        if len(pw) < 4:
            continue
        pw = pw[1:]
        k = int(np.argmax(pw)); peak = float(pw[k])
        period = n / (k + 1)
        rng = np.random.default_rng(0)
        base = []
        for _ in range(80):
            y = rng.permutation(x)
            q = np.abs(np.fft.rfft(y)) ** 2
            base.append(float(q[1:].max()))
        b95 = float(np.percentile(base, 95)) or 1e-9
        out.append((ip, seg, len(c), round(m, 2), round(cv, 3), round(period, 1), round(peak / b95, 2)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = []
    for pat in a.pcaps:
        files += sorted(glob.glob(pat)) or [pat]

    G = {k: Counter() for k in ("dns", "dns_type", "dns_rcode", "sni", "tls_type", "host", "ua",
                                "init_matrix", "init_bytes")}
    G["tls_no_sni"] = 0; G["packets"] = 0; G["bytes"] = 0
    all_flows = []
    per_file = []
    host_sec_all, host_pkts_all = {}, Counter()
    for f in files:
        t0 = time.time()
        sys.stderr.write("[deep] %s ...\n" % os.path.basename(f)); sys.stderr.flush()
        st = probe(f)
        for k in ("dns", "dns_type", "dns_rcode", "sni", "tls_type", "host", "ua",
                  "init_matrix", "init_bytes"):
            G[k].update(st[k])
        G["tls_no_sni"] += st["tls_no_sni"]
        G["packets"] += st["packets"]; G["bytes"] += st["bytes"]
        # 会话聚合
        rows = []
        for (proto, a_ip, a_port, b_ip, b_port), (fst, lst, pk, by, ini, _) in st["flows"].items():
            if pk < 2:
                continue
            ic, rc_ = cls(ini), (cls(b_ip) if ini == a_ip else cls(a_ip))
            rows.append((ini, (b_ip if ini == a_ip else a_ip), a_port if ini == a_ip else b_port,
                         proto, pk, round(lst - fst, 3), by, ic, rc_))
            G["init_matrix"]["%s->%s" % (ic, rc_)] += 1
            G["init_bytes"]["%s->%s" % (ic, rc_)] += by
        all_flows += rows
        # 主机周期（分段内）
        for (ip, seg), c in st["host_sec"].items():
            host_sec_all.setdefault(ip, {})[seg] = dict(c)
        host_pkts_all.update(st["host_pkts"])
        per_file.append({"file": st["file"], "packets": st["packets"],
                         "sessions": len(rows), "floors_pruned": st["flow_pruned"],
                         "dns_names": len(st["dns"]), "sni_names": len(st["sni"]),
                         "secs": round(time.time() - t0, 1)})
        del st
        sys.stderr.write("[deep] done %s in %.0fs\n" % (os.path.basename(f), time.time() - t0))

    # ---- A1 输出 ----
    with open(os.path.join(a.out, "domains_top.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["kind", "name", "count"])
        for nm, c in G["dns"].most_common(200):
            w.writerow(["dns", nm, c])
        for nm, c in G["sni"].most_common(200):
            w.writerow(["tls_sni", nm, c])
        for nm, c in G["host"].most_common(100):
            w.writerow(["http_host", nm, c])
    with open(os.path.join(a.out, "dns_detail.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["qtype", "count"])
        for k, v in G["dns_type"].most_common():
            w.writerow([k, v])
        w.writerow([]); w.writerow(["rcode", "count"])
        for k, v in G["dns_rcode"].most_common():
            w.writerow([k, v])
    with open(os.path.join(a.out, "http_user_agents.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["user_agent", "count"])
        for k, v in G["ua"].most_common(100):
            w.writerow([k, v])

    # ---- A3 输出 ----
    all_flows.sort(key=lambda r: -r[6])
    with open(os.path.join(a.out, "sessions_top.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["initiator", "responder", "init_port", "proto", "packets", "duration_s", "bytes",
                    "init_class", "resp_class", "MB_per_s"])
        for r in all_flows[:300]:
            w.writerow(list(r) + [round(r[6] / 1e6 / max(r[5], 0.001), 3)])
    hist = dur_hist(all_flows)
    with open(os.path.join(a.out, "session_duration_hist.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["duration_bin", "sessions"])
        for k, v in hist.items():
            w.writerow([k, v])

    # ---- A4 输出 ----
    with open(os.path.join(a.out, "initiator_matrix.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["initiator->responder", "sessions", "bytes"])
        for k in sorted(G["init_matrix"], key=lambda x: -G["init_matrix"][x]):
            w.writerow([k, G["init_matrix"][k], G["init_bytes"][k]])
    ext_types = Counter()
    for r in all_flows:
        if r[0] and cls(r[0]) == "ext":
            ext_types["ext_initiated (client-side)"] += 1
        elif cls(r[1]) == "ext":
            ext_types["ext_responded (resource-side)"] += 1
    with open(os.path.join(a.out, "client_side_types.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["type", "sessions"])
        for k, v in ext_types.most_common():
            w.writerow([k, v])

    # ---- A2 输出 ----
    rows = []
    for ip, segs in host_sec_all.items():
        for seg, c in segs.items():
            rows += periodicity({(ip, seg): c}, {}, min_secs=30, min_mean=2.0)
    rows.sort(key=lambda r: -r[6])
    with open(os.path.join(a.out, "host_periodicity.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "segment", "active_secs", "mean_pps", "cv", "top_period_s", "peak_vs_random"])
        w.writerows(rows)

    summary = {
        "files": per_file,
        "totals": {"packets": G["packets"], "bytes": G["bytes"],
                   "dns_unique_names": len(G["dns"]), "sni_unique_names": len(G["sni"]),
                   "http_unique_hosts": len(G["host"]), "client_hellos_without_sni": G["tls_no_sni"],
                   "sessions_ge2pkt": len(all_flows)},
        "top_dns": G["dns"].most_common(30),
        "top_sni": G["sni"].most_common(30),
        "top_http_hosts": G["host"].most_common(20),
        "top_user_agents": G["ua"].most_common(15),
        "dns_qtypes": G["dns_type"].most_common(10),
        "dns_rcodes": G["dns_rcode"].most_common(10),
        "initiator_matrix": dict(G["init_matrix"]),
        "initiator_bytes": dict(G["init_bytes"]),
        "session_duration_hist": hist,
        "top_sessions": [list(r) for r in all_flows[:20]],
        "periodicity_top": rows[:40],
        "client_side_types": dict(ext_types),
    }
    with open(os.path.join(a.out, "deep_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1, default=str)
    print(json.dumps({k: summary[k] for k in ("totals", "top_dns", "top_sni", "initiator_matrix",
                                             "session_duration_hist", "client_side_types")},
                     ensure_ascii=False, indent=1, default=str)[:4000])


if __name__ == "__main__":
    main()
