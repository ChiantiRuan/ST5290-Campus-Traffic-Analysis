#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 深读补刀（probe_deep2）：补齐两张图所缺的数据
  ① 每主机秒级序列（pkts/bytes）→ 供"周期主机时序曲线"类图
  ② 完整会话字节分布（全部会话，不截断）→ 供完整 Lorenz 曲线 / 累计占比折线 / 精确 Gini

与 probe_deep.py 的差别：那次只落盘了周期指标与会话 Top300；这次把序列与全量分布落盘。

口径：内部=10/8 ∪ 172.2/16；loopback 单列；非 IP 与不可解析地址跳过；聚合键取最外层 IP。
输出（--out 目录）：
  host_series_top.csv       每片段 Top N 主机的每秒 pkts/bytes
  host_series_watch.csv     指定关注列表（默认取 host_periodicity 前若干）的每秒序列
  session_bytes_dist.csv    会话字节的分箱分布（flows / bytes）
  session_bytes_lorenz.csv  会话字节累计占比曲线（0..1，步长 1%）
  session2_summary.json     汇总：会话数、总字节、精确 Gini、Top-N 占比、时长直方图
"""
import argparse, csv, glob, ipaddress, json, os, subprocess, sys, time
from collections import Counter, defaultdict

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags"]
INTERNAL = [ipaddress.ip_network("172.2.0.0/16")]
FLOW_CAP = 1_600_000


def icls(ip):
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
    if a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved or str(a).startswith("0."):
        return "skip"
    if any(a in n for n in INTERNAL) or a.is_private:
        return "int"
    return "ext"


def gini(vals):
    import numpy as np
    a = np.sort(np.asarray(vals, dtype=float))
    n = a.size
    if n == 0 or a.sum() == 0:
        return 0.0
    cum = np.cumsum(a)
    return float((n + 1 - 2 * (cum / cum[-1]).sum()) / n)


def probe(path, watch):
    st = {"file": os.path.basename(path), "packets": 0, "bytes": 0,
          "series": defaultdict(Counter), "series_bytes": defaultdict(Counter),
          "host_pkts": Counter(), "flows": {}, "flow_pruned": 0}
    cmd = [TSHARK, "-r", path, "-T", "fields"] + [x for f in FIELDS for x in ("-e", f)]
    pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 22)
    n, series, sbytes, hp, flows = len(FIELDS), st["series"], st["series_bytes"], st["host_pkts"], st["flows"]
    for line in pr.stdout:
        p = line.rstrip("\n").split("\t")
        if len(p) < n:
            p += [""] * (n - len(p))
        ts, flen, src, dst, proto, tsport, tdport, usport, udport, flags = p
        if not ts:
            continue
        try:
            t = int(float(ts)); flen = int(flen) if flen else 0
        except ValueError:
            continue
        st["packets"] += 1; st["bytes"] += flen
        src = src.split(",")[0].strip(); dst = dst.split(",")[0].strip()
        cs, cd = icls(src), icls(dst)
        if cs == "skip" or cd == "skip":
            continue
        hp[src] += 1
        series[src][t] += 1
        sbytes[src][t] += flen
        key = (proto, src, (tsport or usport).split(",")[0], dst, (tdport or udport).split(",")[0])
        if key[1:3] > key[3:5]:
            key = (proto, dst, key[4], src, key[2])
        f = flows.get(key)
        if f is None:
            if len(flows) > FLOW_CAP:
                keep = {k: v for k, v in flows.items() if v[2] >= 3}
                st["flow_pruned"] += len(flows) - len(keep); flows = st["flows"] = keep
            flows[key] = [t, t, 1, flen]
        else:
            f[1] = t; f[2] += 1; f[3] += flen
    pr.stdout.close(); pr.wait()
    st["tshark_rc"] = pr.returncode
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--top", type=int, default=100, help="每片段落盘 Top N 主机的秒级序列")
    ap.add_argument("--watch-file", default="", help="额外落盘这些主机的序列（每行一个 IP，可用 host_periodicity.csv 的 ip 列）")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = []
    for pat in a.pcaps:
        files += sorted(glob.glob(pat)) or [pat]
    watch = set()
    if a.watch_file and os.path.exists(a.watch_file):
        with open(a.watch_file, encoding="utf-8") as fh:
            for ln in fh:
                ip = ln.split(",")[0].strip()
                if ip and ip[0].isdigit():
                    watch.add(ip)

    all_flow_bytes, dur_all = [], []
    top_rows, watch_rows, dist, per_file = [], [], Counter(), []
    for f in files:
        t0 = time.time()
        sys.stderr.write("[deep2] %s ...\n" % os.path.basename(f)); sys.stderr.flush()
        st = probe(f, watch)
        # 唯一片段标签：取文件名里的 6 位时间戳（不能用 [-6:]，否则 …111416/…112821/…113321 都会变成 "1.pcap"）
        seg = os.path.basename(st["file"]).split("_")[-1].replace(".pcap", "")
        top = [ip for ip, _ in st["host_pkts"].most_common(a.top)]
        for ip in set(top) | watch:
            for sec, cnt in sorted(st["series"].get(ip, {}).items()):
                row = (ip, seg, int(sec), cnt, st["series_bytes"].get(ip, {}).get(sec, 0))
                (watch_rows if ip in watch else top_rows).append(row)
        fb, dur = [], []
        for (proto, a_ip, a_port, b_ip, b_port), (fst, lst, pk, by) in st["flows"].items():
            if pk < 2:
                continue
            fb.append(by); dur.append(lst - fst)
        all_flow_bytes += fb; dur_all += dur
        import math
        for b in fb:
            dist[int(math.floor(math.log10(b))) if b > 0 else 0] += 1
        per_file.append({"file": st["file"], "packets": st["packets"], "sessions": len(fb),
                         "pruned": st["flow_pruned"], "hosts": len(st["host_pkts"]),
                         "secs": round(time.time() - t0, 1)})
        del st
        sys.stderr.write("[deep2] done %s in %.0fs\n" % (os.path.basename(f), time.time() - t0))

    with open(os.path.join(a.out, "host_series_top.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["ip", "segment", "unix_sec", "packets", "bytes"])
        w.writerows(top_rows)
    with open(os.path.join(a.out, "host_series_watch.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["ip", "segment", "unix_sec", "packets", "bytes"])
        w.writerows(watch_rows)
    with open(os.path.join(a.out, "session_bytes_dist.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["byte_magnitude", "flows"])
        for k in sorted(dist):
            w.writerow(["1e%d" % k, dist[k]])

    import numpy as np
    bytes_arr = np.array(all_flow_bytes, dtype=np.int64)
    dur_arr = np.array(dur_all, dtype=float)
    order = np.argsort(bytes_arr)
    sb, sd = bytes_arr[order], dur_arr[order]
    cum = np.cumsum(sb) / sb.sum()
    lorenz = [(round(i / 100, 2), float(cum[max(int(len(sb) * i / 100) - 1, 0)])) for i in range(1, 101)]
    with open(os.path.join(a.out, "session_bytes_lorenz.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["top_share_of_flows", "share_of_bytes"])
        w.writerows(lorenz)
    bins = [0.001, 0.01, 0.1, 1, 10, 60, 300]
    dh = Counter()
    for v in dur_arr:
        for b in bins:
            if v < b:
                dh["< %s s" % b] += 1; break
        else:
            dh[">= %ss" % bins[-1]] += 1
    summary = {
        "files": per_file,
        "sessions_ge2pkt": int(len(sb)),
        "session_bytes_total": int(sb.sum()),
        "session_gini": round(gini(sb), 4),
        "top_flow_shares": {f"top_{k}": round(float(sb[-k:].sum() / sb.sum()), 4)
                            for k in (10, 100, 1000, 10000, 100000) if k <= len(sb)},
        "duration_hist": dict(dh),
        "duration_median_s": round(float(np.median(dur_arr)), 3),
        "duration_p90_s": round(float(np.percentile(dur_arr, 90)), 3),
        "host_series_rows": len(top_rows) + len(watch_rows),
        "watch_hosts": sorted(watch),
    }
    with open(os.path.join(a.out, "session2_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1, default=str)
    print(json.dumps({k: summary[k] for k in ("sessions_ge2pkt", "session_bytes_total", "session_gini",
                                             "top_flow_shares", "duration_hist", "duration_median_s",
                                             "host_series_rows")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
