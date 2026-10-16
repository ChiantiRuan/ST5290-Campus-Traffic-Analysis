#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 细粒度（/24）属性化探针：回答"哪个网段在干服务器的事、哪个在干办公终端的事"。
每个抓包只读取前 N 包；按源 /24 汇总 DNS 查询名 / TLS SNI / HTTP UA 分类。
过滤非 ASCII 名称（畸形解析）；只统计 DNS 查询侧（response 位为 False）。

用法: python probe_seg24.py cap_*.pcap --limit 500000
"""
import argparse, glob, os, re, subprocess, sys
from collections import Counter, defaultdict

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["ip.src", "dns.qry.name", "dns.flags.response",
          "tls.handshake.extensions_server_name", "tls.handshake.type", "http.user_agent"]
UA_CLIENT = re.compile(r"MicroMessenger|Mozilla|Windows NT|360|AppleWebKit|Chrome|Safari|Edg|Firefox|QQBrowser|DingTalk|WeCom|Mac OS X|iPhone", re.I)
UA_SERVER = re.compile(r"Go-http-client|curl|python|okhttp|Java|Apache|nginx|libwww|Wget|PostmanRuntime|node-fetch|axios|WinHttp|Microsoft-Delivery", re.I)
ASCII = re.compile(r"^[\x20-\x7e]+$")


def seg24(ip):
    if not ip:
        return "unknown"
    p = ip.split(".")
    if len(p) != 4:
        return "unknown"
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.2."):
        return ".".join(p[:3]) + ".0/24"
    if ip.startswith("127."):
        return "loopback"
    return "public"


def ascii_name(nm):
    nm = nm.strip().rstrip(".").lower()
    return nm if nm and nm not in ("-", "(null)") and ASCII.match(nm) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--limit", type=int, default=500000)
    a = ap.parse_args()
    files = []
    for pat in a.pcaps:
        files += sorted(glob.glob(pat)) or [pat]

    dns = defaultdict(Counter); sni = defaultdict(Counter); ua = defaultdict(Counter)
    ua_cls = defaultdict(Counter); pkts = Counter(); names_total = Counter()
    for f in files:
        sys.stderr.write("[seg24] %s (first %d)\n" % (os.path.basename(f), a.limit)); sys.stderr.flush()
        cmd = [TSHARK, "-r", f, "-c", str(a.limit), "-T", "fields"] + [x for fl in FIELDS for x in ("-e", fl)]
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 22)
        for line in pr.stdout:
            v = line.rstrip("\n").split("\t")
            if len(v) < 6:
                v += [""] * (6 - len(v))
            seg = seg24(v[0].split(",")[0]); pkts[seg] += 1
            if v[1] and v[2].strip().lower() in ("false", "0", ""):
                for nm in v[1].split(","):
                    n2 = ascii_name(nm)
                    if n2:
                        dns[seg][n2] += 1; names_total[seg] += 1
            if v[3] and "1" in v[4].split(","):
                for nm in v[3].split(","):
                    n2 = ascii_name(nm)
                    if n2:
                        sni[seg][n2] += 1
            if v[5]:
                u = v[5][:80]
                ua[seg][u] += 1
                ua_cls[seg]["client" if UA_CLIENT.search(u) else "server" if UA_SERVER.search(u) else "other"] += 1
        pr.stdout.close(); pr.wait()

    rows = []
    for seg in pkts:
        n = names_total[seg]
        tot_ua = sum(ua_cls[seg].values())
        cl = 100 * ua_cls[seg].get("client", 0) / tot_ua if tot_ua >= 20 else None
        sv = 100 * ua_cls[seg].get("server", 0) / tot_ua if tot_ua >= 20 else None
        rows.append((seg, pkts[seg], n, cl, sv, tot_ua))
    rows.sort(key=lambda r: (-(r[2] + (r[5] or 0)), r[0]))
    print("%-17s %9s %8s %10s %10s %8s" % ("源 /24", "抽样包", "DNS名次", "UA终端%", "UA服务端%", "UA样本"))
    for seg, pk, n, cl, sv, tu in rows[:24]:
        if n == 0 and (tu or 0) < 20:
            continue
        print("%-17s %9d %8d %10s %10s %8d" % (
            seg, pk, n, "-" if cl is None else "%.0f" % cl,
            "-" if sv is None else "%.0f" % sv, tu or 0))
        for label, c in (("DNS", dns[seg]), ("SNI", sni[seg]), ("UA", ua[seg])):
            top = c.most_common(3)
            if top:
                print("      %-4s %s" % (label, "; ".join("%s(%d)" % (k[:42], v) for k, v in top)))


if __name__ == "__main__":
    main()
