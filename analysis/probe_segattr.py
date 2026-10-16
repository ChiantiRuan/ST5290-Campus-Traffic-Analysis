#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 抽样属性化探针：把 DNS 查询名 / TLS SNI / HTTP UA 归属到**源网段**，
用来回答一个口径问题：10.168.x 到底是"业务服务器"还是"办公/终端"？

方法：每个抓包只读前 N 包（默认 50 万），统计每个源网段（10.100 / 10.168 / 172.2 /
10.101 / 10.254 / 其它私网 / 公网）问过哪些域名、用哪些 User-Agent。
并给出"终端特征 vs 服务端特征"的粗分类计数。

限制（写进报告）：抽样窗口是每段的开头若干秒，非随机抽样；DNS/SNI/UA 只能看到
"问过名字 / 亮明身份"的连接；UA 分类是关键词法，非精确识别。

用法:
  python probe_segattr.py cap_*.pcap --limit 500000 --out ../双周4_报告/seg_attr
"""
import argparse, csv, glob, json, os, re, subprocess, sys
from collections import Counter, defaultdict

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
FIELDS = ["ip.src", "ip.dst", "dns.qry.name", "dns.flags.response",
          "tls.handshake.extensions_server_name", "tls.handshake.type",
          "http.host", "http.user_agent", "dns.qry.type", "dns.flags.rcode"]

# 网段标签（按 /16 归并；172.2 单列）
SEGS = [("10.100.", "10.100/16"), ("10.168.", "10.168/16"), ("10.101.", "10.101/16"),
        ("10.254.", "10.254/16"), ("172.2.", "172.2/16"), ("10.", "10/8 其它"),
        ("192.168.", "192.168/16"), ("127.", "loopback")]
UA_CLIENT = re.compile(r"MicroMessenger|Mozilla|Windows NT|360|AppleWebKit|Chrome|Safari|Edg|Firefox|Gecko|QQBrowser|DingTalk|WeCom", re.I)
UA_SERVER = re.compile(r"Go-http-client|curl|python|okhttp|Java|Apache|nginx|libwww|Wget|PostmanRuntime|node-fetch|axios", re.I)
DOM_OFFICE = re.compile(r"dingtalk|ding\.zj|weixin|wps|feishu|lark|office|sharepoint|jtoa|oa\.", re.I)
DOM_TELEMETRY = re.compile(r"telemetry|events\.data\.microsoft|optimizationguide|galileo|adash|track|analytics|beacon|umeng|growing", re.I)


def seg_of(ip):
    for pre, lab in SEGS:
        if ip.startswith(pre):
            return lab
    if not ip:
        return "unknown"
    return "public" if not (ip.startswith("10.") or ip.startswith("192.168.")
                            or ip.startswith("172.") or ip.startswith("127.")) else "private-other"


def local_name(n):
    return n.endswith(".local") or n in ("wpad", "wpad.local") or "-" in n and "." not in n


def run(path, limit):
    cmd = [TSHARK, "-r", path, "-c", str(limit), "-T", "fields"] + \
          [x for f in FIELDS for x in ("-e", f)]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 22)
    dns = defaultdict(Counter)      # seg -> name
    sni = defaultdict(Counter)
    ua = defaultdict(Counter)
    host = defaultdict(Counter)
    ua_cls = defaultdict(Counter)
    dns_cls = defaultdict(Counter)
    pkts = Counter(); qtype = defaultdict(Counter); rcode = defaultdict(Counter)
    n = len(FIELDS)
    for line in p.stdout:
        v = line.rstrip("\n").split("\t")
        if len(v) < n:
            v += [""] * (n - len(v))
        src = v[0].split(",")[0]; seg = seg_of(src)
        pkts[seg] += 1
        if v[2] and v[3].strip().lower() in ("false", "0", ""):   # DNS 查询（response 位为 False）
            for nm in v[2].split(","):
                nm = nm.strip().rstrip(".").lower()
                if nm and nm not in ("-", "(null)"):
                    dns[seg][nm] += 1
                    dns_cls[seg]["local-discover" if local_name(nm) else
                                 "office-collab" if DOM_OFFICE.search(nm) else
                                 "telemetry-track" if DOM_TELEMETRY.search(nm) else "other"] += 1
        if v[4] and "1" in v[5].split(","):
            for nm in v[4].split(","):
                nm = nm.strip().rstrip(".").lower()
                if nm and nm not in ("-", "(null)"):
                    sni[seg][nm] += 1
        if v[8] and v[3].strip().lower() in ("false", "0", ""):    # qtype：仅查询侧
            for t_ in v[8].split(","):
                if t_:
                    qtype[seg][t_] += 1
        if v[9] and v[3].strip().lower() == "true":                 # rcode：仅响应侧
            for t_ in v[9].split(","):
                if t_:
                    rcode[seg][t_] += 1
        if v[6]:
            for nm in v[6].split(","):
                host[seg][nm.strip().lower()] += 1
        if v[7]:
            ua[seg][v[7][:100]] += 1
            ua_cls[seg]["client-like" if UA_CLIENT.search(v[7]) else
                      "server-like" if UA_SERVER.search(v[7]) else "other"] += 1
    p.stdout.close(); p.wait()
    return dict(dns=dns, sni=sni, ua=ua, host=host, ua_cls=ua_cls, dns_cls=dns_cls,
                pkts=pkts, qtype=qtype, rcode=rcode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--limit", type=int, default=500000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = []
    for pat in a.pcaps:
        files += sorted(glob.glob(pat)) or [pat]

    agg = {k: defaultdict(Counter) for k in ("dns", "sni", "ua", "host", "ua_cls", "dns_cls", "qtype", "rcode")}
    pkts = Counter()
    for f in files:
        sys.stderr.write("[segattr] %s (first %d pkts)\n" % (os.path.basename(f), a.limit)); sys.stderr.flush()
        r = run(f, a.limit)
        pkts.update(r["pkts"])
        for k in agg:
            for seg, c in r[k].items():
                agg[k][seg].update(c)

    with open(os.path.join(a.out, "segattr_domains.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["seg", "kind", "name", "count"])
        for seg in agg["dns"]:
            for nm, c in agg["dns"][seg].most_common(25):
                w.writerow([seg, "dns", nm, c])
        for seg in agg["sni"]:
            for nm, c in agg["sni"][seg].most_common(25):
                w.writerow([seg, "tls_sni", nm, c])
    with open(os.path.join(a.out, "segattr_ua.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["seg", "user_agent", "count"])
        for seg in agg["ua"]:
            for nm, c in agg["ua"][seg].most_common(15):
                w.writerow([seg, nm, c])

    summary = {"limit_per_file": a.limit, "files": [os.path.basename(x) for x in files],
               "packets_sampled": dict(pkts),
               "dns_name_class": {s: dict(agg["dns_cls"][s]) for s in agg["dns_cls"]},
               "ua_class": {s: dict(agg["ua_cls"][s]) for s in agg["ua_cls"]},
               "top_dns": {s: agg["dns"][s].most_common(20) for s in agg["dns"]},
               "top_sni": {s: agg["sni"][s].most_common(20) for s in agg["sni"]},
               "top_ua": {s: agg["ua"][s].most_common(10) for s in agg["ua"]},
               "top_host": {s: agg["host"][s].most_common(10) for s in agg["host"]},
               "qtype_query_side": {s: dict(agg["qtype"][s]) for s in agg["qtype"]},
               "rcode_response_side": {s: dict(agg["rcode"][s]) for s in agg["rcode"]}}
    with open(os.path.join(a.out, "segattr_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1, default=str)

    # 控制台摘要：UA 分类占比 + 各段 Top3 域名
    print("== 抽样包数（按源网段）==")
    for s, c in pkts.most_common():
        print("   %-13s %9d" % (s, c))
    print("\n== UA 粗分类占比 ==")
    for s, c in agg["ua_cls"].items():
        t = sum(c.values())
        if t < 20:
            continue
        print("   %-13s 终端特征 %5.1f%% | 服务端特征 %5.1f%% | 其它 %5.1f%%  (n=%d)"
              % (s, 100 * c.get("client-like", 0) / t, 100 * c.get("server-like", 0) / t,
                 100 * c.get("other", 0) / t, t))
    print("\n== DNS 名称性质占比 ==")
    for s, c in agg["dns_cls"].items():
        t = sum(c.values())
        if t < 20:
            continue
        print("   %-13s 内网发现 %5.1f%% | 办公协同 %5.1f%% | 遥测埋点 %5.1f%% | 其它 %5.1f%%  (n=%d)"
              % (s, 100 * c.get("local-discover", 0) / t, 100 * c.get("office-collab", 0) / t,
                 100 * c.get("telemetry-track", 0) / t, 100 * c.get("other", 0) / t, t))
    print("\n== 各段 DNS 查询名 Top5 ==")
    for s in agg["dns"]:
        print("   ", s, [n for n, _ in agg["dns"][s].most_common(5)])


if __name__ == "__main__":
    main()
