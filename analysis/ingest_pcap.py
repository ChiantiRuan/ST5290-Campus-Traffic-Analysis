#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap -> ClickHouse 入库（真实数据表 traffic，按 obs_date 分区）
用法:
  ~/miniconda3/envs/dsaproject/bin/python ingest_pcap.py             # 默认读 抓包数据/ 下所有 cap_*.pcap
  ~/miniconda3/envs/dsaproject/bin/python ingest_pcap.py 文件1.pcap   # 指定文件
  ~/miniconda3/envs/dsaproject/bin/python ingest_pcap.py --selftest   # 自测：只用临时表，不碰生产表
"""
import glob, io, os, shutil, subprocess, sys
from urllib.parse import quote
import pandas as pd
import requests

CH, TABLE = "http://192.168.0.113:8123/", "traffic"
# 脚本位于 脚本/ 下 → 项目根 = 上一级；默认从 抓包数据/ 读取 pcap（可用 PCAP_DIR 覆盖）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR = os.environ.get("PCAP_DIR", os.path.join(ROOT, "抓包数据"))
# tshark 不在 PATH（Wireshark.app 内），必须用绝对路径；可用环境变量 TSHARK 覆盖
TSHARK = os.environ.get("TSHARK") or next(
    (p for p in ("/Applications/Wireshark.app/Contents/MacOS/tshark", "/opt/homebrew/bin/tshark",
                 "/usr/local/bin/tshark") if os.path.exists(p)),
    shutil.which("tshark") or "tshark")

FIELDS = ["frame.time_epoch", "ip.proto", "ip.src", "ip.dst",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len"]
COLS = ["ts", "src_ip", "dst_ip", "proto", "src_port", "dst_port", "pkt_len"]
PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP", "47": "GRE", "58": "ICMPv6", "89": "OSPF"}


def ddl(table):
    return f"""CREATE TABLE IF NOT EXISTS {table} (
  ts DateTime64(9), obs_date Date, src_ip IPv4, dst_ip IPv4,
  proto LowCardinality(String), src_port UInt16, dst_port UInt16, pkt_len UInt32
) ENGINE = MergeTree PARTITION BY obs_date ORDER BY (obs_date, ts)"""


def post(query, timeout=600):
    r = requests.post(CH, data=query, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"CH {r.status_code}: {r.text[:300]}")
    return r.text


def normalize(raw):
    """tshark 原始字段(9列) -> 规范 7 列；TCP/UDP 端口合并、协议号转名、帧长转 pkt_len"""
    df = raw.fillna("")
    for c in ("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"):
        df[c] = pd.to_numeric(df[c].replace("", "0"), errors="coerce").fillna(0).astype("uint32")
    df["src_port"] = df["tcp.srcport"].where(df["tcp.srcport"] > 0, df["udp.srcport"]).clip(0, 65535)
    df["dst_port"] = df["tcp.dstport"].where(df["tcp.dstport"] > 0, df["udp.dstport"]).clip(0, 65535)
    df["proto"] = df["ip.proto"].map(PROTO_MAP).fillna("IP-" + df["ip.proto"].astype(str))
    df["pkt_len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0).astype("uint32")
    df["ts"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df = df.dropna(subset=["ts"])
    df = df[(df["ip.src"] != "") & (df["ip.dst"] != "")]
    out = df[["ts", "ip.src", "ip.dst", "proto", "src_port", "dst_port", "pkt_len"]].copy()
    out.columns = COLS
    return out


def pcap_to_frame(pcap):
    expr = " ".join(f"-e {f}" for f in FIELDS)
    r = subprocess.run(f'"{TSHARK}" -r "{pcap}" -T fields -E separator=, -E occurrence=f {expr}',
                       shell=True, capture_output=True, text=True)
    if not r.stdout.strip():
        print("  无数据行 | tshark stderr:", r.stderr[:200])
        return None
    raw = pd.read_csv(io.StringIO(r.stdout), sep=",", header=None, names=FIELDS, dtype=str)
    return normalize(raw)


def insert_frame(df, table=TABLE):
    """走 HTTP 直连（不用 curl，避免依赖 PATH）"""
    buf = io.StringIO()
    df.to_csv(buf, index=False, header=False, float_format="%.9f")
    q = (f"INSERT INTO {table} SELECT toDateTime64(ts,9), toDate(toDateTime64(ts,9)), toIPv4(src_ip), "
         f"toIPv4(dst_ip), proto, src_port, dst_port, pkt_len FROM input('ts Float64, src_ip String, "
         f"dst_ip String, proto String, src_port UInt32, dst_port UInt32, pkt_len UInt32') FORMAT CSV")
    r = requests.post(f"{CH}?query={quote(q)}", data=buf.getvalue(), timeout=1200)
    if r.status_code != 200:
        raise RuntimeError(f"插入 {table} 失败 {r.status_code}: {r.text[:300]}")
    return len(df)


def summary(table):
    """安全摘要（不要用 groupArray —— 大表会刷屏）"""
    return post(f"SELECT count() AS rows, uniqExact(proto) AS protos, uniqExact(src_ip) AS hosts, "
                f"min(obs_date) AS d0, max(obs_date) AS d1 FROM {table} FORMAT TSVWithNames").strip()


def selftest():
    """自测：建独立临时表 → 插入 → 回读 → 删除。绝不触碰生产表 TABLE。"""
    tmp = TABLE + "_selftest"
    post(f"DROP TABLE IF EXISTS {tmp}")
    post(ddl(tmp))
    print("临时表就绪:", tmp, "(生产表", TABLE, "不受影响)")
    sample = ("1788612000.100,6,192.168.0.126,142.250.1.1,51234,443,,,1500\n"
              "1788612000.200,6,192.168.0.126,142.250.1.1,51234,443,,,1500\n"
              "1788612000.300,17,192.168.0.126,223.5.5.5,,,53000,53,80\n"
              "1788612000.400,1,192.168.0.126,8.8.8.8,,,,,96\n")
    raw = pd.DataFrame([l.split(",") for l in sample.strip().split("\n")], columns=FIELDS)
    df = normalize(raw)
    print(df.to_string(index=False))
    insert_frame(df, tmp)
    print("回读:", summary(tmp).replace("\t", " | "))
    post(f"DROP TABLE IF EXISTS {tmp}")
    print("临时表已删除；生产表行数（应保持不变）:", post(f"SELECT count() FROM {TABLE}").strip())


def ensure_table():
    post(ddl(TABLE))
    print("表就绪:", TABLE)


def main():
    if "--selftest" in sys.argv:
        return selftest()
    files = [a for a in sys.argv[1:] if not a.startswith("--")] or sorted(glob.glob(os.path.join(PCAP_DIR, "cap_*.pcap")))
    if not files:
        print("没有 pcap 文件（默认目录:", PCAP_DIR, "）")
        return
    ensure_table()
    total = 0
    for p in files:
        if not os.path.exists(p):
            print("跳过:", p)
            continue
        print(f"解析 {p} ({os.path.getsize(p)/1e6:.1f} MB)")
        df = pcap_to_frame(p)
        if df is None or df.empty:
            print("  空，跳过")
            continue
        print(f"  {len(df)} 包 | hosts={df.src_ip.nunique()} | ts {df.ts.min():.0f}–{df.ts.max():.0f}")
        total += insert_frame(df)
        print("  ✅ 已导入")
    print(f"\n合计导入 {total} 行")
    print(summary(TABLE).replace("\t", " | "))


if __name__ == "__main__":
    main()
