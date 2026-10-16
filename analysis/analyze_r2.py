#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 R2 分析 —— 流量基线画像 + 时间序列基线（自适应时间窗）
数据源: ClickHouse 表 traffic（真实采集）或 packets（旧测试集，仅验证流程）
产出: charts/*.png + metrics_r2.json
用法: ~/miniconda3/envs/dsaproject/bin/python analyze_r2.py      # 默认 traffic
      TBL=packets ~/miniconda3/envs/dsaproject/bin/python analyze_r2.py
"""
import io, json, os
import numpy as np
import pandas as pd
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

CH = "http://192.168.0.113:8123/"
TBL = os.environ.get("TBL", "traffic")
# 脚本位于 脚本/ 下 → 项目根目录 = 上一级；分析产出默认落到 双周2_报告/（可用 OUT_DIR 覆盖）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get("OUT_DIR", os.path.join(ROOT, "双周2_报告"))
CHARTS = os.path.join(OUT, "charts")
os.makedirs(CHARTS, exist_ok=True)
GAP_SEC, TOP_N = 300, 15


def ch(query, _tries=3):
    import time
    q = query if "FORMAT" in query.upper() else query.rstrip().rstrip(";") + " FORMAT TSVWithNames"
    last = None
    for i in range(_tries):
        try:
            r = requests.post(CH, data=q, timeout=600)
            r.raise_for_status()
            return pd.DataFrame() if not r.text.strip() else pd.read_csv(io.StringIO(r.text), sep="\t")
        except Exception as e:
            last = e
            print(f"   [retry {i+1}/{_tries}] {type(e).__name__}")
            time.sleep(3)
    raise last


def q(s, ps=(0.5, 0.9, 0.99)):
    return {f"p{int(p*100)}": float(np.quantile(s, p)) for p in ps}


M = {}

# ---------- 0. 概况 ----------
try:
    ov = ch(f"""SELECT count() AS rows, uniqExact(src_ip) AS src_ips, uniqExact(dst_ip) AS dst_ips,
        uniqExact(proto) AS protos, min(ts) AS t_min, max(ts) AS t_max, sum(pkt_len) AS bytes
        FROM {TBL}""").iloc[0]
except requests.exceptions.HTTPError as e:
    code = e.response.status_code if e.response is not None else "?"
    raise SystemExit(f"读取表 {TBL} 失败（HTTP {code}）—— 表不存在或不可读；先运行 ingest_pcap.py 入库，"
                     f"或用 TBL=<表名> 指定") from None
if int(ov["rows"]) == 0:
    raise SystemExit(f"表 {TBL} 没有数据（count=0）—— 先抓包并运行 ingest_pcap.py 入库")
span_h = (pd.Timestamp(ov["t_max"]) - pd.Timestamp(ov["t_min"])).total_seconds() / 3600
M["overview"] = {"rows": int(ov["rows"]), "src_ips": int(ov["src_ips"]), "dst_ips": int(ov["dst_ips"]),
                 "protos": int(ov["protos"]), "t_min": str(ov["t_min"]), "t_max": str(ov["t_max"]),
                 "bytes": int(ov["bytes"]), "span_hours": round(span_h, 2)}
print(f"概况: {M['overview']['rows']} 包 / {M['overview']['src_ips']} 源主机 / 跨度 {span_h:.1f} 小时")

# ---------- 1. 明细 + 会话切分 ----------
df = ch(f"""SELECT toUnixTimestamp(ts) AS ts, toString(src_ip) AS src_ip, toString(dst_ip) AS dst_ip,
    proto, src_port, dst_port, pkt_len FROM {TBL}""")
df["ts"] = df["ts"].astype("int64")
print("明细行数:", len(df))
df = df.sort_values(["src_ip", "dst_ip", "proto", "src_port", "dst_port", "ts"], kind="mergesort")
g = df.groupby(["src_ip", "dst_ip", "proto", "src_port", "dst_port"], sort=False)
df["gap"] = g["ts"].diff()
df["new_sess"] = (df["gap"].isna() | (df["gap"] > GAP_SEC)).astype(int)
df["flow_key"] = (df.src_ip + "|" + df.dst_ip + "|" + df.proto.astype(str) + "|" +
                  df.src_port.astype(str) + "|" + df.dst_port.astype(str))
df["sess_id"] = df.groupby("flow_key", sort=False)["new_sess"].cumsum()

sess = df.groupby(["flow_key", "sess_id"], sort=False).agg(
    ts0=("ts", "min"), ts1=("ts", "max"), pkts=("ts", "size"), bytes=("pkt_len", "sum")).reset_index()
sess["dur"] = sess["ts1"] - sess["ts0"]

# ---------- 2. 分布画像 ----------
M["packet_size"] = {"mean": float(df.pkt_len.mean()), **q(df.pkt_len), "max": int(df.pkt_len.max())}
M["flow"] = {"count": int(len(sess)), "pkts_per_flow": q(sess.pkts),
             "bytes_per_flow": q(sess.bytes), "dur_sec": q(sess.dur)}
M["pkt_share"] = {"small_le128": float((df.pkt_len <= 128).mean()),
                  "full_mtu_ge1400": float((df.pkt_len >= 1400).mean())}

host = df.groupby("src_ip").agg(pkts=("pkt_len", "size"), bytes=("pkt_len", "sum"),
                                peers=("dst_ip", "nunique"), ports=("dst_port", "nunique")).reset_index()
host = host.sort_values("bytes", ascending=False)
M["host"] = {"n": int(len(host)), "top1_share": float(host.bytes.iloc[0] / host.bytes.sum()),
             "top10_share": float(host.bytes.head(10).sum() / host.bytes.sum()),
             "top10": host.head(10)[["src_ip", "bytes", "pkts", "peers"]].to_dict("records")}

fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(df.pkt_len, bins=60, color="#1F3864")
for p, c, t in [(0.5, "#C55A11", "p50"), (0.9, "#375623", "p90"), (0.99, "#7030A0", "p99")]:
    v = np.quantile(df.pkt_len, p)
    ax.axvline(v, color=c, ls="--", lw=1.2, label=f"{t} = {v:.0f} B")
ax.set_xlabel("packet size (bytes)"); ax.set_ylabel("packet count")
ax.set_title("Packet size distribution", fontsize=11, color="#1F3864")
ax.legend(fontsize=8); fig.tight_layout()
fig.savefig(f"{CHARTS}/fig1_pktlen_dist.png", dpi=150); plt.close(fig)

fig, ax = plt.subplots(figsize=(7, 4))
h = host.head(TOP_N)
ax.bar(range(len(h)), h.bytes / 1e6, color="#1F3864")
ax.set_xticks(range(len(h)))
ax.set_xticklabels([x.split(".")[-2] + "." + x.split(".")[-1] for x in h.src_ip], rotation=60, fontsize=7)
ax2 = ax.twinx()
ax2.plot(range(len(host)), np.cumsum(host.bytes) / host.bytes.sum() * 100, color="#C55A11", lw=1.5)
ax2.set_ylabel("cumulative share (%)", color="#C55A11"); ax2.set_ylim(0, 105)
ax.set_xlim(-0.6, min(len(host), 60) - 0.4); ax.set_ylabel("MB")
ax.set_title(f"Top hosts by traffic (top {TOP_N} bars, cumulative curve over all hosts)", fontsize=11, color="#1F3864")
fig.tight_layout(); fig.savefig(f"{CHARTS}/fig2_host_pareto.png", dpi=150); plt.close(fig)

proto = ch(f"SELECT proto, count() AS pkts, sum(pkt_len) AS bytes FROM {TBL} GROUP BY proto ORDER BY bytes DESC")
ports = ch(f"SELECT dst_port, count() AS pkts FROM {TBL} GROUP BY dst_port ORDER BY pkts DESC LIMIT 12")
SVC = {80: "http", 443: "https", 53: "dns", 22: "ssh", 3389: "rdp", 8080: "http-alt", 123: "ntp",
       5353: "mdns", 3306: "mysql", 1900: "ssdp", 5228: "gcm", 853: "dot", 547: "dhcpv6"}
fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
axes[0].bar(proto.proto.astype(str), proto.bytes / 1e6, color="#1F3864")
axes[0].set_title("Traffic by protocol (MB)", fontsize=10, color="#1F3864"); axes[0].set_ylabel("MB")
lab = [f"{int(p)} {SVC.get(int(p),'')}".strip() for p in ports.dst_port]
axes[1].barh(lab[::-1], ports.pkts[::-1], color="#375623")
axes[1].set_title("Top destination ports (packets)", fontsize=10, color="#1F3864")
fig.tight_layout(); fig.savefig(f"{CHARTS}/fig3_proto_ports.png", dpi=150); plt.close(fig)
M["proto"] = proto.to_dict("records"); M["top_ports"] = ports.to_dict("records")

# ---------- 3. 时间序列（自适应桶宽）----------
bucket = "minute" if span_h < 24 else "hour"
fn = "toStartOfMinute" if bucket == "minute" else "toStartOfHour"
freq = "min" if bucket == "minute" else "h"
period = 60 if bucket == "minute" else 24          # 一个"小时周期"或"一天周期"
ts = ch(f"""SELECT {fn}(ts) AS t, count() AS pkts, sum(pkt_len) AS bytes, uniqExact(src_ip) AS hosts
    FROM {TBL} GROUP BY t ORDER BY t""")
ts["t"] = pd.to_datetime(ts["t"])
ts = ts.set_index("t").astype(float)
full = pd.date_range(ts.index.min(), ts.index.max(), freq=freq)
ts = ts.reindex(full, fill_value=0.0)
M["series"] = {"bucket": bucket, "n_points": int(len(ts)), "period": period,
               "bytes_total_MB": float(ts.bytes.sum() / 1e6),
               "bytes_per_bucket_MB": {"mean": float(ts.bytes.mean() / 1e6),
                                       "min": float(ts.bytes.min() / 1e6),
                                       "max": float(ts.bytes.max() / 1e6)},
               "hosts_per_bucket": {"mean": float(ts.hosts.mean()), "max": float(ts.hosts.max())}}

# 峰谷（按钟点聚合）
hod = ts.groupby(ts.index.hour).bytes.mean() / 1e6
peak_h, trough_h = int(hod.idxmax()), int(hod.idxmin())
M["diurnal"] = {"peak_hour": peak_h, "peak_MB_avg": float(hod.max()),
                "trough_hour": trough_h, "trough_MB_avg": float(hod.min()),
                "peak_trough_ratio": float(hod.max() / hod.min()) if hod.min() > 0 else None,
                "hours_covered": sorted(int(x) for x in hod.index)}

fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(ts.index, ts.bytes / 1e6, color="#1F3864", lw=.9)
ax.set_xlabel("time"); ax.set_ylabel("MB per " + bucket, color="#1F3864")
ax2 = ax.twinx(); ax2.plot(ts.index, ts.hosts, color="#C55A11", lw=.8, alpha=.8)
ax2.set_ylabel("active hosts", color="#C55A11")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.set_title(f"Traffic time series ({bucket} buckets, {len(ts)} points)", fontsize=11, color="#1F3864")
fig.tight_layout(); fig.savefig(f"{CHARTS}/fig4_timeseries.png", dpi=150); plt.close(fig)

# ---------- 4. 分解与正常波动带 ----------
series = ts.bytes.values.astype(float)
trend = seasonal = resid = None
used = None
if len(series) >= 2 * period:
    try:
        from statsmodels.tsa.seasonal import STL
        res = STL(pd.Series(series), period=period, robust=True).fit()
        trend, seasonal, resid = res.trend.values, res.seasonal.values, res.resid.values
        used = f"STL (statsmodels, period={period} {bucket}s)"
    except Exception as e:
        print("   STL 失败，改用经典分解:", type(e).__name__, e)
if trend is None:
    s = pd.Series(series)
    w = max(3, period // 2)
    trend = s.rolling(w, center=True, min_periods=1).mean().values
    detr = series - trend
    tmp = pd.DataFrame({"ph": np.arange(len(series)) % period, "detr": detr})
    seasonal = tmp.groupby("ph").detr.transform("mean").values - tmp.detr.mean()
    resid = series - trend - seasonal
    used = f"classical decomposition (MA trend + {period}-{bucket} seasonal)"
sd = float(np.std(resid))
lo_q, hi_q = float(np.quantile(resid, 0.05)), float(np.quantile(resid, 0.95))
band_lo, band_hi = trend + seasonal + lo_q, trend + seasonal + hi_q
# ±3σ 参考值（数据重尾时下界可能为负 → 仅作记录，不用于作图）
sig3_lo, sig3_hi = trend + seasonal - 3 * sd, trend + seasonal + 3 * sd
outliers = [str(ts.index[i].strftime("%H:%M")) for i in range(len(series))
            if series[i] < band_lo[i] or series[i] > band_hi[i]]
M["baseline"] = {"method": used, "resid_sd_MB": sd / 1e6,
                 "band_rule": "baseline + 5th/95th pct of residual (robust to heavy tails)",
                 "band_lo_MB_mean": float(np.mean(band_lo) / 1e6),
                 "band_hi_MB_mean": float(np.mean(band_hi) / 1e6),
                 "sigma3_band_lo_MB_mean": float(np.mean(sig3_lo) / 1e6),
                 "sigma3_band_hi_MB_mean": float(np.mean(sig3_hi) / 1e6),
                 "sigma3_usable": bool(np.mean(sig3_lo) > 0),
                 "outlier_buckets": len(outliers), "outlier_times_sample": outliers[:10]}

fig, axes = plt.subplots(4, 1, figsize=(8, 6.6), sharex=True)
lbl = {"observed": ("MB", 1e6), "trend": ("MB", 1e6), "seasonal": ("MB", 1e6), "residual": ("MB", 1e6)}
data = [("observed", series), ("trend", trend), ("seasonal", seasonal), ("residual", resid)]
for ax, (name, vals) in zip(axes, data):
    ax.plot(ts.index, vals / 1e6 if name != "residual" else vals, color="#1F3864", lw=1.1)
    ax.set_ylabel(f"{name} (MB)" if name != "residual" else "residual", fontsize=8); ax.grid(alpha=.25)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
axes[0].set_title(f"Time-series decomposition — {used}", fontsize=10, color="#1F3864")
fig.tight_layout(); fig.savefig(f"{CHARTS}/fig5_decomposition.png", dpi=150); plt.close(fig)

fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(ts.index, series / 1e6, color="#1F3864", lw=1.0, label="observed")
ax.plot(ts.index, (trend + seasonal) / 1e6, color="#C55A11", lw=1.2, ls="--", label="baseline (trend+seasonal)")
ax.fill_between(ts.index, band_lo / 1e6, band_hi / 1e6, color="#C55A11", alpha=.15,
                label="normal band (5th-95th pct of residual)")
ax.set_xlabel("time"); ax.set_ylabel("MB per " + bucket)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M")); ax.legend(fontsize=8)
ax.set_title("Normal-traffic baseline and fluctuation band", fontsize=11, color="#1F3864")
fig.tight_layout(); fig.savefig(f"{CHARTS}/fig6_baseline_band.png", dpi=150); plt.close(fig)

json.dump(M, open(os.path.join(OUT, "metrics_r2.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)

print("\n=== 关键结果 ===")
print("包长 p50/p90/p99:", M["packet_size"]["p50"], M["packet_size"]["p90"], M["packet_size"]["p99"],
      "| 满MTU占比:", round(M["pkt_share"]["full_mtu_ge1400"], 3), "| 小包占比:", round(M["pkt_share"]["small_le128"], 3))
print("会话数:", M["flow"]["count"], "| 会话时长 p50/p90(s):", M["flow"]["dur_sec"]["p50"], M["flow"]["dur_sec"]["p90"])
print("主机 Top1/Top10 占比:", round(M["host"]["top1_share"], 3), round(M["host"]["top10_share"], 3))
print("峰谷:", M["diurnal"])
print("分解方法:", used, "| 残差σ(MB):", round(sd / 1e6, 3), "| 超带桶数:", M["baseline"]["outlier_buckets"])
print("图 ->", CHARTS)
