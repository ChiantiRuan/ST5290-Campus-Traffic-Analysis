#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 出图第四批（F10–F18）
  F10 秒级序列 + 滑动均值        F11 周期图与打乱基线
  F12 残差波动带                 F13 分析管线示意
  F14 聚类散点（k=4 vs 规则分群） F15 按采集文件的一致性
  F16 外部 /24 集中度            F17 固定端口组等量对照
  F18 变点与极值（POT）
图内纯 ASCII（CJK 会渲染成方框），口径同前。
"""
from pathlib import Path
REPO = str(Path(__file__).resolve().parents[1]) + "/"  # 导出后为仓库根目录；脚本位于仓库下一级
import json
import os

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.ticker import PercentFormatter

P = REPO
P3, CAL, DET, DP2 = (P + "data/probe/", P + "data/probe_caliber/",
                     P + "data/detect/", P + "data/deep2/")
OUT = P + "figures/output/"
os.makedirs(OUT, exist_ok=True)
import chart_style
from chart_style import NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED, SRC, finish
chart_style.set_out(OUT)
chart_style.use_style()
ps = pd.read_csv(P3 + "per_second_all.csv").sort_values("unix_sec")
ps["t"] = ps["unix_sec"] - ps["unix_sec"].min()
gaps = np.where(np.diff(ps["t"].to_numpy()) > 60)[0]
blk1 = ps.iloc[: gaps[0] + 1] if len(gaps) else ps
blk2 = ps.iloc[gaps[0] + 1:] if len(gaps) else ps.iloc[0:0]
blocks = [("block 1 (192 s)", blk1), ("block 2 (840 s)", blk2)]


# ---------- F10 秒级序列 ----------
def fig_series():
    fig, ax = plt.subplots(figsize=(8.0, 3.0))
    off = 0
    for name, b in blocks:
        x = np.arange(len(b)) + off
        ax.plot(x, b["packets"] / 1000, lw=0.7, color=NAVY, alpha=0.55)
        ax.plot(x, (b["packets"].rolling(30, min_periods=5, center=True).mean()) / 1000,
                lw=1.8, color=ORANGE, label="30 s rolling mean")
        ax.axvspan(off - 3, off + len(b) + 3, color="#F7F7F7", zorder=0)
        ax.text(off + len(b) / 2, b["packets"].max() / 1000 * 1.02, name, ha="center", fontsize=9.8, color=GREY)
        off += len(b) + 6
    ax.set_xlabel("Seconds since capture start (blocks laid side by side; gap omitted)")
    ax.set_ylabel("Packets per second (thousands)")
    ax.set_title("Second-level load: a flat level with a mild rhythm, no collapse",
                 loc="left", fontweight="bold")
    ax.legend(fontsize=9.8, frameon=False, loc="lower right")
    cvs = ", ".join(f"{n.split(' ')[0]} CV={b['packets'].std()/b['packets'].mean():.3f}" for n, b in blocks)
    finish(fig, "fig10_series_level", f"Coefficient of variation: {cvs}. No scaling event in either block.")


# ---------- F11 周期图 ----------
def fig_periodogram():
    rng = np.random.default_rng(5)
    fig, axes = plt.subplots(1, 2, figsize=(9.0, 3.2))
    peaks = []
    for ax, (name, b) in zip(axes, blocks):
        x = b["packets"].to_numpy(float)
        n = len(x)
        y = x - x.mean()
        pw = np.abs(np.fft.rfft(y))[1:] ** 2          # 去掉 DC 分量
        periods = n / np.arange(1, len(pw) + 1)
        ok = periods <= n / 3                          # 排除周期 > n/3 的最低频（趋势会被误当周期）
        null = np.array([np.max(np.abs(np.fft.rfft(y[rng.permutation(n)]))[1:] ** 2 * ok)
                         for _ in range(150)])
        base = float(np.percentile(null, 95))
        ax.plot(periods[ok], pw[ok], lw=1.0, color=NAVY)
        ax.axhline(base, ls="--", lw=1.0, color=RED)
        k = int(np.argmax(np.where(ok, pw, -1)))
        ax.axvline(periods[k], ls=":", lw=1.0, color=ORANGE)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("Period (seconds, log scale)"); ax.set_ylabel("Spectral power (log scale)")
        ax.set_title(name, loc="left", fontweight="bold", fontsize=12.3, x=0.04)   # 避开 y 轴标题
        # 绘图区里没有安全空白（数据铺满两侧）：峰值用小圆点 + 脚注数字标出，虚线保留
        ax.plot([periods[k]], [pw[k]], marker="o", ms=4.5, color=ORANGE, zorder=5)
        peaks.append(f"{name.split(' (')[0]} {periods[k]:.1f} s ({pw[k]/base:.0f}x the 95% shuffle level)")
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("Periodogram: a real 20-43 s rhythm in both blocks", x=0.005, y=0.97, ha="left",
                 fontweight="bold", fontsize=15.0)
    finish(fig, "fig11_periodogram",
           "Peak (orange dot): " + "; ".join(peaks) + ". "
           "Periods above one third of the block are excluded (otherwise a slow trend looks like a cycle). "
           "The dashed red line is the 95th percentile of 150 shuffled copies of the same block.")


# ---------- F12 波动带 ----------
def fig_band():
    name, b = blocks[1]
    x = b["packets"].to_numpy(float)
    trend = pd.Series(x).rolling(31, min_periods=8, center=True).mean().to_numpy()
    resid = x - trend
    q = {p: np.nanpercentile(resid, p) for p in (5, 25, 50, 75, 95)}
    fig, ax = plt.subplots(figsize=(8.0, 3.2))
    t = np.arange(len(x))
    ax.fill_between(t, trend + q[5], trend + q[95], color="#D6E0EA", label="5-95% of residual")
    ax.fill_between(t, trend + q[25], trend + q[75], color="#9DB8CE", label="25-75%")
    ax.plot(t, trend, lw=1.6, color=NAVY, label="31 s rolling mean")
    ax.set_xlabel("Seconds into block 2"); ax.set_ylabel("Packets per second (thousands)")
    ax.yaxis.set_major_formatter(lambda v, _: f"{v/1000:.0f}")
    ax.set_title("Residual band around the local level: the spread is small and stable",
                 loc="left", fontweight="bold")
    # 图例原本压在波动带上：移到坐标区下方（脚注会自动跟到它下面）
    ax.legend(fontsize=9.8, frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.17))
    fig.subplots_adjust(bottom=0.30)
    finish(fig, "fig12_band",
           f"Residuals against a 31 s rolling mean: 5-95% band spans {q[5]/1000:.1f}k to {q[95]/1000:.1f}k pps, "
           f"i.e. about {100*(q[95]-q[5])/np.median(trend):.0f}% of the local level.")


# ---------- F13 管线示意 ----------
def fig_pipeline():
    # 框内文字原来比框宽（互相压住）：缩短到每行放得下
    steps = [("4 pcap files\n36.2 GB\n68.7 M packets", NAVY),
             ("Field extraction\n(tshark,\nper packet)", TEAL),
             ("Data convention\none-way bytes;\nloopback and non-IP\nsplit out", GREEN),
             ("Three views\n49,560 hosts\n693k sessions\n13,957 names", PURPLE),
             ("Four detections\nperiodicity, entropy,\nchange points,\nextremes", ORANGE),
             ("Findings and advice\ncapacity, monitoring,\nlimitation notes", RED)]
    fig, ax = plt.subplots(figsize=(9.6, 2.2))
    ax.axis("off")
    w, h, gap = 0.145, 0.52, 0.024
    for i, (txt, col) in enumerate(steps):
        x = i * (w + gap)
        ax.add_patch(FancyBboxPatch((x, 0.24), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                    fc="white", ec=col, lw=1.4))
        ax.text(x + w / 2, 0.24 + h / 2, txt, ha="center", va="center", fontsize=8.0, color=col)
        if i:
            ax.add_patch(FancyArrowPatch((x - gap, 0.5), (x - 0.004, 0.5), arrowstyle="-|>",
                                         mutation_scale=9, color=GREY, lw=1.0))
    ax.set_xlim(-0.01, len(steps) * (w + gap)); ax.set_ylim(0.1, 0.9)
    ax.set_title("Analysis pipeline: from raw captures to defensible statements",
                 loc="left", fontweight="bold")
    finish(fig, "fig13_pipeline", "Every arrow is a script kept in the project folder, re-runnable end to end.")


# ---------- F14 聚类 ----------
def fig_clusters():
    c = pd.read_csv(DET + "cluster_points.csv")
    s = json.load(open(DET + "detect_summary.json", encoding="utf-8"))["clustering"]
    cols = [NAVY, ORANGE, TEAL, PURPLE]
    marks = {"Serving": "o", "Bulk": "s", "Interactive": "^", "Low volume": "x"}
    zh = {"服务型": "Serving", "传输型": "Bulk", "交互型": "Interactive", "低频型": "Low volume"}
    c["rg"] = c["rule_group"].map(zh)
    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    for cl, d in c.groupby("cluster"):
        ax.scatter(d["total_bytes"].clip(lower=1), d["peers"].clip(lower=0.9), s=7, alpha=0.5,
                   color=cols[int(cl) % 4], label=f"cluster {cl} (n={len(d):,})", edgecolors="none")
    for rg, m in marks.items():
        ax.scatter([], [], marker=m, s=22, facecolors="none", edgecolors="#333333", label=f"rule: {rg}")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("One-way bytes per host (log scale)"); ax.set_ylabel("Distinct peers (log scale)")
    ax.set_title(f"K-means (k={s['k']}) vs the transparent rule: same layers, different cuts",
                 loc="left", fontweight="bold")
    ax.legend(fontsize=8.8, frameon=False, ncol=2, loc="upper left")
    finish(fig, "fig14_clusters",
           f"Adjusted Rand index {s['ari_vs_rule']:.2f}: the layers agree, but the interactive group is "
           "split across clusters. Silhouette favours k=4 (0.562) and k=5 (0.565); k=4 is reported as the "
           "simpler of the two.")


# ---------- F15 按文件一致性 ----------
def fig_consistency():
    rows = []
    for f in ("cap_20260920_111416", "cap_20260920_112321", "cap_20260920_112821", "cap_20260920_113321"):
        d = json.load(open(f"{CAL}{f}/caliber_summary.json", encoding="utf-8"))
        rows.append(dict(file=f[-6:], gini=d["gini"], top1=d["top1pct_share"],
                         ratio=d["direction_bytes"]["ext-int"] / d["direction_bytes"]["int-ext"]))
    r = pd.DataFrame(rows)
    fig, axes = plt.subplots(1, 3, figsize=(9.4, 2.9))
    for ax, col, title, fmt in ((axes[0], "gini", "Byte concentration (Gini)", "{:.3f}"),
                                (axes[1], "top1", "Top 1% hosts' byte share", "{:.1%}"),
                                (axes[2], "ratio", "Inbound / outbound bytes", "{:.2f}x")):
        ax.bar([f"file\n{x}" for x in r["file"]], r[col], color=NAVY, width=0.6)
        ax.set_title(title, loc="left", fontweight="bold", fontsize=12.3)
        ax.tick_params(axis="x", labelsize=6.8)
        for i, v in enumerate(r[col]):
            ax.text(i, v * 1.005, fmt.format(v), ha="center", fontsize=9.1)
        lo = min(r[col]) * (0.9 if col != "gini" else 0.995)
        ax.set_ylim(lo, max(r[col]) * 1.06)
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("The same structure in every capture file", x=0.005, y=0.97, ha="left",
                 fontweight="bold", fontsize=15.0)
    finish(fig, "fig15_file_consistency",
           "Per-file values (files 2-4 are contiguous chunks of one 840 s block). Concentration and the "
           "in/out imbalance are stable, which is why the structure findings do not depend on one window.")


# ---------- F16 外部 /24 集中度 ----------
def fig_client_blocks():
    h = pd.read_csv(CAL + "host_profile_v2_merged.csv")
    ext = h[h["class"] == "ext"].copy()
    ext["blk"] = ext["ip"].str.rsplit(".", n=1).str[0]
    agg = ext.groupby("blk")["total_bytes"].sum().sort_values(ascending=False)
    cum = agg.cumsum() / agg.sum()
    n = len(agg)
    t1, t10 = float(cum.iloc[max(int(0.01 * n) - 1, 0)]), float(cum.iloc[int(0.10 * n) - 1])
    assert abs(t1 - 0.850) < 0.02 and abs(t10 - 0.992) < 0.01, f"外部 /24 集中度与口径不符: {t1:.3f}/{t10:.3f}"
    assert abs(n - 26809) < 200, f"/24 数量与口径不符: {n}"
    fig, ax = plt.subplots(figsize=(7.2, 3.3))
    ax.plot(np.arange(1, n + 1), cum.to_numpy(), lw=1.7, color=NAVY)
    ax.set_xscale("log")
    ax.set_xlabel("External /24 blocks, ranked by bytes (log scale)")
    ax.set_ylabel("Cumulative share of external bytes")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    for k, c in ((0.01, ORANGE), (0.10, GREEN)):
        ax.axvline(n * k, ls=":", lw=0.9, color=c)
        ax.text(n * k * 1.1, 0.06, f"top {k:.0%} of blocks", fontsize=9.1, color=c, rotation=90)
    ax.set_title(f"External peers: {n:,} /24 blocks, and how unevenly they carry the bytes",
                 loc="left", fontweight="bold")
    finish(fig, "fig16_client_blocks",
           f"Top 1% of blocks carry {t1:.1%} of external bytes, top 10% carry {t10:.1%}. "
           "A /24 is an approximation of one external organisation, not a person.")


# ---------- F17 固定端口组 ----------
def fig_port_groups():
    watch = json.load(open(CAL + "caliber_all_summary.json", encoding="utf-8"))["watch_port_src_top"]
    tot = lambda v: sum(v.values()) if isinstance(v, dict) else int(v)   # 值可能是"按方向的字典"
    top = sorted(((k, tot(v)) for k, v in watch.items()), key=lambda kv: -kv[1])[:10][::-1]
    lab = [k for k, _ in top]
    val = [v for _, v in top]
    fig, ax = plt.subplots(figsize=(7.0, 3.4))
    ax.barh(np.arange(len(lab)), val, color=[ORANGE if v > 8e5 else NAVY for v in val], height=0.62)
    ax.set_yticks(np.arange(len(lab))); ax.set_yticklabels([f"port {k}" for k in lab])
    ax.set_xlabel("Packets from this source port")
    ax.ticklabel_format(axis="x", style="plain")
    for y, v in zip(np.arange(len(lab)), val):
        ax.text(v * 1.01, y, f"{v:,}", va="center", fontsize=9.1)
    ax.set_xlim(0, max(val) * 1.2)
    ax.set_title("Three source ports carry near-identical volume", loc="left", fontweight="bold")
    dom = {k: max(v.items(), key=lambda kv: kv[1]) for k, v in watch.items() if isinstance(v, dict)}
    finish(fig, "fig17_port_groups",
           "The three highlighted ports differ by a handful of packets out of about 810,000 each. "
           f"Ports 50316 and 35326 are dominated by a single inside host ({dom['50316'][0]}), and "
           f"port 45780 is almost entirely loopback ({dom['45780'][0]}); that reads as one application "
           "spread over parallel channels, not as adversarial behaviour.")


# ---------- F18 变点与极值 ----------
def fig_changepoints():
    cp = pd.read_csv(DET + "changepoints.csv")
    pot = pd.read_csv(DET + "pot.csv")
    fig, axes = plt.subplots(1, len(blocks), figsize=(9.0, 3.0), sharey=True)
    tails = []
    for ax, (name, b) in zip(axes, blocks):
        seg = str(b["segment"].iloc[0])
        x = b["packets"].to_numpy(float)
        ax.plot(x / 1000, lw=0.8, color=NAVY)
        row = cp[cp["segment"].astype(str) == seg[:6]]
        if len(row):
            c = int(row.iloc[0]["changepoint_sec"])
            ax.axvline(c, ls="--", lw=1.1, color=ORANGE)
            # 序列又密又尖，绘图区里没有安全的空白：变点信息并入分面标题，图上只留虚线
            name = "%s  -  change point at %d s (p=%.3f)" % (name, c, row.iloc[0]["perm_p"])
        prow = pot[pot["segment"].astype(str) == seg[:6]]
        if len(prow):
            u = float(prow.iloc[0]["threshold"]) / 1000
            xi = float(prow.iloc[0]["xi"])
            tail = ("bounded tail" if xi < -0.01 else "exponential tail" if abs(xi) <= 0.01 else "heavy tail")
            ax.axhline(u, ls=":", lw=1.0, color=RED)
            # 阈值文字不再压在曲线上：数值并入脚注（见下），图上只留虚线
            tails.append("%s %.0fk pps (%s, xi=%+.3f)" % (name.split(" (")[0], u, tail, xi))
        ax.set_title(name, loc="left", fontweight="bold", fontsize=12.3)
        ax.set_xlabel("Seconds into block"); ax.set_ylabel("Packets per second (thousands)")
    fig.subplots_adjust(top=0.80)          # 分面标题与总标题之间留出间距
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("Change points and extreme levels: steps, not cliffs", x=0.005, y=0.97, ha="left",
                 fontweight="bold", fontsize=15.0)
    finish(fig, "fig18_changepoints_pot",
           "One significant change point per block (permutation p = 0.003-0.012), each moving the mean by at "
           "most about 11%. Extreme threshold (dotted line): " + "; ".join(tails) +
           " - the negative shape parameter means a bounded tail.")


for fn in (fig_series, fig_periodogram, fig_band, fig_pipeline, fig_clusters, fig_consistency,
           fig_client_blocks, fig_port_groups, fig_changepoints):
    fn()
print("第四批完成（F10-F18）")
