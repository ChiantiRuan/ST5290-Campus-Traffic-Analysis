#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 出图第三批（F1–F9）：流量构成与主机结构
  F1 包长分布（4 文件合并，标注 >1518 卸载右尾）
  F2 协议构成 + 目的端口 Top
  F3 方向构成（五类 × 包数/字节）
  F4 服务端口 × 方向 热力图
  F5 接口（ifidx）流量分布
  F7 离群散点（对端数 × 端口数）
  F8 端口熵分布
  F9 内网各段行为差异（中位数对照）
约定同前：图内英文、单向口径、分母进标题/脚注。
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
from matplotlib.colors import LogNorm
from matplotlib.ticker import PercentFormatter

P = REPO
P3, CAL = P + "data/probe/", P + "data/probe_caliber/"
OUT = P + "figures/output/"
os.makedirs(OUT, exist_ok=True)
import chart_style
from chart_style import NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED, SRC, finish
chart_style.set_out(OUT)
chart_style.use_style()

FILES = ["cap_20260920_111416", "cap_20260920_112321", "cap_20260920_112821", "cap_20260920_113321"]
C = json.load(open(CAL + "caliber_all_summary.json", encoding="utf-8"))


# ---------- F1 包长分布 ----------
def fig_pktlen():
    tot = None
    for f in FILES:
        d = pd.read_csv(f"{P3}{f}/pktlen_hist.csv")
        tot = d if tot is None else tot.merge(d, on="len_bin", suffixes=("", "_r"))
        if "packets_r" in tot:
            tot["packets"] = tot["packets"] + tot["packets_r"]
            tot = tot.drop(columns=["packets_r"])
    lo = tot["len_bin"].str.split("-", expand=True)[0].astype(int)
    tot = tot.assign(lo=lo).sort_values("lo")
    n = tot["packets"].sum()
    small = tot[tot["lo"] < 1518]["packets"].sum()

    fig, ax = plt.subplots(figsize=(7.6, 3.4))
    ax.bar(tot["lo"], tot["packets"], width=48, color=NAVY, align="edge")
    ax.set_yscale("log")
    ax.axvline(1518, ls="--", lw=1.0, color=RED)
    ax.text(1560, tot["packets"].max() * 0.35, f"frames > 1518 B: {1 - small / n:.1%}\n(offload-inflated lengths)",
            fontsize=9.8, color=RED)
    ax.set_xlabel("Frame length (bytes, 64-byte bins)")
    ax.set_ylabel("Packets (log scale)")
    ax.set_title("Packet-length distribution: a control-heavy mode plus an inflated tail",
                 loc="left", fontweight="bold")
    finish(fig, "fig01b_pktlen", f"n = {n:,} packets. The 64-127 B mode is ACK/control traffic; "
                                 "the >1518 B tail exceeds Ethernet MTU and points to capture-side offload.")


# ---------- F2 协议 + 端口 ----------
def fig_protocol():
    agg, ports = {}, {}
    for f in FILES:
        p = json.load(open(f"{P3}{f}/probe_summary.json", encoding="utf-8"))["protocol"]
        for k, v in p.items():
            if k == "non-IP":
                agg["non-IP"] = agg.get("non-IP", 0) + v
            else:
                last = str(k).split(",")[-1]
                lab = {"6": "TCP", "17": "UDP", "1": "ICMP", "2": "IGMP/other IP"}.get(last, "other IP")
                agg[lab] = agg.get(lab, 0) + v
        for k, v in ports.items():
            pass
    for prt, dd in C["service_ports"].items():
        ports[prt] = sum(v for k, v in dd.items() if k != "int-skip")
    tot = sum(agg.values())
    order = ["TCP", "UDP", "non-IP", "ICMP", "IGMP/other IP", "other IP"]
    labels = [k for k in order if k in agg]

    fig, axes = plt.subplots(1, 2, figsize=(9.0, 3.4))
    ax = axes[0]
    vals = [agg[k] / tot for k in labels]
    cols = [NAVY, TEAL, ORANGE, GREEN, PURPLE, GREY]
    ax.barh(np.arange(len(labels))[::-1], vals, color=cols[:len(labels)], height=0.66)
    ax.set_yticks(np.arange(len(labels))[::-1]); ax.set_yticklabels(labels)
    for y, v, k in zip(np.arange(len(labels))[::-1], vals, labels):
        ax.text(v + 0.012, y, f"{v:.1%}", va="center", fontsize=9.8)
    ax.set_xlim(0, max(vals) * 1.22); ax.xaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_title("Protocol mix (packet share)", loc="left", fontweight="bold")
    ax = axes[1]
    top = sorted(ports.items(), key=lambda kv: -kv[1])[:8][::-1]
    ax.barh(np.arange(len(top)), [v / 1e6 for _, v in top], color=GREEN, height=0.66)
    ax.set_yticks(np.arange(len(top))); ax.set_yticklabels(["port %s" % k for k, _ in top])
    ax.set_xlabel("Packets (millions)"); ax.set_title("Top destination ports", loc="left", fontweight="bold")
    for y, (k, v) in zip(np.arange(len(top)), top):
        ax.text(v / 1e6 * 1.02, y, f"{v / 1e6:.1f}M", va="center", fontsize=9.1)
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("What the traffic is: protocol mix and the ports that carry it",
                 x=0.005, y=0.97, ha="left", fontweight="bold", fontsize=15.0)
    finish(fig, "fig02_protocol_ports",
           f"n = {tot:,} packets. VLAN-tagged variants (e.g. \"1,17\") are merged into their inner protocol.")


# ---------- F3 方向构成 ----------
def fig_direction():
    dp, db = C["direction_pkts"], C["direction_bytes"]
    keys = ["ext-int", "int-ext", "int-int", "loop-loop", "int-loop"]
    lab = ["Inbound (external → inside)", "Outbound (inside → external)", "Inside ↔ inside",
           "Loopback", "Host → own services"]
    cols = [NAVY, ORANGE, TEAL, GREY, PURPLE]
    tp, tb = sum(dp.values()), sum(db.values())
    fig, axes = plt.subplots(1, 2, figsize=(9.4, 3.2), sharey=True)
    for ax, d, tot, unit, title in ((axes[0], dp, tp, "packets", "Share of packets"),
                                    (axes[1], db, tb, "bytes", "Share of bytes")):
        left = 0.0
        for k, l, c in zip(keys, lab, cols):
            w = d[k] / tot
            ax.barh([0], [w], left=left, color=c, height=0.5)
            # 标签必须装得进自己那段色块：量一次实际宽度，装不下就不画（数值在脚注里给出）
            # —— 原先只按"段宽 > 4.5%"粗判，5% 那段依然溢出压到相邻色块。
            t = ax.text(left + w / 2, 0, f"{w:.0%}", ha="center", va="center", fontsize=10.4,
                        color="white", fontweight="bold")
            fig.canvas.draw()
            seg_px = (ax.transData.transform((left + w, 0))[0] - ax.transData.transform((left, 0))[0])
            if t.get_window_extent().width > seg_px - 5:
                t.remove()
            left += w
        ax.set_xlim(0, 1); ax.set_yticks([]); ax.xaxis.set_major_formatter(PercentFormatter(1.0))
        ax.set_title(title, loc="left", fontweight="bold")
        ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, fc=c) for c in cols]
    fig.legend(handles, lab, ncol=3, fontsize=9.8, loc="lower center", frameon=False, bbox_to_anchor=(0.5, -0.16))
    # 总标题与分面标题之间留出间距（原默认 top=0.88 时会互相压住）
    fig.subplots_adjust(top=0.80)
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("Direction of traffic: inbound dominates the bytes, packets stay symmetric",
                 x=0.005, y=0.97, ha="left", fontweight="bold", fontsize=15.0)
    # 分母写清楚：五类合计（含回环与本机服务两类），避免与正文的"单向实流量"口径混淆
    shares = " · ".join("%s %.1f%% (%.1f GB)" % (l.split(" (")[0], db[k] / tb * 100, db[k] / 1e9)
                        for k, l in zip(keys, lab))
    finish(fig, "fig03_direction",
           f"Byte shares, denominator = sum of the five direction classes ({tb/1e9:.2f} GB): {shares}. "
           f"In/out byte ratio {db['ext-int']/db['int-ext']:.2f}x while the packet ratio is "
           f"{dp['ext-int']/dp['int-ext']:.2f}x.")


# ---------- F4 端口 × 方向 ----------
def fig_port_direction():
    ports = sorted(C["service_ports"].items(), key=lambda kv: -sum(v for k, v in kv[1].items()))[:10]
    keys = ["int-ext", "ext-int", "int-int", "int-skip"]
    M = np.array([[dd.get(k, 0) for k in keys] for _, dd in ports], dtype=float)
    fig, ax = plt.subplots(figsize=(5.6, 4.0))
    im = ax.imshow(np.where(M > 0, M, np.nan), aspect="auto", cmap="Blues", norm=LogNorm(vmin=max(M[M > 0].min(), 1), vmax=M.max()))
    ax.set_xticks(range(len(keys)))
    ax.set_xticklabels(["inside →\nexternal", "external →\ninside", "inside →\ninside", "self traffic"], fontsize=9.8)
    ax.set_yticks(range(len(ports)))
    ax.set_yticklabels([f"port {k}" for k, _ in ports], fontsize=10.4)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v = M[i, j]
            ax.text(j, i, "—" if v == 0 else f"{v/1e6:.1f}M" if v >= 1e6 else f"{v/1e3:.0f}k",
                    ha="center", va="center", fontsize=8.3,
                    color="white" if v > M.max() * 0.15 else "#333333")
    ax.set_title("Service ports by direction\n(packets, log colour scale)", loc="left", fontweight="bold")
    ax.grid(False)
    fig.colorbar(im, ax=ax, shrink=0.8, label="packets")
    top = ports[0]
    finish(fig, "fig04_port_direction_heat",
           f"Top-10 destination ports. Port {top[0]} alone carries {sum(top[1].values())/sum(sum(d.values()) for _, d in C['service_ports'].items()):.0%} "
           "of all service-port packets; the directional split is what makes it a serving port.")


# ---------- F5 接口分布 ----------
def fig_ifindex():
    pk, by = C["ifindex_pkts"], C["ifindex_bytes"]
    items = sorted(pk.items(), key=lambda kv: -kv[1])[:12]
    lab = [k for k, _ in items][::-1]
    pv = [pk[k] / 1e6 for k in lab]
    bv = [by.get(k, 0) / 1e9 for k in lab]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    y = np.arange(len(lab))
    ax.barh(y, pv, color=NAVY, height=0.62)
    ax.set_yticks(y); ax.set_yticklabels([f"if {k}" for k in lab])
    ax.set_xlabel("Packets (millions)")
    ax.set_title("Where traffic enters and leaves: top capture interfaces", loc="left", fontweight="bold")
    for yi, (p, b) in zip(y, zip(pv, bv)):
        ax.text(p * 1.01, yi, f"{p:.1f}M pkt / {b:.1f} GB", va="center", fontsize=9.1)
    ax.set_xlim(0, max(pv) * 1.28)
    dup = sorted([k for k, v in pk.items() if v == pk.get("8")] if len(set(pk.values())) < len(pk) else [])
    finish(fig, "fig05_ifindex",
           f"{len(pk)} capture interfaces in total. Identical counts on some pairs (e.g. if 8 and if 6, "
           "and 156/157/161) come from multi-interface capture seeing the same frame twice; "
           "the affected volume is under 0.1% and does not move any conclusion.")


# ---------- F7 离群散点 ----------
def fig_outliers():
    h = pd.read_csv(CAL + "host_profile_v2_merged.csv")
    i = h[h["class"] == "int"].copy()
    big = i["total_bytes"] >= i["total_bytes"].quantile(0.90)
    wide = (i["ports"] >= 50) & (i["peers"] >= 20)
    i["grp"] = np.where(big & wide, "Serving", np.where(~big & wide, "Interactive",
                        np.where(big & ~wide, "Bulk", "Low volume")))
    cols = {"Serving": NAVY, "Interactive": TEAL, "Bulk": ORANGE, "Low volume": "#C9C9C9"}
    fig, ax = plt.subplots(figsize=(7.0, 4.0))
    for g, d in i.groupby("grp"):
        ax.scatter(d["peers"], d["ports"], s=6, alpha=0.55, color=cols[g], label=f"{g} (n={len(d):,})",
                   edgecolors="none")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Distinct peers (log scale)"); ax.set_ylabel("Distinct destination ports (log scale)")
    top = i.nlargest(1, "peers").iloc[0]
    # 标注块放到右下空白区、用引线指向出界主机（原来放在 (0.42,0.16)，正压在密集点云上）
    ax.annotate(f"{top['ip']}\npeers {int(top['peers'])}, ports {int(top['ports'])} (censored at 5,000)",
                xy=(top["peers"], top["ports"]), xytext=(0.98, 0.04), textcoords="axes fraction",
                ha="right", va="bottom", fontsize=9.8, color=RED,
                arrowprops=dict(arrowstyle="->", color=RED, lw=0.9, shrinkB=2))
    ax.legend(fontsize=9.8, frameon=False, loc="upper left")
    ax.set_title("Inside hosts: fan-out vs port spread, and the one host off the chart",
                 loc="left", fontweight="bold")
    finish(fig, "fig07_outlier_scatter",
           f"n = {len(i):,} inside hosts. Groups follow the same transparent rule as the report "
           "(bulk = bytes ≥ P90; wide = ports ≥ 50 and peers ≥ 20).")


# ---------- F8 端口熵 ----------
def fig_entropy():
    h = pd.read_csv(CAL + "host_profile_v2_merged.csv")
    e = h.loc[h["class"] == "int", "port_entropy_norm"].dropna()
    fig, ax = plt.subplots(figsize=(7.0, 3.2))
    ax.hist(e, bins=np.linspace(0, 1, 41), color=NAVY)
    zero = (e == 0).mean()
    ax.axvline(0.9, ls="--", lw=1.0, color=ORANGE)
    ax.text(0.62, ax.get_ylim()[1] * 0.72, f"single-port hosts: {zero:.1%}\n(entropy = 0)",
            fontsize=10.4, color=NAVY)
    ax.text(0.905, ax.get_ylim()[1] * 0.45, "wide\nport spread", fontsize=9.8, color=ORANGE)
    ax.set_xlabel("Normalised destination-port entropy"); ax.set_ylabel("Inside hosts")
    ax.set_title("Port entropy is bimodal: single-port hosts vs wide spreaders",
                 loc="left", fontweight="bold")
    finish(fig, "fig08_entropy_hist",
           f"n = {len(e):,} inside hosts. Bimodality coefficient 0.836 and a two/three-component mixture "
           "beats one component on BIC (see the anomaly list, section 3).")


# ---------- F9 各段行为差异 ----------
def fig_segments():
    h = pd.read_csv(CAL + "host_profile_v2_merged.csv")
    i = h[h["class"] == "int"].copy()
    i["seg"] = i["ip"].str.rsplit(".", n=1).str[0]
    grp = {"10.100": i[i["ip"].str.startswith("10.100.")], "10.168": i[i["ip"].str.startswith("10.168.")],
           "172.2": i[i["ip"].str.startswith("172.2.")], "10.254.254": i[i["ip"].str.startswith("10.254.254.")]}
    name = {"10.100": "10.100/16\n(service-leaning)", "10.168": "10.168/16\n(business-leaning)",
            "172.2": "172.2/16\n(infrastructure)", "10.254.254": "10.254.254.0/24\n(network devices)"}
    metrics = [("peers", "Median distinct peers"), ("ports", "Median distinct ports"),
               ("bytes_per_pkt", "Median bytes per packet")]
    fig, axes = plt.subplots(1, 3, figsize=(9.6, 3.2))
    for ax, (m, title) in zip(axes, metrics):
        vals = [grp[k][m].median() for k in grp]
        ax.bar(range(len(grp)), vals, color=[NAVY, ORANGE, GREY, TEAL], width=0.62)
        ax.set_xticks(range(len(grp)))
        # 原先用两行长名做刻度，三个面板下彼此相压：刻度只留短前缀，含义写进脚注
        ax.set_xticklabels([name[k].split("\n")[0].replace("10.254.254.0/24", "10.254.254/24") for k in grp],
                           fontsize=9.1, rotation=18, ha="right")
        ax.set_title(title, loc="left", fontweight="bold", fontsize=12.3)
        for x, v in zip(range(len(grp)), vals):
            ax.text(x, v * 1.02, f"{v:,.0f}" if v >= 10 else f"{v:,.0f}" if v >= 1 else f"{v:.0f}",
                    ha="center", fontsize=9.8)
    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("Inside segments differ in behaviour, not in nature (medians)",
                 x=0.005, y=0.97, ha="left", fontweight="bold", fontsize=15.0)
    lean = {"10.100": "service-leaning", "10.168": "business-leaning", "172.2": "infrastructure",
            "10.254.254": "network devices"}
    finish(fig, "fig09_segment_behaviour",
           "Medians per segment; n = " + ", ".join(
               f"{name[k].splitlines()[0]} ({lean[k]}) {len(grp[k]):,}" for k in grp) +
           ". Segment meaning: 10.100/16 service-leaning, 10.168/16 business-leaning, 172.2/16 "
           "infrastructure, 10.254.254.0/24 network devices (identified by vendor/NTP names in the "
           "sampled attribution, not by a rule).")


for fn in (fig_pktlen, fig_protocol, fig_direction, fig_port_direction, fig_ifindex, fig_outliers, fig_entropy, fig_segments):
    fn()
print("第三批完成（F1–F9）")
