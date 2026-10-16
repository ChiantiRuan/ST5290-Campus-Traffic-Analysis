#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 出图第五批（F20 / F21 / F23）
  F20 会话时长分布
  F21 发起方 → 响应方 矩阵（会话数与字节）
  F23 主机周期：周期 vs 峰值强度（BH-FDR 校正后）
图内纯 ASCII，口径同前。
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
from matplotlib.ticker import PercentFormatter

P = REPO
DP, DP2 = P + "data/deep_probe/", P + "data/deep2/"
OUT = P + "figures/output/"
os.makedirs(OUT, exist_ok=True)
import chart_style
from chart_style import NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED, SRC, finish
chart_style.set_out(OUT)
chart_style.use_style()
# ---------- F20 会话时长 ----------
def fig_durations():
    s = json.load(open(DP2 + "session2_summary.json", encoding="utf-8"))
    N = s["sessions_ge2pkt"]
    labels = ["under 1 s\n(same second)", "1-9 s", "10-59 s", "60-299 s", "300 s and over"]
    vals = [s["duration_hist"]["< 0.001 s"], s["duration_hist"]["< 10 s"], s["duration_hist"]["< 60 s"],
            s["duration_hist"]["< 300 s"], s["duration_hist"][">= 300s"]]
    assert sum(vals) == N, f"时长分箱合计 {sum(vals)} != 会话数 {N}"

    fig, ax = plt.subplots(figsize=(7.6, 3.3))
    x = np.arange(len(labels))
    ax.bar(x, vals, color=[ORANGE, NAVY, NAVY, GREEN, PURPLE], width=0.62)
    ax.set_yscale("log")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=10.4)
    ax.set_ylabel("Sessions (log scale)")
    for xi, v in zip(x, vals):
        ax.text(xi, v * 1.06, f"{v:,}\n{v/N:.1%}", ha="center", fontsize=9.8)
    ax.set_ylim(1, max(vals) * 6)
    ax.set_title("Session durations: short bursts plus a long tail of near-persistent flows",
                 loc="left", fontweight="bold")
    finish(fig, "fig20_session_duration",
           f"n = {N:,} sessions. Median {s['duration_median_s']:.1f} s, P90 {s['duration_p90_s']:.0f} s. "
           "Durations are last minus first packet time, resolved in whole seconds in this pass, "
           "so the first bar covers anything below one second.")


# ---------- F21 发起方矩阵 ----------
def fig_initiator():
    m = pd.read_csv(DP + "initiator_matrix.csv")
    m["bytes_per_session"] = m["bytes"] / m["sessions"]
    m = m.sort_values("sessions", ascending=True)
    zh = {"int->ext": "Inside → external", "ext->int": "External → inside", "int->int": "Inside ↔ inside",
          "loop->loop": "Loopback", "int->loop": "Host → own services"}
    lab = [zh.get(k, k) for k in m["initiator->responder"]]

    # 右面板沿用同样的类别名，刻度标签会伸进左面板：拉开面板间距
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.2))
    fig.subplots_adjust(wspace=0.55)
    ax = axes[0]
    y = np.arange(len(m))
    ax.barh(y, m["sessions"], color=NAVY, height=0.62)
    ax.set_yticks(y); ax.set_yticklabels(lab, fontsize=10.4)
    ax.set_xlabel("Sessions")
    for yi, v in zip(y, m["sessions"]):
        ax.text(v * 1.01, yi, f"{v:,} ({v/m['sessions'].sum():.0%})", va="center", fontsize=9.1)
    ax.set_xlim(0, m["sessions"].max() * 1.35)
    ax.set_title("Who starts the conversation", loc="left", fontweight="bold", fontsize=12.3)

    ax = axes[1]
    ratio = m["bytes_per_session"] / 1e3
    ax.barh(np.arange(len(m)), ratio, color=[GREEN if k in ("ext->int", "loop->loop") else NAVY
                                             for k in m["initiator->responder"]], height=0.62)
    ax.set_yticks(np.arange(len(m))); ax.set_yticklabels(lab, fontsize=10.4)
    ax.set_xscale("log")
    ax.set_xlabel("Bytes per session (log scale, thousands)")
    for yi, v in zip(np.arange(len(m)), ratio):
        ax.text(v * 1.06, yi, f"{v:,.0f}k", va="center", fontsize=9.1)
    ax.set_xlim(right=ratio.max() * 3)
    ax.set_title("How much each session carries", loc="left", fontweight="bold", fontsize=12.3)

    fig.subplots_adjust(top=0.80)   # 与分面标题留间距
    fig.suptitle("The network starts most conversations, but the heavy ones are started from outside",
                 x=0.005, y=0.97, ha="left", fontweight="bold", fontsize=15.0)
    finish(fig, "fig21_initiator_matrix",
           "Inside hosts initiate 79.5% of sessions; sessions started from outside carry about twice the "
           "bytes per session, and loopback sessions carry the most (1.7 MB each on average).")


# ---------- F23 主机周期 ----------
def fig_periodicity():
    f = pd.read_csv(DP2 + "fdr_periodic_hosts.csv")
    sig = f["significant_q05"].astype(bool)
    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    ax.scatter(f.loc[~sig, "period_s"], f.loc[~sig, "peak"], s=8, color="#C9C9C9", alpha=0.6,
               edgecolors="none", label=f"not significant after FDR (n={(~sig).sum():,})")
    sc = ax.scatter(f.loc[sig, "period_s"], f.loc[sig, "peak"], s=10 + 14 * f.loc[sig, "cv"].clip(0, 4),
                    color=NAVY, alpha=0.7, edgecolors="none",
                    label=f"significant at q<0.05 (n={sig.sum():,})")
    ax.axvspan(2, 60, color="#FFF6E0", zorder=0)
    # 说明文字原来压在散点上：改到脚注，图上只留浅色带
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Dominant period (seconds, log scale)"); ax.set_ylabel("Spectral peak vs shuffled baseline (log)")
    ax.set_title("Host-level periodicity: many candidates, a credible few", loc="left", fontweight="bold")
    # 图例原本在右上角，与主机标注相撞：移到坐标区下方（再往下让开 x 轴标题）
    fig.subplots_adjust(bottom=0.40)
    leg = ax.legend(fontsize=9.8, frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.245))
    for txt in leg.get_texts():
        txt.set_color("#333333")
    cred = f[sig].assign(score=lambda d: d["peak"] / (1 + d["cv"])).nlargest(3, "score")
    # 三个标注原来用同一个偏移量，彼此相压：按索引错开方向与距离
    offs = [(10, -26), (-98, -14), (10, 18)]
    for (_, r), (dx, dy) in zip(cred.iterrows(), offs):
        ax.annotate(f"{r['ip']}  {r['period_s']:.1f} s\nCV {r['cv']:.2f}", xy=(r["period_s"], r["peak"]),
                    xytext=(dx, dy), textcoords="offset points", fontsize=8.8, color=RED,
                    arrowprops=dict(arrowstyle="-", color=RED, lw=0.7))
    finish(fig, "fig23_periodic_hosts",
           f"n = {len(f):,} host-by-block series with at least 30 seconds of data; {sig.sum():,} pass "
           "Benjamini-Hochberg at q<0.05. The shaded band marks 2-60 s, where a heartbeat would live. "
           "Shuffling is a weak null for bursty traffic, so the credible set is the low-CV, high-peak "
           "corner, not the whole blue cloud.")


fig_durations()
fig_initiator()
fig_periodicity()
print("第五批完成（F20/F21/F23）")
