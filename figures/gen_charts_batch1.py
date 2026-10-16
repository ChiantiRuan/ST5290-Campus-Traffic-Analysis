#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 终期报告出图（第一批 4 张核心图，用于定风格）
  图 1  F0  观测窗口示意（含两段连续观测与间隔）
  图 2  F6  主机流量 Lorenz + 累计占比（Gini）
  图 3  F19 对外服务画像（Top-500 名称的类别构成）
  图 4  F22 会话级 Lorenz + 会话字节量级分布

统一约定（与报告口径一致）
  · 图内标签一律英文；中文版仅翻译图注，不重绘
  · 单向字节口径；分母写进标题或脚注；时间类结论限两个观测段内
  · 输出 PNG(300dpi) + SVG 到 figures/output/
"""
from pathlib import Path
REPO = str(Path(__file__).resolve().parents[1]) + "/"  # 导出后为仓库根目录；脚本位于仓库下一级
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

P = REPO
CAL, P3, DP, DP2 = (P + "data/probe_caliber/", P + "data/probe/",
                    P + "data/deep_probe/", P + "data/deep2/")
OUT = P + "figures/output/"
os.makedirs(OUT, exist_ok=True)

import chart_style
from chart_style import NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED, SRC, finish
chart_style.set_out(OUT)
chart_style.use_style()
# ---------------- 图 1：观测窗口 ----------------
def fig_window():
    ps = pd.read_csv(P3 + "per_second_all.csv")
    ps["time_cst"] = (pd.to_datetime(ps["time_cst"].str.replace(" CST", "", regex=False),
                                     format="%Y-%m-%d %H:%M:%S.%f").dt.tz_localize("Asia/Shanghai"))
    ps = ps.sort_values("unix_sec")
    t0 = ps["time_cst"].min()
    sec = (ps["unix_sec"] - ps["unix_sec"].min()).astype(int)
    # 缺秒处插 NaN，让间隔真实显示
    full = np.arange(sec.max() + 1)
    rate = pd.Series(np.nan, index=full)
    rate.loc[sec.values] = ps["packets"].values
    x = t0 + pd.to_timedelta(full, unit="s")

    fig, ax = plt.subplots(figsize=(7.6, 2.9))
    ax.plot(x, rate / 1000.0, lw=0.9, color=NAVY)
    ax.set_ylabel("Packets per second (thousands)")
    ax.set_xlabel("Local time (CST, 20 Sep 2026)")
    ax.set_title("Capture coverage: two continuous blocks, 17.2 minutes in total", loc="left", fontweight="bold")
    ax.axvspan(t0 + pd.Timedelta(seconds=192), t0 + pd.Timedelta(seconds=352),
               color="#F2C14E", alpha=0.25, lw=0)
    ax.annotate("gap ≈ 5.9 min\n(no capture)", xy=(t0 + pd.Timedelta(seconds=272), 40),
                ha="center", fontsize=9.8, color="#8A6D1A")
    ax.annotate("block 1: 192 s", xy=(t0 + pd.Timedelta(seconds=96), ax.get_ylim()[1] * 0.92),
                ha="center", fontsize=9.8, color=NAVY)
    ax.annotate("block 2: 840 s (files 2-4, back-to-back)", xy=(t0 + pd.Timedelta(seconds=690), ax.get_ylim()[1] * 0.92),
                ha="center", fontsize=9.8, color=NAVY)
    fig.autofmt_xdate(rotation=0, ha="center")
    finish(fig, "fig01_capture_window",
           "Each point = one second of capture; gaps are seconds with no data. Files 2/3/4 meet "
           "end-to-start, so they form one 840 s block.")


# ---------------- 图 2：主机 Lorenz ----------------
def fig_host_lorenz():
    hp = pd.read_csv(CAL + "host_profile_v2_merged.csv")
    v = np.sort(hp["total_bytes"].to_numpy(float))
    n = v.size
    cum = np.cumsum(v) / v.sum()
    xs = np.arange(1, n + 1) / n
    a = np.sort(v)
    gini = float((n + 1 - 2 * (np.cumsum(a) / a.sum()).sum()) / n)
    # 注意：v 升序，cum[i] 是"最小的 i+1 台"所占份额。前 K% 必须从尾部取。
    top = lambda frac: float(v[-max(int(frac * n), 1):].sum() / v.sum())
    t1, t10, t100 = top(0.01), top(0.10), top(100 / n)
    # 内置对照断言：与已定稿口径不一致就直接报错，避免图上印错数字
    for label, got, want in (("Gini", gini, 0.982), ("top1%", t1, 0.816),
                             ("top10%", t10, 0.986), ("top100", t100, 0.600)):
        assert abs(got - want) < 0.004, f"{label} 与记录口径不符: {got:.4f} vs {want}"
    print(f"  [自检] Gini={gini:.3f} top1%={t1:.1%} top10%={t10:.1%} top100={t100:.1%} 与口径一致")

    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.2))
    ax = axes[0]
    ax.plot(xs, cum, lw=1.6, color=NAVY)
    ax.plot([0, 1], [0, 1], ls="--", lw=0.9, color=GREY)
    ax.set_title("Lorenz curve of one-way bytes per host", loc="left", fontweight="bold")
    ax.set_xlabel("Hosts, least → most traffic"); ax.set_ylabel("Cumulative share of bytes")
    ax.xaxis.set_major_formatter(PercentFormatter(1.0)); ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    # 贴在左上角、顶端对齐：原 (0.06, 0.62) 的框会压到对角虚线
    ax.text(0.02, 0.98, f"Gini = {gini:.3f}\nTop 1% of hosts = {t1:.1%}\nTop 10% = {t10:.1%}\nTop 100 hosts = {t100:.1%}",
            fontsize=10.4, color=NAVY, va="top", ha="left", bbox=dict(fc="#F4F7FA", ec="#D6E0EA", lw=0.6))
    ax = axes[1]
    rank = np.arange(1, n + 1)
    desc = v[::-1]                                   # v 升序 → 反转即降序（从最大主机开始）
    cum_top = np.cumsum(desc) / desc.sum()
    ax.plot(rank, cum_top, lw=1.6, color=ORANGE)
    ax.set_xscale("log")
    ax.set_ylim(0, 1.02)
    ax.set_title("Same curve, host rank on log scale", loc="left", fontweight="bold")
    ax.set_xlabel("Hosts, ranked by traffic (log scale)"); ax.set_ylabel("Cumulative share of bytes")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    for k, c in ((100, NAVY), (1000, GREEN), (10000, PURPLE)):
        ax.axvline(k, ls=":", lw=0.8, color=c)
        ax.text(k, 0.04, f" top {k}", fontsize=9.1, color=c, rotation=90, va="bottom")
    finish(fig, "fig06_host_lorenz",
           f"n = {n:,} hosts (5,223 inside + 44,335 external peers + 2 loopback), one-way bytes. "
           "Left tail of the log panel is where the capacity sits.")

for fn in (fig_window, fig_host_lorenz):
    fn()
print("第一批 2 张完成（先看风格是否合意，再出 F19/F22）")
