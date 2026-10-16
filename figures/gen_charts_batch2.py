#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 出图第二批：F19 对外服务画像 / F22 会话级集中度
约定同 gen_charts_batch1：图内英文、单向口径、分母进标题或脚注。
"""
from pathlib import Path
REPO = str(Path(__file__).resolve().parents[1]) + "/"  # 导出后为仓库根目录；脚本位于仓库下一级
import os
import re

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
# 关键词 → 类别（透明映射，落到 CSV 供审阅；只写类别，不逐条列举个人向域名）
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
RULES = [
    ("Internal discovery (mDNS/SSDP/NetBIOS/print)", [".local", "wpad", "_ipp", "_googlecast", "_airplay", "_raop",
                                                      "_companion-link", "_rdlink", "_homekit", "print", "hp ",
                                                      "239.255.255.250", "nbns"]),
    ("Literal IP endpoints (no name)", []),   # 由 IP_RE 判定
    ("Instant messaging / collaboration", ["weixin", "wechat", "dingtalk", "ding.zj.gov", "qq.com", "feishu", "lark"]),
    ("Office suite / cloud drive", ["wps", "kdocs", "office", "onedrive", "sharepoint", "dingtalk.com"]),
    ("Cloud services & telemetry", ["tencent", "googleapis", "gstatic", "mmstat", "tb.", "alibaba", "qihucdn",
                                    "doubleclick", "analytics", "umeng", "cnzz", "stat", "bytedance", "bdstatic",
                                    "google", "huawei", "qpic"]),
    ("Internal host names & services", ["seaweedfs", "-pc", "pc-", "win-", "hunt", "dev3", "fwb-"]),
    ("Search & portals", ["baidu", "sogou", "bing", "so.com", "360"]),
    ("OS / vendor services", ["apple", "microsoft", "windowsupdate", "msftconnecttest", "icloud", "dell", "lenovo"]),
    ("Endpoint agent / security", ["asiainfo", "osce", "deepsurf", "safedog", "qianxin"]),
    ("Network device / infra", ["ruijienetworks", "rdate", "stun", "ntp", "ruijie"]),
    ("E-commerce & local services", ["taobao", "tmall", "lianjia", "jd.com", "meituan"]),
]


def categorise(name):
    low = name.lower()
    if IP_RE.match(low):
        return "Literal IP endpoints (no name)"
    if "." not in low and not low.isdigit():      # NetBIOS 风格短名：dev305b52 / win-od4svun7hgd
        return "Internal host names & services"
    for label, keys in RULES:
        if keys and any(k in low for k in keys):
            return label
    return "Other / unmatched"


def fig_service_profile():
    d = pd.read_csv(DP + "domains_top.csv")
    d["category"] = d["name"].map(categorise)
    d[["kind", "name", "count", "category"]].to_csv(OUT + "chart_data_f19_categories.csv", index=False)
    KINDS = [("dns", NAVY, "DNS query name"), ("tls_sni", GREEN, "TLS SNI"), ("http_host", ORANGE, "HTTP Host")]
    KIND_C = {k: c for k, c, _ in KINDS}
    KIND_L = {k: lbl for k, _, lbl in KINDS}

    fig, axes = plt.subplots(1, 2, figsize=(9.6, 4.0))
    # 左：Top-15 名称（不做任何分类，最透明）
    ax = axes[0]
    top = d.sort_values("count", ascending=False).head(15).iloc[::-1]
    y = np.arange(len(top))
    ax.barh(y, top["count"], color=[KIND_C.get(k, GREY) for k in top["kind"]], height=0.68)
    ax.set_yticks(y)
    ax.set_yticklabels([(n[:40] + "…") if len(n) > 41 else n for n in top["name"]], fontsize=9.1)
    ax.set_xlabel("Appearances in the capture")
    ax.set_title("Top-15 names, by kind", loc="left", fontweight="bold")
    ax.legend(handles=[plt.Rectangle((0, 0), 1, 1, fc=KIND_C[k]) for k in KIND_C],
              labels=[KIND_L[k] for k in KIND_C], fontsize=9.1, loc="lower right", frameon=False)

    # 右：类别构成（关键词映射；未归类的长尾单列）
    ax = axes[1]
    tab = d.groupby("category").size().sort_values()
    y = np.arange(len(tab))
    ax.barh(y, tab.values, height=0.68,
            color=[GREY if c.startswith("Other") else TEAL for c in tab.index])
    ax.set_yticks(y)
    ax.set_yticklabels([t.replace(" (mDNS/SSDP/NetBIOS/print)", "\n  (mDNS/SSDP/NetBIOS/print)") if len(t) > 30 else t
                        for t in tab.index], fontsize=9.8)
    ax.set_xlabel("Names in the top-500 sample")
    ax.set_title("Category composition (keyword mapping)", loc="left", fontweight="bold")
    for yi, v in zip(y, tab.values):
        ax.text(v + 2, yi, str(v), va="center", fontsize=9.1)
    ax.set_xlim(0, tab.max() * 1.14)

    # 右面板的类别名很长，刻度标签会伸进左面板：拉开面板间距
    fig.subplots_adjust(top=0.80, wspace=0.62)   # 与分面标题留间距 + 面板间距
    fig.suptitle("Outward identity: which names the network talks to", x=0.005, y=0.97, ha="left",
                 fontweight="bold", fontsize=15.0)
    finish(fig, "fig19_service_profile",
           "Sample = top 500 names by appearance count (200 DNS / 200 TLS SNI / 100 HTTP Host); "
           "the capture holds 13,957 unique DNS names, 6,875 SNI and 1,407 HTTP Hosts in total. "
           "Left panel is unclassified; right panel groups by keyword (see chart_data_f19_categories.csv). "
           "The unmapped remainder is a long tail of misc SaaS/APIs and enterprise-specific names.")


def fig_session_concentration():
    lz = pd.read_csv(DP2 + "session_bytes_lorenz.csv")
    dist = pd.read_csv(DP2 + "session_bytes_dist.csv")
    import json
    s = json.load(open(DP2 + "session2_summary.json", encoding="utf-8"))
    N = s["sessions_ge2pkt"]
    tf = s["top_flow_shares"]

    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.3))
    ax = axes[0]
    ax.plot(lz["top_share_of_flows"], lz["share_of_bytes"], lw=1.7, color=NAVY)
    ax.plot([0, 1], [0, 1], ls="--", lw=0.9, color=GREY)
    ax.set_title("Lorenz curve of session bytes", loc="left", fontweight="bold")
    ax.set_xlabel("Sessions, smallest → largest"); ax.set_ylabel("Cumulative share of bytes")
    ax.xaxis.set_major_formatter(PercentFormatter(1.0)); ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    # 说明框在这个尺寸下无处可放（左上三角、曲线与对角线之间的空隙都会撞线）：
    # 数字并入脚注，绘图区内不再放文字
    ax.set_title("Lorenz curve of session bytes", loc="left", fontweight="bold")
    ax = axes[1]
    ax.bar(dist["byte_magnitude"], dist["flows"], color=TEAL, width=0.62)
    ax.set_yscale("log")
    ax.set_title("Session size distribution", loc="left", fontweight="bold")
    ax.set_xlabel("Session bytes (order of magnitude)"); ax.set_ylabel("Sessions (log scale)")
    ax.tick_params(axis="x", labelrotation=30)
    finish(fig, "fig22_session_concentration",
           f"n = {N:,} sessions (≥2 packets); Gini = {s['session_gini']:.3f}; "
           f"top 10 = {tf['top_10']:.1%}, top 100 = {tf['top_100']:.1%}, top 1,000 = {tf['top_1000']:.1%}. "
           "Session = bidirectional 5-tuple with ≥2 packets. Byte total 34.23 GB, i.e. 98.2% of the "
           "34.85 GB one-way total; median duration 1.0 s, P90 90.0 s.")


fig_service_profile()
fig_session_concentration()
print("第二批 2 张完成（F19 / F22）")
