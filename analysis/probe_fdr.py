#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 主机级周期的严格复核（probe_fdr）：把"高于打乱基线"升级为"经验 p 值 + BH-FDR"。

输入：data/deep2/host_series_watch.csv（probe_deep2 落盘的每主机秒级序列）
     data/deep_probe/host_periodicity.csv（候选来源与"假象"过滤标记）
做法：对每台候选主机、每个片段的秒级序列：
  ① 观测统计量 = 周期图峰值（排除周期 > n/3 的最低频段，剔除趋势/假象）
  ② 经验 p 值 = 打乱序列 N 次后峰值 ≥ 观测值的比例（N=2000）
  ③ 跨主机做 Benjamini–Hochberg 校正，给出 q 值
输出：data/deep2/fdr_periodic_hosts.csv + fdr_summary.json
"""
from pathlib import Path
REPO = str(Path(__file__).resolve().parents[1]) + "/"  # 导出后为仓库根目录；脚本位于仓库下一级
import json, os, sys
import numpy as np
import pandas as pd

P = REPO
DP2 = P + "data/deep2/"
DP = P + "data/deep_probe/"
NSHUF = 2000
RNG = np.random.default_rng(11)


def relabel_segments(df, gap=120):
    """还原真实观测段：按 unix_sec 中 >gap 秒的断点聚簇，按时间顺序命名 blk1, blk2, ...

    背景（实测）：4 个采集文件里，2/3/4 的首尾时间严丝合缝相接
    （11:28:20.995 → 11:33:20.994），因此它们构成**一个连续的 840 秒观测段**；
    只有文件 1（192 秒）与它之间有约 5.9 分钟的间隔。
    即：实际是「两个连续观测段」，而不是四个不连续片段。
    现有 deep2 产物只带歧义标签（三个文件都叫 "1.pcap"），故用时间还原，无需重读原包。
    """
    secs = np.sort(df["unix_sec"].unique())
    cut = np.where(np.diff(secs) > gap)[0]
    groups = np.split(secs, cut + 1)
    m = np.full(df.shape[0], "", dtype=object)
    for i, grp in enumerate(groups, 1):
        m[df["unix_sec"].isin(grp).to_numpy()] = "blk%d" % i
    df = df.copy()
    df["segment"] = m
    return df


def series_of(df, ip, seg):
    g = df[(df["ip"] == ip) & (df["segment"] == seg)].sort_values("unix_sec")
    if g.empty:
        return None
    lo, hi = int(g["unix_sec"].min()), int(g["unix_sec"].max())
    n = hi - lo + 1
    if n < 30 or n > 4000:
        return None
    x = np.zeros(n)
    x[g["unix_sec"].to_numpy(int) - lo] = g["packets"].to_numpy(float)
    return x


def peak(x, kmin=3):
    """周期图峰值（排除周期 > n/kmin 的最低频段，避免趋势被当成周期）。"""
    y = x - x.mean()
    pw = np.abs(np.fft.rfft(y)) ** 2
    pw = pw[1:]
    idx = np.arange(1, len(pw) + 1)
    if not (idx >= kmin).any():
        return np.nan
    return float(pw[int(np.argmax(np.where(idx >= kmin, pw, -1)))])


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", default=DP2 + "host_series_watch.csv")
    ap.add_argument("--periodicity", default=DP + "host_periodicity.csv")
    ap.add_argument("--out", default=DP2)
    a = ap.parse_args()
    global NSHUF
    ws = relabel_segments(pd.read_csv(a.series))
    # 候选直接取自序列数据本身（不再依赖预筛名单，避免"先在旧标签上筛过"的偏差）：
    # 每个（主机 × 观测段）只要跨度 ≥30 秒即可检验
    g = ws.groupby(["ip", "segment"])["unix_sec"].agg(["min", "max"]).reset_index()
    g["span"] = g["max"] - g["min"] + 1
    cand = g[(g["span"] >= 30) & (g["span"] <= 4000)][["ip", "segment"]].drop_duplicates()
    rows = []
    for _, r in cand.iterrows():
        x = series_of(ws, r["ip"], r["segment"])
        if x is None:
            continue
        n = len(x)
        obs = peak(x)
        if not np.isfinite(obs) or obs <= 0:
            continue
        null = np.empty(NSHUF)
        y0 = x - x.mean()
        for i in range(NSHUF):
            z = y0[RNG.permutation(n)]
            pz = np.abs(np.fft.rfft(z)) ** 2
            pz = pz[1:]
            idx = np.arange(1, len(pz) + 1)
            null[i] = np.max(np.where(idx >= 3, pz, -1))
        p = float((np.sum(null >= obs) + 1) / (NSHUF + 1))
        # 反推周期（与 probe_detect 同口径）
        pw = np.abs(np.fft.rfft(y0)) ** 2
        pw = pw[1:]
        idx = np.arange(1, len(pw) + 1)
        k = int(np.argmax(np.where(idx >= 3, pw, -1)))
        rows.append(dict(ip=r["ip"], segment=r["segment"], seconds=n, mean_pps=round(x.mean(), 2),
                         cv=round(float(x.std() / x.mean()), 3) if x.mean() else None,
                         period_s=round(n / (k + 1), 1), peak=obs, perm_p=p))
    out = pd.DataFrame(rows)
    if out.empty:
        print("无可用序列（deep2 未完成？）"); sys.exit(1)
    # Benjamini–Hochberg
    out = out.sort_values("perm_p").reset_index(drop=True)
    m = len(out)
    # BH：q_i = min_{j>=i} (m / j * p_j) —— 必须自大 p 向小 p 反向累积
    qv = out["perm_p"].to_numpy(float) * m / np.arange(1, m + 1)
    out["q_bh"] = np.minimum.accumulate(qv[::-1])[::-1].clip(max=1.0)
    out["significant_q05"] = out["q_bh"] < 0.05
    out.to_csv(a.out + "fdr_periodic_hosts.csv", index=False)
    summ = dict(candidates=int(len(cand)), tested=int(m),
                sig_q05=int(out["significant_q05"].sum()),
                sig_q05_peak_ge3=int(((out["q_bh"] < 0.05) & (out["peak"] >= out["peak"].median())).sum()),
                n_shuffles=NSHUF,
                note="经验 p 值 = 打乱序列后周期图峰值 ≥ 观测值的比例；BH 校正给 q 值")
    with open(a.out + "fdr_summary.json", "w", encoding="utf-8") as fh:
        json.dump(summ, fh, ensure_ascii=False, indent=1)
    print(json.dumps(summ, ensure_ascii=False, indent=1))
    print(out.head(20).to_string(index=False))


if __name__ == "__main__":
    main()
