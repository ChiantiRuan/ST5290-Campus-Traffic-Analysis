#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按"两个连续观测段"口径重算秒级时间统计。

背景：`probe_detect.py` 当初按"四个采集文件"分段计算（CV 0.163/0.142/0.199/0.195）。
后来确认文件 2/3/4 首尾相接（11:28:20.995 → 11:33:20.994），四个文件实为两个连续观测段：
    block1 = 111416                    192 秒
    block2 = 112321 + 112821 + 113321   842 秒（中间无缺口）
本脚本沿用 probe_detect.py 的同一套方法（FFT 周期图、周期 ≤ n/3、各 400 次置换），
在修正口径下重算，写到 data/deep2/block_stats.json 供报告正文引用。

用法：~/miniconda3/envs/dsaproject/bin/python probe_blocks.py
"""
import json
import os

import numpy as np
import pandas as pd
from scipy import stats as sps

P = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")) + "/"
P3, OUT = P + "data/probe/", P + "data/deep2/"
RNG = np.random.default_rng(7)                 # 与 probe_detect.py 同种子，结果可复现
BLOCKS = {"block1": [111416], "block2": [112321, 112821, 113321]}
N_PERM = 400                                   # 置换次数（沿用 probe_detect.py）


def _periodogram(y):
    """谱峰值与随机基线中位水平。只取周期 ≤ n/3 的频点，避免把趋势当周期。"""
    pw = (np.abs(np.fft.rfft(y)) ** 2)[1:]
    ok = np.arange(1, len(pw) + 1) >= 3
    return pw, ok


def _peak(pw, ok):
    return float(np.max(np.where(ok, pw, -1)))


def seg_stats(x):
    """CV、周期图主峰、峰/中位比、置换 p（与 probe_detect.py 同法）。"""
    n, m, sd = len(x), x.mean(), x.std(ddof=1)
    pw, ok = _periodogram(x - m)
    k = int(np.argmax(np.where(ok, pw, -1)))
    peak = float(pw[k])
    null = np.array([_peak(*_periodogram(RNG.permutation(x - m))) for _ in range(N_PERM)])
    return dict(seconds=n, mean_pps=round(float(m), 1), cv=round(float(sd / m), 3),
                period_s=round(n / (k + 1), 1),
                peak_over_median=round(peak / float(np.median(pw[ok])), 1),
                perm_p=float(((null >= peak).sum() + 1) / (N_PERM + 1)))


def _split_stat(x, c):
    """二值分割的均值差统计量。"""
    return abs(x[:c].mean() - x[c:].mean()) * np.sqrt(c * (len(x) - c) / len(x))


def changepoint(x):
    n = len(x)
    lo, hi = int(n * 0.15), int(n * 0.85)
    c_obs = max(range(lo, hi), key=lambda c: _split_stat(x, c))
    d_obs = _split_stat(x, c_obs)
    null = np.array([_split_stat(x, int(RNG.integers(lo, hi))) for _ in range(N_PERM)])
    before, after = float(x[:c_obs].mean()), float(x[c_obs:].mean())
    return dict(changepoint_sec=int(c_obs), perm_p=float(((null >= d_obs).sum() + 1) / (N_PERM + 1)),
                mean_before=round(before, 1), mean_after=round(after, 1),
                delta_pct=round(abs(after - before) / before * 100, 1))


def pot_row(seg, x):
    """POT：超 90 分位为峰，拟合 GPD，给 10 秒一遇重现水平。"""
    u = np.percentile(x, 90)
    exc = x[x > u] - u
    if len(exc) < 20:
        return None
    xi, _, sig = sps.genpareto.fit(exc, floc=0)
    n_blocks = 10 * len(x) / len(exc)               # 每 10 个超阈事件算一个"区块"
    level = u + sig * np.log(n_blocks) if abs(xi) < 1e-6 else u + sig / xi * (n_blocks ** xi - 1)
    return dict(segment=int(seg), xi=round(float(xi), 3),
                return_level_1in10s=round(float(level), 1), tail_bounded=bool(xi < 0))


def main():
    ps = pd.read_csv(P3 + "per_second_all.csv")
    res = {"note": "按两个连续观测段重算（原 probe_detect.py 为四文件口径）", "blocks": {}}
    for name, segs in BLOCKS.items():
        g = ps[ps["segment"].isin(segs)].sort_values("unix_sec")
        x = g["packets"].to_numpy(float)
        res["blocks"][name] = dict(files=segs, span_unix=[int(g["unix_sec"].min()), int(g["unix_sec"].max())],
                                   **seg_stats(x), changepoint=changepoint(x))
    b1, b2 = res["blocks"]["block1"], res["blocks"]["block2"]
    res["gap_seconds"] = b2["span_unix"][0] - b1["span_unix"][1] - 1
    res["total_seconds"] = b1["seconds"] + b2["seconds"]
    res["pot_per_file"] = [r for seg, g in ps.groupby("segment", sort=True)
                           if (r := pot_row(seg, g.sort_values("unix_sec")["packets"].to_numpy(float)))]

    os.makedirs(OUT, exist_ok=True)
    with open(OUT + "block_stats.json", "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)

    for k, v in res["blocks"].items():
        print(f"{k}: {v['seconds']} 秒 | 文件 {v['files']} | 均值 {v['mean_pps']} pps | CV {v['cv']} | "
              f"主周期 {v['period_s']} 秒 | 峰/中位 {v['peak_over_median']} | 置换 p {v['perm_p']:.4f}")
    print(f"两段间隔 {res['gap_seconds']} 秒 | 合计 {res['total_seconds']} 秒 = {res['total_seconds'] / 60:.1f} 分钟")
    print("变点：", {k: (v["changepoint"]["changepoint_sec"], v["changepoint"]["delta_pct"]) for k, v in res["blocks"].items()})
    print("极值（按文件）：ξ 全部 < 0 =", all(p["tail_bounded"] for p in res["pot_per_file"]),
          "| 1-in-10s 重现水平", sorted(p["return_level_1in10s"] for p in res["pot_per_file"]))
    print("写出:", OUT + "block_stats.json")


if __name__ == "__main__":
    main()
