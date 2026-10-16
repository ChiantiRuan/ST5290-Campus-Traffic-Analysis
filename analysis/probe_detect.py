#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST5290 检测与聚类分析（probe_detect）：产出报告 4.6 的异常发现清单与 F14 聚类结果。
输入（均在盘上，无需重读原包）：
  data/probe_caliber/per_second_all.csv     全局秒级序列（4 段，1,034 行）
  data/probe_caliber/host_profile_v2_merged.csv  49,560 台主机画像
  data/deep_probe/host_periodicity.csv     主机级周期候选（1,461 行）
  data/probe_caliber/caliber_all_summary.json    规模/端口/接口等汇总

四类检测：
  ① 周期性：全局秒级序列的周期图峰值 vs 打乱基线（置换检验）
  ② 熵：内网主机端口熵分布的双峰性（GMM 1 vs 2 分量 BIC + 双峰系数）
  ③ 变点：全局序列的二值分割（均值结构，置换检验给 p）
  ④ 极值：峰值超阈（POT）+ 广义帕累托拟合（形状/尺度、重现水平）
聚类：内网主机 KMeans（k=2..8 按轮廓系数选），与规则分群交叉表 + ARI
"""
from pathlib import Path
REPO = str(Path(__file__).resolve().parents[1]) + "/"  # 导出后为仓库根目录；脚本位于仓库下一级
import json, os, sys
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.cluster import KMeans
from sklearn.metrics import adjusted_rand_score, silhouette_score
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

P = REPO
CAL = P + "data/probe_caliber/"
P3 = P + "data/probe/"
DP = P + "data/deep_probe/"
OUT = P + "data/detect/"
os.makedirs(OUT, exist_ok=True)
RNG = np.random.default_rng(7)
res = {}

# ---------- ① 周期性（全局秒级）＋ ③ 变点 ＋ ④ 极值 ----------
ps = pd.read_csv(P3 + "per_second_all.csv")
seg_stats, cp_rows, pot_rows = [], [], []
for seg, g in ps.groupby("segment", sort=True):
    x = g.sort_values("unix_sec")["packets"].to_numpy(float)
    n = len(x)
    m, sd = x.mean(), x.std(ddof=1)
    cv = sd / m if m else np.nan
    # 周期图（去掉最低频段：周期 > n/3 视为趋势/假象）
    y = x - x.mean()
    pw = np.abs(np.fft.rfft(y)) ** 2
    pw = pw[1:]
    k_ok = np.arange(1, len(pw) + 1) >= 3           # 周期 <= n/3
    k = int(np.argmax(np.where(k_ok, pw, -1)))
    period, peak = n / (k + 1), float(pw[k])
    null = []
    for _ in range(400):
        z = RNG.permutation(y)
        q = np.abs(np.fft.rfft(z)) ** 2
        qq = q[1:]
        null.append(float(np.max(np.where(np.arange(1, len(qq) + 1) >= 3, qq, -1))))
    p_perm = float((np.sum(np.array(null) >= peak) + 1) / (len(null) + 1))
    seg_stats.append(dict(segment=seg, seconds=n, mean_pps=round(m, 1), cv=round(cv, 3),
                          period_s=round(period, 1), peak_over_median=round(peak / np.median(pw[k_ok]), 1),
                          perm_p=p_perm))
    # 变点：二值分割（均值），候选点用置换检验给 p
    best = (0.0, None)
    for c in range(int(n * 0.15), int(n * 0.85)):
        d = abs(x[:c].mean() - x[c:].mean()) * np.sqrt(c * (n - c) / n)
        if d > best[0]:
            best = (d, c)
    d_obs, c_obs = best
    null = [max(abs(x[:c].mean() - x[c:].mean()) * np.sqrt(c * (n - c) / n)
                for c in [RNG.integers(int(n * 0.15), int(n * 0.85))]) for _ in range(400)]
    p_cp = float((np.sum(np.array(null) >= d_obs) + 1) / (len(null) + 1))
    cp_rows.append(dict(segment=seg, changepoint_sec=c_obs, split_ratio=round(c_obs / n, 2),
                        stat=round(d_obs, 2), perm_p=p_cp,
                        mean_before=round(x[:c_obs].mean(), 1), mean_after=round(x[c_obs:].mean(), 1)))
    # POT：超 90 分位为峰，拟合 GPD
    u = np.percentile(x, 90)
    exc = x[x > u] - u
    if len(exc) >= 20:
        xi, loc, sig = stats.genpareto.fit(exc, floc=0)
        # 重现水平：ξ→0 用指数极限，ξ≠0 用 GPD 公式（N 个"区块"= 每段秒数）
        ratio = 10 * len(x) / len(exc)
        rl = float(u + sig * np.log(ratio)) if abs(xi) < 0.01 else \
            float(u + sig / xi * (ratio ** xi - 1))
        pot_rows.append(dict(segment=seg, threshold=round(float(u), 1), n_exceed=len(exc),
                             xi=round(float(xi), 3), sigma=round(float(sig), 1),
                             max_over_threshold=round(float(exc.max()), 1),
                             tail_type="有界（ξ<0）" if xi < -0.01 else ("指数型（ξ≈0）" if abs(xi) <= 0.01 else "重尾（ξ>0）"),
                             return_level_1in10s=round(rl, 1)))
res["segment_time"] = seg_stats
res["changepoints"] = cp_rows
res["pot"] = pot_rows
pd.DataFrame(seg_stats).to_csv(OUT + "segment_time_stats.csv", index=False)
pd.DataFrame(cp_rows).to_csv(OUT + "changepoints.csv", index=False)
pd.DataFrame(pot_rows).to_csv(OUT + "pot.csv", index=False)

# ---------- ② 熵的双峰性 ----------
hp = pd.read_csv(CAL + "host_profile_v2_merged.csv")
int_hosts = hp[hp["class"] == "int"].copy()
e = int_hosts["port_entropy_norm"].dropna().to_numpy()
bc = float((stats.skew(e) ** 2 + 1) / stats.kurtosis(e, fisher=False))
bic = {}
for k_ in (1, 2, 3):
    gm = GaussianMixture(k_, n_init=5, random_state=0).fit(e.reshape(-1, 1))
    bic[k_] = float(gm.bic(e.reshape(-1, 1)))
res["entropy_bimodality"] = dict(n=len(e), mean=round(float(e.mean()), 3), median=round(float(np.median(e)), 3),
                                 pct_zero=round(float((e == 0).mean()) * 100, 1),
                                 bimodality_coefficient=round(bc, 3),
                                 bic={str(k): round(v, 1) for k, v in bic.items()},
                                 best_k=int(min(bic, key=bic.get)))

# ---------- 聚类（内网主机）----------
f = int_hosts.copy()
f["log_bytes"] = np.log10(f["total_bytes"].clip(lower=1))
X = f[["log_bytes", "peers", "ports", "port_entropy_norm", "bytes_per_pkt"]].fillna(0).to_numpy(float)
Xs = StandardScaler().fit_transform(X)
sil, models = {}, {}
for k in range(2, 9):
    km = KMeans(n_clusters=k, n_init=10, random_state=0).fit(Xs)
    lab = km.labels_
    sil[k] = float(silhouette_score(Xs, lab)) if len(set(lab)) > 1 else np.nan
    models[k] = km
_best = max([k for k in sil if not np.isnan(sil[k])], key=lambda k: sil[k])
best_k = min([k for k in sil if not np.isnan(sil[k]) and sil[k] >= sil[_best] - 0.01])  # 简约：并列取最小 k
lab = models[best_k].labels_
f["cluster"] = lab
# 规则分群（与画像 v1 同口径：大流量=total_bytes ≥ 内网 P90；交互广=端口≥50 且 对端≥20）
big = f["total_bytes"] >= f["total_bytes"].quantile(0.90)
wide = (f["ports"] >= 50) & (f["peers"] >= 20)
f["rule_group"] = np.where(big & wide, "服务型",
                           np.where(~big & wide, "交互型",
                                    np.where(big & ~wide, "传输型", "低频型")))
ct = pd.crosstab(f["rule_group"], f["cluster"])
ct.to_csv(OUT + "cluster_vs_rule_crosstab.csv")
res["clustering"] = dict(k=int(best_k), silhouette={str(k): round(v, 3) for k, v in sil.items()},
                         sizes={str(k): int(v) for k, v in pd.Series(lab).value_counts().sort_index().items()},
                         rule_sizes={k: int(v) for k, v in f["rule_group"].value_counts().items()},
                         ari_vs_rule=round(float(adjusted_rand_score(f["rule_group"], lab)), 3))
f[["ip", "class", "rule_group", "total_bytes", "peers", "ports", "port_entropy_norm",
   "bytes_per_pkt", "cluster"]].to_csv(OUT + "cluster_points.csv", index=False)
pd.DataFrame({"k": list(sil), "silhouette": [round(sil[k], 3) for k in sil]}).to_csv(OUT + "cluster_silhouette.csv", index=False)

# ---------- 主机级周期候选（FDR）----------
per = pd.read_csv(DP + "host_periodicity.csv")
per["fake_long"] = per["top_period_s"] >= 150
real = per[~per["fake_long"]].copy()
real["strong"] = (real["peak_vs_random"] >= 3) & (real["top_period_s"].between(2, 60))
res["host_periodicity"] = dict(rows_total=int(len(per)), rows_after_filter=int(len(real)),
                               strong=int(real["strong"].sum()),
                               strong_peak5=int(((real["peak_vs_random"] >= 5) & real["strong"]).sum()),
                               note="峰值=观测周期图峰值 / 80 次打乱基线第 95 百分位；>1 即在 5% 水平上高于随机")
real.sort_values("peak_vs_random", ascending=False).head(100).to_csv(OUT + "periodic_hosts_top100.csv", index=False)

with open(OUT + "detect_summary.json", "w", encoding="utf-8") as fh:
    json.dump(res, fh, ensure_ascii=False, indent=1, default=str)

print(json.dumps(res, ensure_ascii=False, indent=1, default=str)[:3000])
