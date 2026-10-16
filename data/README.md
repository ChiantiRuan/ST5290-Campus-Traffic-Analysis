# data/：派生数据说明

这里放的是**出图脚本直接读取的数据**：从原始抓包（4 个文件、36.2 GB、6,870 万包）聚合出来的
统计表。原始抓包不分发，因此这些表是复现图表所需的全部输入（合计约 3.6 MB）。

## 目录与文件

| 路径 | 内容 | 服务于 |
|---|---|---|
| `probe/per_second_all.csv` | 全局秒级序列（秒级包数/字节数，1,034 行 = 两个观测段） | 时间类全部图（F1、F10、F12、F15） |
| `probe/cap_*/probe_summary.json` | 每个采集文件的总体摘要（包数、字节、时长） | 一致性对照 |
| `probe/cap_*/pktlen_hist.csv` | 每个采集文件的包长分布 | F1b |
| `probe_caliber/caliber_all_summary.json` | 口径确认结果（接口数、方向拆分、网段归类等） | F2、F5、F9 |
| `probe_caliber/host_profile_v2_merged.csv` | **主机级**画像（每主机收发包、字节、对端数、端口数、端口熵） | F6、F7、F16 |
| `probe_caliber/cap_*/caliber_summary.json` | 每个文件的口径摘要 | 对照 |
| `deep_probe/domains_top.csv` | 出现频次最高的名称/端点（DNS 名、SNI、字面 IP） | F19 |
| `deep_probe/initiator_matrix.csv` | 会话发起方 → 响应方矩阵（会话数、字节） | F21 |
| `deep2/session2_summary.json` | 会话级汇总（会话数、时长分箱、字节集中度等） | F20、F22 |
| `deep2/session_bytes_dist.csv` | 会话字节量级分布 | F22 |
| `deep2/session_bytes_lorenz.csv` | 会话字节洛伦兹曲线坐标 | F22 |
| `deep2/fdr_periodic_hosts.csv` | **主机级**周期候选（周期、峰值倍数、经验 p、BH-FDR q） | F23 |
| `detect/detect_summary.json` | 四类检测（周期性、端口熵、变点、极值）的汇总 | F8、F18 |
| `detect/cluster_points.csv` | **主机级**行为特征与聚类标签（k=4 vs 规则分群） | F14 |
| `detect/changepoints.csv` | 检出的变点（位置、幅度、p 值） | F18 |
| `detect/pot.csv` | 极值分析（阈值、形状参数、重现水平） | F18 |

## 口径提醒

* **单向字节口径**；回环与非 IP 流量按《数据口径定义书》处理。
* 时间类结论**只在两个连续观测段内**成立（192 秒 + 842 秒，合计 17.2 分钟）。
* 每张图的标题/图注都写明分母（包数、字节、主机数还是会话数）。
* 网段性质由**抽样**（DNS/SNI 名称）判定；`/24` 只是"外部单位"的近似，不等于一台主机、更不等于一个人。

## 关于地址（隐私）

三张表含抓包中观察到的 IP 地址：`probe_caliber/host_profile_v2_merged.csv`（49,560 台主机）、
`detect/cluster_points.csv`（5,223 台内网主机）、`deep2/fdr_periodic_hosts.csv`（945 台主机）；
`deep_probe/domains_top.csv` 与 `probe_caliber/caliber_all_summary.json` 含少量地址。图表中也有
5 张印出了具体地址（F7、F9、F17、F19、F23）。

保留原地址是为了让图表**逐字节复现**。若需要不含地址的版本，运行：

```bash
python tools/anonymize_data.py      # 生成 data_anonymized/（伪名化副本，原表不动）
```

用伪名数据重出的图在**聚合图上与发布版一致**，只有印出具体地址的那 5 张会显示伪名。

## 重新生成

这些表由 `analysis/` 下的脚本从原始抓包生成（脚本头部写明了各自的输入与用法）。
没有原始抓包时，只能用本目录的数据复现图表（`bash figures/check_charts.sh`）。
