# What a Campus Network Actually Looks Like: Traffic Composition, Concentration and Short-Window Stability
ST5290 Data Science Industry Project · Zhejiang SuanWangYun Intelligent Technology Co., Ltd.

Statistical analysis of a single packet-capture session taken at the core collection point of an
enterprise campus network. The work characterises what the traffic *is* (composition, concentration,
who talks to whom), how it behaves *over time*, and which deviations are worth following up.

This repository contains the analysis code, the plotting code and the complete figure set
(PNG + SVG). The written report is submitted separately and is **not** part of this repository.

## What was analysed

| Item | Value |
|---|---|
| Captures | 4 files (`cap_20260920_111416/112321/112821/113321.pcap`) |
| Volume | 36.2 GB, 68.7 M packets (68,696,735) |
| Effective window | two continuous blocks, 192 s + 842 s = 17.2 min (files 2-4 run end to end) |
| Hosts | 49,560 (5,223 inside + 44,335 external peers + 2 loopback) |
| Sessions (>=2 packets) | 693,484 |
| Byte convention | one-way; loopback and non-IP traffic handled per the data-convention note |

## Main results

* **Direction.** The network is receive-dominant: inbound bytes are 3.64x outbound (21.63 GB vs 5.95 GB),
  while packet counts in the two directions are nearly symmetric (0.93x).
* **Concentration.** Traffic is extremely head-heavy. Host-level Gini is 0.982, the top 1% of hosts carry
  81.6% of one-way bytes and the top 100 hosts alone carry 59.9%; at session level the Gini is 0.97.
* **Structure.** Inside hosts fall into four roles (serving 478, interactive 772, bulk 45, low-volume
  3,928); 478 serving hosts carry 72.2% of inside bytes. Outward traffic presents an encrypted service
  face (outbound packets on port 443 run 5,317x inbound).
* **Time.** Within the window the load is stable - CV 0.163 (block 1) and 0.186 (block 2), dominant
  periods of 21.3 s and 40.1 s, significant change steps of only 9.5% and 10.2%, and a bounded upper
  tail (negative shape parameter in all four files).
* **Anomaly leads.** Ten candidates were collected; none satisfies all three promotion conditions
  (statistical significance, a false-positive assessment, comparison against comparable hosts), so all
  remain leads rather than confirmed anomalies.

## Repository layout

```
analysis/          analysis code (reads the raw captures; see "Running the analysis")
figures/           plotting code + check_charts.sh
  chart_style.py     shared style: palette, fonts, footnotes, output paths, guards
  gen_charts_batch1-5.py
  output/            24 figures as PNG (300 dpi) and SVG
data/              derived tables the figures are built from (~3.6 MB) + data/README.md
                   (figures/output/ also holds chart_data_f19_categories.csv, the small table the F19
                   note refers to)
tools/             helper utilities (anonymize_data.py)
requirements.txt   Python dependencies
```

### Figures

| File | Shows |
|---|---|
| `fig01_capture_window` | capture window: two continuous blocks and the gap between them |
| `fig01b_pktlen` | packet-length distribution |
| `fig02_protocol_ports` | protocol mix and top ports |
| `fig03_direction` | direction of traffic: bytes vs packets |
| `fig04_port_direction_heat` | port x direction heat map |
| `fig05_ifindex` | traffic per capture interface |
| `fig06_host_lorenz` | host-level Lorenz curve and cumulative share (Gini 0.982) |
| `fig07_outlier_scatter` | peers vs ports per host, with the single out-of-range host |
| `fig08_entropy_hist` | destination-port entropy distribution |
| `fig09_segment_behaviour` | behaviour by segment role |
| `fig10_series_level` | second-level load series with rolling mean |
| `fig11_periodogram` | periodogram against the shuffled baseline |
| `fig12_band` | residual band after trend removal |
| `fig13_pipeline` | analysis pipeline (four steps) |
| `fig14_clusters` | k-means clusters vs the rule-based grouping |
| `fig15_file_consistency` | consistency across the four capture files |
| `fig16_client_blocks` | concentration of external /24 blocks |
| `fig17_port_groups` | the three fixed port groups |
| `fig18_changepoints_pot` | change points and extreme-value levels |
| `fig19_service_profile` | what the network talks to (name categories) |
| `fig20_session_duration` | session-duration distribution |
| `fig21_initiator_matrix` | initiators vs responders |
| `fig22_session_concentration` | session-level Lorenz and size distribution |
| `fig23_periodic_hosts` | host-level periodicity: period vs peak strength |

## Data

The raw captures are **not** redistributed: they are 36.2 GB and consist of the organisation's own
network traffic. The derived tables that the figures are generated from are included instead, so the
whole figure set can be rebuilt without the captures.

Two of those tables are host-level (`data/probe_caliber/host_profile_v2_merged.csv`,
`data/detect/cluster_points.csv`) and therefore contain IP addresses observed in the capture, as do
a few summary files and five figures that label specific addresses. They are included so that the
figure set reproduces exactly as published; if you need a version without addresses, run
`python tools/anonymize_data.py`, which writes a pseudonymised copy of `data/` to `data_anonymized/`.
See `data/README.md`.

## Running the figures

The figure pipeline is self-contained - it needs only `data/` and `figures/`.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
bash figures/check_charts.sh        # regenerates all 24 figures into figures/output/
```

`check_charts.sh` rebuilds every figure and then verifies three properties of the output: no missing
glyph warnings, no CJK characters inside the SVGs (they would render as boxes with the Times New Roman
label fonts), and every SVG declaring Times New Roman only.

## Running the analysis

The scripts in `analysis/` read the raw captures and write the derived tables into `data/`. They
require the pcap files, which are not distributed here; each script documents its own inputs at the
top. They are kept in the repository so that the path from raw packets to every published number is
visible and auditable.

## Conventions

* **One-way byte convention**; loopback traffic, non-IP traffic and cross-interface duplicates are
  handled as described in the report's data section.
* **Time-based statements** hold only inside the two continuous blocks (192 s + 842 s).
* **Every caption states its denominator** (packets, bytes, hosts or sessions), because the choice of
  denominator changes the answer.
* Segment character is inferred from sampled names (DNS/SNI), and `/24` blocks are an approximation of
  an external unit, not a host and not a person.

## Tools and fonts

Python 3.13 with numpy, pandas, matplotlib, scipy, scikit-learn and statsmodels (see
`requirements.txt`). Figures use Times New Roman throughout and are emitted as PNG (300 dpi) and SVG
with real text (searchable, not outlined).

## Attribution

Analysis performed on a capture of a single campus network as part of the ST5290 project; the network
belongs to its operator and the data is not redistributed. If you reuse this code, please keep the
conventions above intact.
