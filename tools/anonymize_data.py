#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 data/ 里的 IP 地址替换成稳定伪名，生成 data_anonymized/（原表不动）。

为什么需要：复现图表要求原表逐字节一致，但原表含抓包中观察到的地址。
本工具给出一条"可分享"的路径：伪名化副本仍能跑出同样的聚合图，只是把地址换成 h_int_XXXX / h_ext_XXXX。

规则
  · 内网段（10./172.16-31./192.168./127.）→ h_int_XXXX
  · 其他（公网、多播）                    → h_ext_XXXX
  · 编号按地址字典序稳定分配：同一份输入永远得到同一份映射
  · 只替换文本中的地址，不动其它内容；结构与文件名保持一致

用法：python tools/anonymize_data.py
输出：data_anonymized/（已列入 .gitignore，不会被误提交）
"""
import ipaddress
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC, DST = REPO / "data", REPO / "data_anonymized"
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback


def build_map(texts):
    """按字典序给所有出现过的地址分配稳定伪名。"""
    ips = sorted({ip for t in texts for ip in IPV4.findall(t)})
    m, ni, ne = {}, 0, 0
    for ip in ips:
        if is_internal(ip):
            ni += 1
            m[ip] = "h_int_%04d" % ni
        else:
            ne += 1
            m[ip] = "h_ext_%05d" % ne
    return m


def main():
    files = sorted(p for p in SRC.rglob("*") if p.is_file())
    texts = {p: p.read_text(encoding="utf-8", errors="replace") for p in files}
    m = build_map(texts.values())
    for p, t in texts.items():
        out = DST / p.relative_to(SRC)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(IPV4.sub(lambda x: m[x.group(0)], t), encoding="utf-8")
    left = sum(len(IPV4.findall((DST / p.relative_to(SRC)).read_text(encoding="utf-8")))
               for p in files if p.suffix in (".csv", ".json", ".txt"))
    print("伪名化完成 →", DST)
    print("  地址映射 %d 个（内网 %d / 其它 %d）" %
          (len(m), sum(1 for v in m.values() if v.startswith("h_int")),
           sum(1 for v in m.values() if v.startswith("h_ext"))))
    print("  文件 %d 个；伪名化后残留可识别地址 %d 个（应为 0）" % (len(files), left))
    if left:
        raise SystemExit("仍有地址残留，请检查非 CSV/JSON 的二进制或嵌套格式")


if __name__ == "__main__":
    main()
