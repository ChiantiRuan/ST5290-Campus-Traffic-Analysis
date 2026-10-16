#!/bin/bash
# 出图唯一检查入口（合并了原先重复的两份：字形/CJK + 字体）
#   ① 每个出图脚本 exit=0   ② 无缺字告警   ③ 无"脚注压住图形"告警
#   ④ SVG 内无 CJK          ⑤ 图内字体只声明 Times New Roman
# 任一不满足 → 退出码 1（供后续脚本/CI 判成败）
cd "$(dirname "$0")" || exit 1
PY="${PY:-python3}"
fail=0
for s in gen_charts_batch1.py gen_charts_batch2.py gen_charts_batch3.py gen_charts_batch4.py gen_charts_batch5.py; do
    $PY "$s" > "/tmp/ch_$s.log" 2>&1
    code=$?
    glyph=$(grep -ci glyph "/tmp/ch_$s.log")
    foot=$(grep -c "脚注压住图形" "/tmp/ch_$s.log")
    over=$(grep -cE "压住图形|压住文字" "/tmp/ch_$s.log")
    echo "$s: exit=$code  缺字告警=$glyph  脚注压图=$foot  文字压图=$over"
    if [ $code -ne 0 ] || [ "$glyph" -ne 0 ] || [ "$foot" -ne 0 ] || [ "$over" -ne 0 ]; then fail=1; fi
done
cd output || exit 1
$PY - <<'PY'
import glob, os
svgs = sorted(glob.glob("*.svg"))
cjk_bad, font_bad = [], []
for f in svgs:
    t = open(f, encoding="utf-8").read()
    if any("\u4e00" <= c <= "\u9fff" or "\uff00" <= c <= "\uffef" for c in t):
        cjk_bad.append(f)
    if "Times New Roman" not in t or "DejaVu" in t:
        font_bad.append(f)
print("SVG %d 张 | PNG %d 张 | CJK 残留 %d 张 | 字体异常 %d 张"
      % (len(svgs), len(glob.glob("*.png")), len(cjk_bad), len(font_bad)))
print("  字体检查: %d/%d 张声明 Times New Roman" % (len(svgs) - len(font_bad), len(svgs)))
print("  异常清单:", (cjk_bad + font_bad) or "无")
raise SystemExit(1 if (cjk_bad or font_bad or len(svgs) != 24) else 0)
PY
[ $? -ne 0 ] && fail=1
[ $fail -eq 0 ] && echo "出图检查：全部通过" || echo "出图检查：存在问题（见上）"
exit $fail
