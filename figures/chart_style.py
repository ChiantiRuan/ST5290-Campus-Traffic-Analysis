#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""共用绘图样式：调色板、rcParams、脚注与统一的收尾逻辑。

五个出图脚本原先各自复制一份，是"中文串进图"这类 bug 的温床；
现在只有这一处，且 finish() 会在落盘前检查图内是否混入中日韩字符（会渲染成方框）。

用法：
    import chart_style
    from chart_style import NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED, SRC, finish
    chart_style.set_out(OUT); chart_style.use_style()
"""
import textwrap

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NAVY, GREEN, ORANGE, PURPLE, TEAL, GREY, RED = ("#1F4E79", "#375623", "#C55A11", "#7030A0",
                                                "#0E7C7B", "#6B6B6B", "#A61C00")
SRC = ("Source: cap_20260920_111416/112321/112821/113321.pcap (4 files, 17.2 min; two continuous "
       "blocks of 192 s and 842 s). One-way byte convention; loopback and non-IP traffic are handled "
       "per the data-convention note. Time-based statements are limited to those two blocks.")

OUT = None


def set_out(path):
    global OUT
    OUT = path


def use_style():
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["Times New Roman"], "font.size": 11.7, "axes.titlesize": 14.3,
        "svg.fonttype": "none",   # SVG 保留真实文字（默认为 path），便于检索与字体核验
        "axes.edgecolor": "#BBBBBB", "axes.grid": True, "grid.color": "#E6E6E6",
        "grid.linewidth": 0.7, "figure.dpi": 110, "axes.spines.top": False,
        "axes.spines.right": False, "savefig.bbox": "tight",
    })


def _cjk_guard(fig):
    """图内出现中日韩字符就直接报错：DejaVu 无这些字形，会渲染成方框。"""
    bad = set()
    for t in fig.findobj(match=lambda o: hasattr(o, "get_text")):
        bad |= {c for c in t.get_text() if "\u4e00" <= c <= "\u9fff" or "\uff00" <= c <= "\uffef"}
    if bad:
        raise ValueError("图内出现中日韩字符（会渲染成方框）：" + " ".join(sorted(bad)))


def _overlap_report(fig):
    """文字重叠自检：放大字号后若文字挤在一起，这里会报出来（图的排版无法靠肉眼检查）。"""
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    boxes = []
    for t in fig.findobj(match=lambda o: hasattr(o, "get_text")):
        if t.get_text().strip():
            try:
                boxes.append((t.get_text()[:28], t.get_window_extent(renderer=r)))
            except Exception:
                pass
    bad = []
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            a, b = boxes[i][1], boxes[j][1]
            dx = min(a.x1, b.x1) - max(a.x0, b.x0)
            dy = min(a.y1, b.y1) - max(a.y0, b.y0)
            if dx > 0 and dy > 0 and dx * dy > 0.2 * min(a.width * a.height, b.width * b.height):
                bad.append((boxes[i][0], boxes[j][0]))
    if bad:
        print("  !! 文字重叠 %d 对，例如 %s" % (len(bad), bad[:2]))
    return len(bad)


def _all_texts(fig):
    """图内所有文字对象。

    教训：不能手工列举。ax.title 只等于"居中标题"，loc="left" 的标题存在 ax._left_title 里，
    手工枚举会漏掉它们（护栏因此把左对齐标题误判成"压住图形"）。改用 findobj 抓全部 Text。
    """
    from matplotlib.text import Text
    out = list(fig.findobj(match=lambda o: isinstance(o, Text)))
    for lg in list(fig.legends) + [ax.get_legend() for ax in fig.axes]:
        if lg is not None:
            out += list(lg.get_texts())
    seen, uniq = set(), []
    for t in out:
        if id(t) not in seen:
            seen.add(id(t))
            uniq.append(t)
    return uniq


TEXT_INK_MIN = 20          # 文字框内"图形墨迹"像素下限；低于此视为只是相邻、不报警
TEXT_SOLID_FRAC = 0.60     # 墨迹占比 ≥ 此值视为"压在实色填充上"
TEXT_COLOR_STD = 26        # 实色填充内部允许的颜色波动；超过说明跨了两种填充（如标签溢出色块）


def _text_on_graph(fig, dpi=110):
    """量每段文字框内压住了多少图形墨迹（曲线/柱子/散点）。

    做法：把所有文字与网格线隐去后渲染一次，"非近白"像素即图形墨迹；再逐段文字取其包围盒，
    数框内的墨迹像素。曲线/色块穿过文字时框内会有大量墨迹；仅相邻则几乎为 0。
    返回 [(文字, 墨迹像素数), ...]。
    """
    import numpy as _np
    texts = [t for t in _all_texts(fig) if t.get_visible() and t.get_text().strip()]
    if not texts:
        return []
    # 关键：必须在"文字仍可见"时取包围盒——隐藏后 matplotlib 会返回空框 (0,0,1,1)
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    boxes = [(t, t.get_window_extent(renderer=r)) for t in texts]
    vis = [(t, t.get_visible()) for t in _all_texts(fig)]
    grids = []
    for ax in fig.axes:
        # 网格线、边框、刻度线都不是"数据内容"：文字紧贴它们不算重叠（否则图标题会被误报）
        grid = (list(ax.get_xgridlines()) + list(ax.get_ygridlines())
                + list(ax.spines.values()) + list(ax.xaxis.get_ticklines())
                + list(ax.yaxis.get_ticklines()))
        grids += [(g, g.get_visible()) for g in grid]
        for g in grid:
            g.set_visible(False)
    for t in texts:
        t.set_visible(False)
    fig.canvas.draw()
    buf = _np.asarray(fig.canvas.buffer_rgba())[..., :3]
    ink = buf.min(axis=2) < 245
    H = ink.shape[0]
    out = []
    for t, bb in boxes:
        x0, x1 = int(bb.x0) + 2, int(bb.x1) - 2
        y0, y1 = int(bb.y0) + 2, int(bb.y1) - 2
        if x1 <= x0 or y1 <= y0:
            continue
        rows, cols = slice(max(0, H - y1), H - y0), slice(max(0, x0), x1)
        sub = ink[rows, cols]
        n = int(sub.sum())
        if n < TEXT_INK_MIN:
            continue
        area = sub.size
        frac = n / area
        if frac >= TEXT_SOLID_FRAC:
            # 压在实色填充上（白字压色块）：填充颜色均匀 → 正常设计，不报警
            px = buf[rows, cols][sub]
            if px.std(axis=0).max() <= TEXT_COLOR_STD:
                continue
            out.append((t.get_text().replace("\n", " ")[:46], n, "跨色块边界"))
        else:
            out.append((t.get_text().replace("\n", " ")[:46], n, "压在图形上"))
    for t, v in vis:
        t.set_visible(v)
    for g, v in grids:
        g.set_visible(v)
    fig.canvas.draw()
    return sorted(out, key=lambda kv: -kv[1])


def _render_rgb(fig):
    import numpy as _np
    fig.canvas.draw()
    return _np.asarray(fig.canvas.buffer_rgba())[..., :3].copy()


def _text_collisions(fig):
    """像素级检测：文字压住图形、或文字互相压住。

    做法：先把所有文字隐去渲染一层"图形层"；再逐段文字单独显示渲染（每次只留一段），与图形层
    求差即得该段文字的**字形像素**。于是：
      · 字形像素 ∩ 图形墨迹 = 文字压住了曲线/柱子/散点的像素数
      · 字形像素 ∩ 已被其它文字占用的像素 = 两段文字真正重叠的像素数
    这比"包围盒相交"精确得多——相邻刻度标签的框会相交，但字形并不重叠（旧判据的噪声来源）。
    白字压在实色色块上属设计如此：若文字框内图形墨迹占比高且颜色一致，则不计为缺陷。
    """
    import numpy as _np
    # 图例单独成"块"：Legend.draw() 不理会单个文字的 visible，逐字隐去无效（这是此前的盲点）
    legends = [lg for lg in ([ax.get_legend() for ax in fig.axes] + list(fig.legends))
               if lg is not None and lg.get_visible()]
    texts = [t for t in _all_texts(fig) if t.get_visible() and t.get_text().strip()
             and not any(t in lg.get_texts() for lg in legends)]
    if not texts and not legends:
        return []
    vis = ([(t, t.get_visible()) for t in _all_texts(fig)]
           + [(lg, lg.get_visible()) for lg in legends])
    # 关键：轴标题(轴标签)的位置由刻度标签的包围盒决定。逐次隐藏文字会让它在重绘时移位，
    # 与"全文字层"相减就产生幽灵像素（曾把互不相交的刻度标签与轴标题判成重叠 44px）。
    # 先在"全部可见"状态画一次拿到真实布局，再把"轴标签自动定位"临时改成空操作冻结位置。
    fig.canvas.draw()
    import matplotlib.axis as _maxis
    _frozen = []
    for _name in ("_update_label_position", "_update_offset_text_position"):
        for _cls in (_maxis.Axis, _maxis.XAxis, _maxis.YAxis):
            if hasattr(_cls, _name):
                _frozen.append((_cls, _name, getattr(_cls, _name)))
                setattr(_cls, _name, lambda self, renderer, *a, **k: None)
    gg = []
    for ax in fig.axes:
        for g in (list(ax.get_xgridlines()) + list(ax.get_ygridlines()) + list(ax.spines.values())
                  + list(ax.xaxis.get_ticklines()) + list(ax.yaxis.get_ticklines())):
            gg.append((g, g.get_visible()))
            g.set_visible(False)
    for t in texts:
        t.set_visible(False)
    for lg in legends:
        lg.set_visible(False)
    R0 = _render_rgb(fig)
    graph_ink = R0.min(axis=2) < 245
    idmap = _np.zeros(graph_ink.shape, dtype=_np.int32)
    who = _np.zeros(graph_ink.shape, dtype=_np.int32)
    out = []
    items = [(t, t.get_text().replace("\n", " ")[:46]) for t in texts] + \
            [(lg, "[legend]") for lg in legends]
    names = {k + 1: lbl for k, (_, lbl) in enumerate(items)}
    for i, (obj, lbl) in enumerate(items, 1):
        obj.set_visible(True)
        R = _render_rgb(fig)
        obj.set_visible(False)
        mask = _np.abs(R.astype(_np.int16) - R0.astype(_np.int16)).max(axis=2) > 8
        if not mask.any():
            continue
        over_graph = int((mask & graph_ink).sum())
        prev = idmap > 0
        over_text = int((mask & prev).sum())
        others = sorted(set(who[mask & prev].tolist()) - {0})
        ys, xs = _np.nonzero(mask)
        sub_ink = graph_ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
        frac = float(sub_ink.mean()) if sub_ink.size else 0.0
        solid = False
        if frac >= TEXT_SOLID_FRAC:
            px = R0[ys.min():ys.max() + 1, xs.min():xs.max() + 1][sub_ink]
            solid = px.std(axis=0).max() <= TEXT_COLOR_STD
        ys_, xs_ = _np.nonzero(mask)
        bb = (xs_.min(), graph_ink.shape[0] - ys_.max(), xs_.max(), graph_ink.shape[0] - ys_.min())
        if over_text > 12:
            j = others[0] if others else 0
            out.append((lbl, over_text, "压住文字", [names.get(j, "?")], bb, bb))
        elif over_graph > TEXT_INK_MIN and not solid:
            out.append((lbl, over_graph, "压住图形", [], bb, bb))
        idmap[mask] = i
        who[mask & (who == 0)] = i
    for t, v in vis:
        t.set_visible(v)
    for g, v in gg:
        g.set_visible(v)
    for cls, name, orig in _frozen:
        setattr(cls, name, orig)
    fig.canvas.draw()
    return sorted(out, key=lambda r: -r[1])


FOOT_GAP = 0.075          # 脚注与"最低元素（坐标区连同刻度标签）"之间的间隙（占图高比例）


def _lowest_artist_y(fig, r):
    """可见内容的最低 y（显示坐标）：坐标区（含刻度标签、轴标题）+ figure 级图例与其他 figure 文字。

    教训：fig.legend 挂在 figure 上，不在任何坐标区的 tight bbox 里；只算坐标区会把脚注
    放到图例"身上"（fig03 就是这么压住的）。
    """
    ys = []
    for ax in fig.axes:
        if ax.get_visible():
            try:
                ys.append(ax.get_tightbbox(r).y0)
            except Exception:
                pass
    for lg in fig.legends:
        if lg.get_visible():
            try:
                ys.append(lg.get_window_extent(renderer=r).y0)
            except Exception:
                pass
    for t in list(fig.texts) + [getattr(fig, "_suptitle", None)]:
        if t is not None and t.get_visible() and t.get_text().strip():
            try:
                ys.append(t.get_window_extent(renderer=r).y0)
            except Exception:
                pass
    return min(ys) if ys else fig.bbox.y0


def _footnote_overlap(fig, r):
    """脚注与坐标区（含刻度标签）重叠的处数：排版事故，靠加大间距修，不是删数据。"""
    if not fig.texts:
        return 0
    fb = fig.texts[-1].get_window_extent(renderer=r)
    n = 0
    for ax in fig.axes:
        if not ax.get_visible():
            continue
        ab = ax.get_tightbbox(r)
        if min(fb.x1, ab.x1) - max(fb.x0, ab.x0) > 0 and min(fb.y1, ab.y1) - max(fb.y0, ab.y0) > 0:
            n += 1
    return n


def finish(fig, path, note=None):
    """统一收尾：脚注自动避让图形（不再写死 -0.02）、CJK 护栏、重叠自检、落盘 PNG + SVG。"""
    _cjk_guard(fig)
    txt = (note + "\n" if note else "") + SRC
    wrapped = "\n".join(textwrap.wrap(txt, 150, break_long_words=False))
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    # 从"最低元素"再往下让 FOOT_GAP，避免压住刻度标签（fig21/fig22 就是这么被压住的）
    y = (_lowest_artist_y(fig, r) - fig.bbox.y0) / fig.bbox.height - FOOT_GAP
    fig.text(0.005, y, wrapped, fontsize=11, color=GREY, va="top")
    fig.canvas.draw()
    n_foot = _footnote_overlap(fig, r)
    if n_foot:
        print("  !! 脚注压住图形 %d 处（排版需改，不能删数据）" % n_foot)
    for t, n, kind, others, bb, bb2 in _text_collisions(fig):
        print("  !! [%s] %s [%s] %dpx bbox=(%.0f,%.0f,%.0f,%.0f) %s"
              % (path, kind, t, n, bb[0], bb[1], bb[2], bb[3],
                 ("←与 [%s] bbox=(%.0f,%.0f,%.0f,%.0f)" % (others[0], bb2[0], bb2[1], bb2[2], bb2[3]))
                 if others else ""))
    # 旧的包围盒判据噪声大（相邻刻度标签的框会相交），已由 _text_collisions 的像素级判据取代
    n_overlap = 0
    fig.savefig(OUT + path + ".png", dpi=300)
    fig.savefig(OUT + path + ".svg")
    plt.close(fig)
    print("  ->", path)
