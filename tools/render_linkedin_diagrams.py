#!/usr/bin/env python3
"""Render CYVIDIA LinkedIn flowchart JPEGs (no Mermaid runtime required)."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1]
BG = (248, 249, 251)
INK = (24, 28, 36)
MUTED = (90, 98, 110)
LINE = (55, 65, 80)
ATTACK = (185, 48, 48)
TOOLKIT = (180, 100, 30)
DEFEND = (37, 99, 200)
OK = (22, 140, 70)
CARD = (255, 255, 255)
BORDER = (30, 34, 42)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def text_size(draw: ImageDraw.ImageDraw, text: str, fnt) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0], box[3] - box[1]


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt, max_w: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        trial = (cur + " " + w).strip()
        if text_size(draw, trial, fnt)[0] <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [text]


def rounded(draw: ImageDraw.ImageDraw, xy, fill, outline, radius=14, width=2):
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def node(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    w: int,
    h: int,
    title: str,
    subtitle: str | None,
    accent: tuple[int, int, int],
    title_f,
    sub_f,
):
    fill = tuple(int(CARD[i] * 0.92 + accent[i] * 0.08) for i in range(3))
    rounded(draw, (x, y, x + w, y + h), fill=fill, outline=BORDER, radius=14, width=2)
    draw.rectangle((x, y, x + 8, y + h), fill=accent)
    pad = 18
    max_w = w - pad * 2 - 4
    t_lines = wrap(draw, title, title_f, max_w)
    ty = y + 14
    for line in t_lines:
        draw.text((x + pad, ty), line, font=title_f, fill=INK)
        ty += text_size(draw, line, title_f)[1] + 2
    if subtitle:
        for line in wrap(draw, subtitle, sub_f, max_w):
            draw.text((x + pad, ty + 4), line, font=sub_f, fill=MUTED)
            ty += text_size(draw, line, sub_f)[1] + 2
    return x, y, w, h


def center(box):
    x, y, w, h = box
    return x + w // 2, y + h // 2


def arrow(draw: ImageDraw.ImageDraw, x1, y1, x2, y2, color=LINE, width=3):
    draw.line((x1, y1, x2, y2), fill=color, width=width)
    # arrowhead
    import math

    ang = math.atan2(y2 - y1, x2 - x1)
    size = 12
    left = (x2 - size * math.cos(ang - 0.45), y2 - size * math.sin(ang - 0.45))
    right = (x2 - size * math.cos(ang + 0.45), y2 - size * math.sin(ang + 0.45))
    draw.polygon([(x2, y2), left, right], fill=color)


def title_block(draw, text, sub, w, title_f, sub_f):
    draw.text((40, 28), text, font=title_f, fill=INK)
    draw.text((40, 72), sub, font=sub_f, fill=MUTED)
    draw.line((40, 104, w - 40, 104), fill=(220, 224, 230), width=2)


def save(img: Image.Image, name: str):
    path = OUT / name
    img.convert("RGB").save(path, "JPEG", quality=92, optimize=True)
    print(f"wrote {path} ({path.stat().st_size} bytes)")


def render_components():
    W, H = 1600, 980
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    tf, sf, hf, hs = font(22, True), font(16), font(34, True), font(18)
    title_block(d, "SANSAR modular cast", "Component diagram for workshops", W, hf, hs)

    boxes = {}
    y0 = 140
    boxes["ray"] = node(d, 40, y0, 220, 88, "Ray Jobs API", "unauthenticated entry", ATTACK, tf, sf)
    boxes["shell"] = node(d, 320, y0, 260, 88, "Reverse shell + SSH key", "Ray session account", ATTACK, tf, sf)
    boxes["root"] = node(d, 640, y0, 230, 88, "Root on GPU host", "privilege after shell", ATTACK, tf, sf)

    y1 = 320
    boxes["stage"] = node(d, 40, y1, 250, 88, "/opt/vadi_/ stage", "toolkit drop", TOOLKIT, tf, sf)
    boxes["sansar"] = node(d, 360, y1, 250, 88, "sansar orchestrator", "Rust client over Tor", TOOLKIT, tf, sf)
    boxes["rk"] = node(d, 680, y1, 280, 88, "acpi_thermal_mgr.ko", "ftrace rootkit", TOOLKIT, tf, sf)
    boxes["netns"] = node(d, 1040, y1, 280, 88, "netns + Ethereum C2", "systemd backdoor", TOOLKIT, tf, sf)

    y2 = 520
    boxes["kurt"] = node(d, 80, y2, 220, 88, "kurt / XMRig", "CPU miner", TOOLKIT, tf, sf)
    boxes["tilki"] = node(d, 340, y2, 240, 88, "tilki / SRBMiner", "GPU miner", TOOLKIT, tf, sf)
    boxes["lyre"] = node(d, 620, y2, 240, 88, "lyrebird / Tor PT", "transport cover", TOOLKIT, tf, sf)
    boxes["nvml"] = node(d, 900, y2, 260, 88, "NVML wrapper 0%", "falsifies nvidia-smi", TOOLKIT, tf, sf)

    y3 = 720
    boxes["hide"] = node(d, 520, y3, 260, 88, "Hidden procs / files", "runtime lie", ATTACK, tf, sf)
    boxes["dash"] = node(d, 820, y3, 280, 88, "nvidia-smi idle lie", "dashboards smile", ATTACK, tf, sf)
    boxes["steal"] = node(d, 200, y3, 250, 88, "Stolen GPU/CPU cycles", "attacker payout", ATTACK, tf, sf)

    def link(a, b, color=LINE, from_side="right", to_side="left"):
        ax, ay, aw, ah = boxes[a]
        bx, by, bw, bh = boxes[b]
        if from_side == "right":
            x1, y1 = ax + aw, ay + ah // 2
        elif from_side == "bottom":
            x1, y1 = ax + aw // 2, ay + ah
        else:
            x1, y1 = ax + aw // 2, ay
        if to_side == "left":
            x2, y2 = bx, by + bh // 2
        elif to_side == "top":
            x2, y2 = bx + bw // 2, by
        else:
            x2, y2 = bx + bw // 2, by + bh
        arrow(d, x1, y1, x2, y2, color=color)

    link("ray", "shell", ATTACK)
    link("shell", "root", ATTACK)
    link("root", "stage", TOOLKIT, "bottom", "top")
    link("root", "rk", TOOLKIT, "bottom", "top")
    link("root", "netns", TOOLKIT, "bottom", "top")
    link("stage", "sansar", TOOLKIT)
    link("sansar", "kurt", TOOLKIT, "bottom", "top")
    link("sansar", "tilki", TOOLKIT, "bottom", "top")
    link("sansar", "lyre", TOOLKIT, "bottom", "top")
    link("sansar", "nvml", TOOLKIT, "bottom", "top")
    link("kurt", "steal", ATTACK, "bottom", "top")
    link("tilki", "steal", ATTACK, "bottom", "top")
    link("rk", "hide", ATTACK, "bottom", "top")
    link("nvml", "dash", ATTACK, "bottom", "top")

    # legend
    d.text((40, 900), "Red = attacker path   Orange = toolkit on host", font=sf, fill=MUTED)
    save(img, "linkedin-cyvidia-diagram-components.jpg")


def render_threat():
    W, H = 1100, 1600
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    tf, sf, hf, hs = font(24, True), font(17), font(34, True), font(18)
    title_block(d, "SANSAR threat chain", "How the intrusion works", W, hf, hs)

    steps = [
        ("1  Internet attacker", "external probes begin", ATTACK),
        ("2  Unauthenticated Ray job agent", "Jobs API reachable", ATTACK),
        ("3  nvidia-smi inventory exfil", "GPU inventory outbound", ATTACK),
        ("4  Python reverse shell", "under Ray session account", ATTACK),
        ("5  SSH key persistence", "authorized_keys planted", ATTACK),
        ("6  Root + toolkit stage", "/opt/vadi_/ deployed", TOOLKIT),
        ("7  NVML + rootkit + miners", "conceal and monetize", TOOLKIT),
        ("8  netns + Ethereum lookup", "alternate C2 discovery", TOOLKIT),
        ("9  Dashboards show 0% busy", "NVML idle lie", ATTACK),
        ("10  Power bill and heat disagree", "truth outside nvidia-smi", ATTACK),
    ]

    boxes = []
    x, y, w, h = 180, 130, 740, 96
    for title, sub, accent in steps:
        boxes.append(node(d, x, y, w, h, title, sub, accent, tf, sf))
        y += h + 36

    for i in range(len(boxes) - 1):
        ax, ay, aw, ah = boxes[i]
        bx, by, bw, bh = boxes[i + 1]
        # special: 7 and 8 both feed 9 visually — keep linear 7->8->9 for readability
        arrow(d, ax + aw // 2, ay + ah, bx + bw // 2, by, color=LINE)

    # note for parallel 7/8
    d.text(
        (40, H - 50),
        "Steps 7 and 8 both land after root staging; both feed the idle-dashboard outcome.",
        font=sf,
        fill=MUTED,
    )
    save(img, "linkedin-cyvidia-diagram-threat-chain.jpg")


def render_cyvidia():
    W, H = 1400, 1200
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    tf, sf, hf, hs = font(22, True), font(16), font(34, True), font(18)
    title_block(d, "CYVIDIA response flow", "Hunt · plan · consent · harden / guard", W, hf, hs)

    boxes = {}
    boxes["hunt"] = node(d, 80, 140, 280, 90, "1  cyvidia hunt", "read-only checks", DEFEND, tf, sf)
    boxes["find"] = node(d, 440, 140, 300, 90, "2  Findings JSON + MD", "reports for IR", DEFEND, tf, sf)
    boxes["corr"] = node(d, 820, 140, 280, 90, "3  Correlation labels", "sansar_toolkit etc.", DEFEND, tf, sf)
    boxes["plan"] = node(d, 300, 320, 300, 90, "4  harden --plan", "blast radius listed", DEFEND, tf, sf)
    boxes["consent"] = node(d, 700, 320, 300, 90, "5  Consent gate", "host · expiry · actions", OK, tf, sf)

    boxes["guard"] = node(d, 40, 520, 300, 90, "No → guard alert-only", "journald · no wipe", DEFEND, tf, sf)
    boxes["exec"] = node(d, 560, 520, 320, 90, "Yes → harden execute", "quarantine · restore", DEFEND, tf, sf)
    boxes["q"] = node(d, 420, 700, 280, 90, "Quarantine + ROLLBACK.md", "evidence preserved", DEFEND, tf, sf)
    boxes["nv"] = node(d, 760, 700, 300, 90, "NVML via vendor pkgs", "never homemade .so", DEFEND, tf, sf)
    boxes["re"] = node(d, 420, 900, 360, 90, "6  Re-hunt verify", "exit 2 pages IR · exit 0 baseline", DEFEND, tf, sf)

    def link(a, b, color=DEFEND, fs="right", ts="left"):
        ax, ay, aw, ah = boxes[a]
        bx, by, bw, bh = boxes[b]
        pts = {
            "right": (ax + aw, ay + ah // 2),
            "left": (ax, ay + ah // 2),
            "bottom": (ax + aw // 2, ay + ah),
            "top": (ax + aw // 2, ay),
        }
        pte = {
            "right": (bx + bw, by + bh // 2),
            "left": (bx, by + bh // 2),
            "bottom": (bx + bw // 2, by + bh),
            "top": (bx + bw // 2, by),
        }
        x1, y1 = pts[fs]
        x2, y2 = pte[ts]
        arrow(d, x1, y1, x2, y2, color=color)

    link("hunt", "find")
    link("find", "corr")
    link("corr", "plan", DEFEND, "bottom", "top")
    link("plan", "consent")
    link("consent", "guard", DEFEND, "bottom", "top")
    link("consent", "exec", OK, "bottom", "top")
    link("exec", "q", DEFEND, "bottom", "top")
    link("exec", "nv", DEFEND, "bottom", "top")
    # Guard skips quarantine: alerts only, then verify/hunt again.
    ax, ay, aw, ah = boxes["guard"]
    bx, by, bw, bh = boxes["re"]
    arrow(d, ax + aw // 2, ay + ah, ax + aw // 2, by + bh // 2, color=DEFEND)
    arrow(d, ax + aw // 2, by + bh // 2, bx, by + bh // 2, color=DEFEND)
    link("q", "re", DEFEND, "bottom", "top")
    link("nv", "re", DEFEND, "bottom", "top")

    d.text((40, 1120), "Blue = defensive path   Green = consent gate", font=sf, fill=MUTED)
    save(img, "linkedin-cyvidia-diagram-response-flow.jpg")


if __name__ == "__main__":
    render_components()
    render_threat()
    render_cyvidia()
