from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "linkedin-assets" / "png" / "linkedin-cover.png"
W, H = 1600, 900

FONT_REG = "/System/Library/Fonts/Supplemental/Arial.ttf"
FONT_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
FONT_BLACK = "/System/Library/Fonts/Supplemental/Arial Black.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size=size)


def fit_font(path: str, value: str, max_width: int, start_size: int, min_size: int = 12) -> ImageFont.FreeTypeFont:
    size = start_size
    while size > min_size:
        candidate = font(path, size)
        if candidate.getlength(value) <= max_width:
            return candidate
        size -= 1
    return font(path, min_size)


def text(draw: ImageDraw.ImageDraw, xy: tuple[int, int], value: str, fnt: ImageFont.FreeTypeFont, fill: tuple[int, int, int, int], spacing: int = 0) -> None:
    x, y = xy
    if spacing == 0:
        draw.text((x, y), value, font=fnt, fill=fill)
        return
    for ch in value:
        draw.text((x, y), ch, font=fnt, fill=fill)
        x += int(draw.textlength(ch, font=fnt)) + spacing


def rounded_panel(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int, fill: tuple[int, int, int, int], outline: tuple[int, int, int, int], width: int = 2) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)

    img = Image.new("RGBA", (W, H), (8, 15, 30, 255))
    px = img.load()
    for y in range(H):
        for x in range(W):
            tx = x / (W - 1)
            ty = y / (H - 1)
            r = int(9 + 10 * tx + 4 * ty)
            g = int(18 + 26 * tx + 22 * ty)
            b = int(36 + 42 * tx + 28 * ty)
            px[x, y] = (r, g, b, 255)

    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for cx, cy, color, maxr in [
        (1060, 390, (56, 189, 248), 390),
        (1320, 680, (52, 211, 153), 330),
    ]:
        for rr in range(maxr, 0, -12):
            alpha = int(50 * (1 - rr / maxr) ** 1.7)
            gd.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), fill=(*color, alpha))
    img = Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(18)))
    draw = ImageDraw.Draw(img)

    for x in range(0, W + 1, 160):
        draw.line((x, 0, x, H), fill=(148, 163, 184, 28), width=1)
    for y in range(0, H + 1, 130):
        draw.line((0, y, W, y), fill=(148, 163, 184, 28), width=1)

    # Left title block.
    text(draw, (110, 118), "DEFENSIVE AI / SOC ARCHITECTURE", font(FONT_BOLD, 24), (103, 232, 249, 255), spacing=3)
    draw.text((110, 210), "Defensive AI", font=font(FONT_BLACK, 90), fill=(248, 250, 252, 255))
    draw.text((110, 312), "Gateway", font=font(FONT_BLACK, 90), fill=(248, 250, 252, 255))
    draw.text((113, 430), "Governed alert analysis for", font=font(FONT_REG, 38), fill=(203, 213, 225, 255))
    draw.text((113, 478), "regulated security operations", font=font(FONT_REG, 38), fill=(203, 213, 225, 255))

    rounded_panel(draw, (112, 575, 790, 648), 36, (14, 116, 144, 46), (125, 211, 252, 120), 3)
    draw.text((150, 598), "Read-only by default", font=font(FONT_BOLD, 23), fill=(224, 242, 254, 255))
    draw.ellipse((397, 610, 413, 626), fill=(103, 232, 249, 255))
    draw.text((435, 598), "Evidence-first", font=font(FONT_BOLD, 23), fill=(224, 242, 254, 255))
    draw.ellipse((602, 610, 618, 626), fill=(103, 232, 249, 255))
    draw.text((640, 598), "Auditable", font=font(FONT_BOLD, 23), fill=(224, 242, 254, 255))

    # Right architecture motif.
    def node(box, title, lines, color):
        shadow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sd = ImageDraw.Draw(shadow)
        sd.rounded_rectangle((box[0], box[1] + 16, box[2], box[3] + 16), radius=24, fill=(2, 6, 23, 90))
        nonlocal_img = shadow.filter(ImageFilter.GaussianBlur(12))
        img.alpha_composite(nonlocal_img)
        rounded_panel(draw, box, 24, (15, 23, 42, 188), (*color, 135), 2)
        draw.ellipse((box[0] + 28, box[1] + 34, box[0] + 54, box[1] + 60), fill=(*color, 255))
        text_max = box[2] - box[0] - 96
        title_font = fit_font(FONT_BOLD, title, text_max, 27, 19)
        draw.text((box[0] + 72, box[1] + 30), title, font=title_font, fill=(248, 250, 252, 255))
        yy = box[1] + 76
        for line in lines:
            line_font = fit_font(FONT_REG, line, text_max, 19, 14)
            draw.text((box[0] + 72, yy), line, font=line_font, fill=(203, 213, 225, 255))
            yy += 30

    node((845, 168, 1218, 338), "AI Gateway Core", ["Normalize alerts", "Apply policy controls", "Route product agents"], (56, 189, 248))
    node((1232, 210, 1510, 350), "LLM Adapter", ["Local analyzer", "Enterprise gateway"], (52, 211, 153))
    node((800, 570, 1065, 725), "Memory", ["Case, asset, org", "Promotion gates"], (52, 211, 153))
    node((1160, 570, 1435, 725), "Audit Trail", ["Cases, runs, events", "Analyst review"], (251, 146, 60))
    node((838, 398, 1178, 508), "Product Agents", ["HIPS / RASP / NDR / WAF / SIEM"], (129, 140, 248))

    # Curved connections.
    for start, end, color in [
        ((790, 614), (845, 455), (125, 211, 252)),
        ((1178, 453), (1232, 278), (125, 211, 252)),
        ((1020, 508), (940, 570), (94, 234, 212)),
        ((1090, 508), (1265, 570), (251, 191, 36)),
        ((1218, 253), (1232, 280), (167, 243, 208)),
    ]:
        sx, sy = start
        ex, ey = end
        mx = (sx + ex) // 2
        my = min(sy, ey) - 60
        points = []
        for i in range(42):
            t = i / 41
            x = (1 - t) ** 2 * sx + 2 * (1 - t) * t * mx + t**2 * ex
            y = (1 - t) ** 2 * sy + 2 * (1 - t) * t * my + t**2 * ey
            points.append((x, y))
        draw.line(points, fill=(*color, 150), width=4)
        angle = math.atan2(points[-1][1] - points[-3][1], points[-1][0] - points[-3][0])
        ah = 14
        p1 = (ex - ah * math.cos(angle - 0.45), ey - ah * math.sin(angle - 0.45))
        p2 = (ex - ah * math.cos(angle + 0.45), ey - ah * math.sin(angle + 0.45))
        draw.polygon([end, p1, p2], fill=(*color, 190))

    # Floating telemetry dots.
    for i in range(34):
        x = int(720 + (i * 73) % 780)
        y = int(120 + (i * 137) % 650)
        alpha = 70 + (i * 17) % 110
        r = 2 + (i % 4)
        draw.ellipse((x - r, y - r, x + r, y + r), fill=(125, 211, 252, alpha))

    footer = "Normalize  •  Govern  •  Analyze  •  Review"
    footer_font = fit_font(FONT_REG, footer, 480, 24, 18)
    footer_w = int(footer_font.getlength(footer))
    footer_x1 = 1010
    footer_x2 = footer_x1 + footer_w + 90
    rounded_panel(draw, (footer_x1, 785, footer_x2, 846), 30, (15, 23, 42, 132), (148, 163, 184, 72), 2)
    draw.text((footer_x1 + 45, 804), footer, font=footer_font, fill=(203, 213, 225, 255))

    img.convert("RGB").save(OUT, quality=95)
    print(OUT)


if __name__ == "__main__":
    main()
