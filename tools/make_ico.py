"""生成 AITaskManager 图标：浅色（蓝玻璃）与暗色两套。

用法：
    python make_ico.py            # 两套都出，并生成对比图
    python make_ico.py dark       # 只出暗色
输出：icon.ico（当前选用的那套）、icon-light.ico、icon-dark.ico、icon_preview.png
"""
import sys

from PIL import Image, ImageDraw, ImageFilter

S = 1024
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
GREEN = (90, 218, 143)

PALETTES = {
    "light": {
        "top": (56, 189, 248), "bot": (3, 105, 161),
        "bar": (255, 255, 255), "gloss": 115, "rim": None,
    },
    "dark": {
        "top": (58, 62, 74), "bot": (18, 19, 24),
        "bar": (232, 234, 240), "gloss": 46, "rim": (255, 255, 255, 30),
    },
}


def mask(radius=int(S * 0.22)):
    m = Image.new("L", (S, S), 0)
    ImageDraw.Draw(m).rounded_rectangle([0, 0, S - 1, S - 1], radius=radius, fill=255)
    return m


def plate(p):
    g = Image.new("RGB", (1, S))
    d = ImageDraw.Draw(g)
    for y in range(S):
        t = y / (S - 1)
        d.point((0, y), tuple(int(p["top"][i] + (p["bot"][i] - p["top"][i]) * t) for i in range(3)))
    g = g.resize((S, S))

    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    img.paste(g, (0, 0), mask())

    gloss = Image.new("RGBA", (S, int(S * 0.52)), (0, 0, 0, 0))
    gd = ImageDraw.Draw(gloss)
    for y in range(gloss.height):
        gd.line([(0, y), (S, y)],
                fill=(255, 255, 255, int(p["gloss"] * (1 - y / gloss.height))))
    img.alpha_composite(gloss.filter(ImageFilter.GaussianBlur(8)), (0, 0))

    out = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask())

    if p["rim"]:
        d2 = ImageDraw.Draw(out)
        d2.rounded_rectangle([3, 3, S - 4, S - 4], radius=int(S * 0.22),
                             outline=p["rim"], width=7)
    return out


def build(p):
    img = plate(p)
    d = ImageDraw.Draw(img)

    base_y = 742
    w, gap = 122, 54
    heights = [286, 440, 592]
    total = len(heights) * w + (len(heights) - 1) * gap
    x0 = (S - total) // 2
    for i, h in enumerate(heights):
        x = x0 + i * (w + gap)
        d.rounded_rectangle([x, base_y - h, x + w, base_y], radius=28, fill=p["bar"])

    cx, cy, r = 786, 268, 72
    d.ellipse([cx - r - 10, cy - r - 10, cx + r + 10, cy + r + 10], fill=(255, 255, 255, 70))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=GREEN)
    d.ellipse([cx - r + 20, cy - r + 18, cx + r - 34, cy + r - 62], fill=(255, 255, 255, 90))
    return img


def save_ico(img, path):
    frames = [img.resize((s, s), Image.LANCZOS).convert("RGBA") for s in SIZES]
    frames[-1].save(path, format="ICO", sizes=[(s, s) for s in SIZES], append_images=frames[:-1])


def preview(light, dark):
    cols = [("light", light, (244, 246, 249)), ("light", light, (28, 29, 34)),
            ("dark", dark, (244, 246, 249)), ("dark", dark, (28, 29, 34))]
    cw, ch = 250, 300
    sheet = Image.new("RGB", (cw * 4, ch), (255, 255, 255))
    d = ImageDraw.Draw(sheet)
    for i, (name, im, bg) in enumerate(cols):
        d.rectangle([i * cw, 0, (i + 1) * cw, ch], fill=bg)
        big = im.resize((128, 128), Image.LANCZOS)
        sheet.paste(big, (i * cw + 61, 40), big)
        x = i * cw + 30
        for s in (16, 24, 32, 48):
            sm = im.resize((s, s), Image.LANCZOS)
            sheet.paste(sm, (x, 210), sm)
            x += s + 14
    sheet.save("icon_preview.png")


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    light = build(PALETTES["light"]) if which in ("both", "light") else None
    dark = build(PALETTES["dark"]) if which in ("both", "dark") else None

    if light:
        save_ico(light, "icon-light.ico")
    if dark:
        save_ico(dark, "icon-dark.ico")

    chosen = dark if dark else light
    save_ico(chosen, "icon.ico")

    if light and dark:
        preview(light, dark)
    print("done")


if __name__ == "__main__":
    main()
