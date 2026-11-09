"""极简单色图标：透明底、无边框、无渐变。三种变体。

输出：
    icon-mono-white.ico   纯白（深色背景用）
    icon-mono-dark.ico    近黑（浅色背景用）
    icon-mono-accent.ico  白柱 + 绿点
    mono_preview.png      三种 × 深/浅/灰底的对比
"""
from PIL import Image, ImageDraw

S = 1024
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
GREEN = (90, 218, 143)


def bars(color, dot_color=None):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    base_y = 812
    w, gap = 178, 58                      # 没有底板，柱子略微加宽更好认
    heights = [300, 470, 640]
    total = len(heights) * w + (len(heights) - 1) * gap
    x0 = (S - total) // 2
    for i, h in enumerate(heights):
        x = x0 + i * (w + gap)
        d.rounded_rectangle([x, base_y - h, x + w, base_y], radius=34, fill=color)

    if dot_color:
        cx, cy, r = x0 + total + 6, base_y - heights[-1] + 10, 52
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=dot_color)
    return img


def save(img, path):
    frames = [img.resize((s, s), Image.LANCZOS).convert("RGBA") for s in SIZES]
    frames[-1].save(path, format="ICO", sizes=[(s, s) for s in SIZES], append_images=frames[:-1])


def main():
    variants = [
        ("纯白", bars((255, 255, 255)), "icon-mono-white.ico"),
        ("近黑", bars((22, 23, 28)), "icon-mono-dark.ico"),
        ("白柱+绿点", bars((255, 255, 255), GREEN), "icon-mono-accent.ico"),
    ]
    for _, im, path in variants:
        save(im, path)

    bgs = [(255, 255, 255), (240, 242, 246), (28, 29, 34)]
    cw, ch = 230, 270
    sheet = Image.new("RGB", (cw * len(variants), ch * len(bgs)), (255, 255, 255))
    d = ImageDraw.Draw(sheet)
    for row, bg in enumerate(bgs):
        for col, (_, im, _) in enumerate(variants):
            x0, y0 = col * cw, row * ch
            d.rectangle([x0, y0, x0 + cw, y0 + ch], fill=bg)
            big = im.resize((120, 120), Image.LANCZOS)
            sheet.paste(big, (x0 + 55, y0 + 24), big)
            x = x0 + 22
            for s in (16, 24, 32, 48):
                sm = im.resize((s, s), Image.LANCZOS)
                sheet.paste(sm, (x, y0 + 190), sm)
                x += s + 12
    sheet.save("mono_preview.png")
    print("mono icons done")


if __name__ == "__main__":
    main()
