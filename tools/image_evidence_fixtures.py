"""Authored image-only, corrupt-encoding and rotation cases; no research papers."""
from io import BytesIO

TEXT = "We measure x = 2. The result is stable."


def synthetic_pdf(*, rotation=0, corrupt=False, repeated=False):
    import fitz
    from PIL import Image, ImageDraw, ImageFont
    image = Image.new("RGB", (600, 240), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=22)
    draw.text((20, 20), "Abstract", font=font, fill="black")
    draw.text((20, 65), TEXT, font=font, fill="black")
    if repeated:
        draw.text((20, 130), TEXT, font=font, fill="black")
    output = BytesIO(); image.save(output, format="PNG")
    with fitz.open() as document:
        page = document.new_page(width=600, height=240)
        page.insert_image(page.rect, stream=output.getvalue())
        if corrupt:
            # A hidden, visibly irrelevant text layer with incorrect Unicode
            # mapping simulates broken extraction while the page stays legible.
            page.insert_text((20, 100), "BAD ENCODING", fontsize=12, render_mode=3)
            font_xref = page.get_fonts()[0][0]
            cmap = document.get_new_xref()
            document.update_object(cmap, "<< >>")
            # A valid but wrong mapping avoids renderer fallback to glyph names.
            # Corruption is not always identifiable by searching for U+FFFD.
            mappings = b"\n".join(f"<{code:02X}> <0058>".encode() for code in range(32, 127))
            document.update_stream(cmap, b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap "
                b"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def "
                b"/CMapName /Broken def /CMapType 2 def 1 begincodespacerange <00> <FF> endcodespacerange "
                b"95 beginbfchar\n" + mappings + b"\nendbfchar endcmap CMapName currentdict /CMap defineresource pop end end")
            document.xref_set_key(font_xref, "ToUnicode", f"{cmap} 0 R")
        page.set_rotation(rotation)
        return document.tobytes()
