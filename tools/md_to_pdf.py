"""Convert README.md to README.pdf via HTML using xhtml2pdf."""

import sys
import pathlib
import markdown
from xhtml2pdf import pisa

MD_PATH  = pathlib.Path(__file__).parent.parent / "README.md"
PDF_PATH = pathlib.Path(__file__).parent.parent / "README.pdf"

CSS = """
@page {
    size: a4 portrait;
    margin: 22mm 20mm 22mm 20mm;
    @frame footer {
        -pdf-frame-content: footer_content;
        bottom: 12mm;
        left: 20mm;
        right: 20mm;
        height: 8mm;
    }
}

body {
    font-family: Times New Roman, serif;
    font-size: 10.5pt;
    line-height: 1.6;
    color: #111111;
    text-align: justify;
}

#footer_content {
    text-align: center;
    font-size: 8pt;
    color: #888888;
}

h1 {
    font-size: 19pt;
    font-weight: bold;
    text-align: center;
    margin-top: 0pt;
    margin-bottom: 4pt;
    color: #000000;
}

h2 {
    font-size: 13pt;
    font-weight: bold;
    color: #111111;
    margin-top: 16pt;
    margin-bottom: 5pt;
    border-bottom: 0.5pt solid #aaaaaa;
    padding-bottom: 2pt;
}

h3 {
    font-size: 11pt;
    font-weight: bold;
    color: #222222;
    margin-top: 11pt;
    margin-bottom: 3pt;
}

p {
    margin-top: 0pt;
    margin-bottom: 6pt;
}

.subtitle {
    text-align: center;
    font-size: 10pt;
    color: #555555;
    margin-bottom: 14pt;
}

.abstract-box {
    border: 0.5pt solid #999999;
    background-color: #f8f8f8;
    padding: 8pt 10pt;
    margin-bottom: 12pt;
    font-size: 9.5pt;
    line-height: 1.5;
}

pre {
    font-family: Courier New, monospace;
    font-size: 8pt;
    background-color: #f5f5f5;
    border: 0.5pt solid #cccccc;
    padding: 6pt 8pt;
    margin-top: 4pt;
    margin-bottom: 8pt;
    line-height: 1.4;
    white-space: pre-wrap;
    word-wrap: break-word;
}

code {
    font-family: Courier New, monospace;
    font-size: 8.5pt;
    background-color: #f0f0f0;
    padding: 0pt 2pt;
}

pre code {
    background-color: transparent;
    padding: 0pt;
    font-size: 8pt;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin-top: 6pt;
    margin-bottom: 10pt;
}

th {
    background-color: #222222;
    color: #ffffff;
    font-weight: bold;
    padding: 4pt 7pt;
    text-align: left;
}

td {
    padding: 3pt 7pt;
    border-bottom: 0.5pt solid #dddddd;
    vertical-align: top;
}

ul, ol {
    margin-top: 3pt;
    margin-bottom: 7pt;
    padding-left: 16pt;
}

li {
    margin-bottom: 2pt;
}

hr {
    border-top: 0.5pt solid #cccccc;
    margin-top: 12pt;
    margin-bottom: 12pt;
}

blockquote {
    border-left: 2pt solid #888888;
    margin: 0 0 8pt 0;
    padding: 4pt 10pt;
    background-color: #f8f8f8;
    font-size: 9.5pt;
}
"""


def build_html(md_text: str) -> str:
    # Parse abstract section specially — everything between ## Abstract and ## 1.
    # We'll wrap it in a styled box
    lines = md_text.split("\n")
    in_abstract = False
    abstract_lines = []
    rest_lines = []
    for line in lines:
        if line.strip() == "## Abstract":
            in_abstract = True
            rest_lines.append('<div class="abstract-box"><strong>Abstract.</strong> ')
            continue
        if in_abstract and line.startswith("## "):
            in_abstract = False
            rest_lines.append("</div>\n")
        if in_abstract:
            abstract_lines.append(line)
            rest_lines.append(line)
        else:
            rest_lines.append(line)

    md_text = "\n".join(rest_lines)

    body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "nl2br"],
    )

    # Wrap version line
    body = body.replace(
        "<p><strong>Version 1.0</strong></p>",
        '<p class="subtitle"><strong>Version 1.0</strong></p>',
    )

    footer_html = '<div id="footer_content"><pdf:pagenumber/></div>'

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>{CSS}</style>
</head>
<body>
{footer_html}
{body}
</body>
</html>"""


def main():
    md_text = MD_PATH.read_text(encoding="utf-8")
    html    = build_html(md_text)

    print(f"Converting {MD_PATH.name} -> {PDF_PATH.name} ...", flush=True)

    with open(PDF_PATH, "wb") as pdf_file:
        result = pisa.CreatePDF(html, dest=pdf_file, encoding="utf-8")

    if result.err:
        print(f"ERROR: {result.err}")
        return 1

    size_kb = PDF_PATH.stat().st_size // 1024
    print(f"Done: {PDF_PATH}  ({size_kb} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
