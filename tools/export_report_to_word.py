from __future__ import annotations

import argparse
import base64
import html
import mimetypes
import re
import unicodedata
from pathlib import Path


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
ORDERED_LIST_RE = re.compile(r"^\d+\.\s+(.*)$")
UNORDERED_LIST_RE = re.compile(r"^-\s+(.*)$")
TABLE_SEP_CELL_RE = re.compile(r"^:?-{3,}:?$")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


def slugify(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    ascii_only = ascii_only.lower()
    ascii_only = re.sub(r"[^a-z0-9]+", "-", ascii_only).strip("-")
    return ascii_only or "section"


def image_to_data_uri(raw_path: str, base_dir: Path) -> str:
    image_path = (base_dir / raw_path).resolve()
    mime_type, _ = mimetypes.guess_type(str(image_path))
    if mime_type is None:
        mime_type = "application/octet-stream"
    payload = base64.b64encode(image_path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{payload}"


def render_inline(text: str, base_dir: Path) -> str:
    placeholders: dict[str, str] = {}

    def stash(fragment: str) -> str:
        token = f"__HTML_PLACEHOLDER_{len(placeholders)}__"
        placeholders[token] = fragment
        return token

    text = IMAGE_RE.sub(
        lambda match: stash(
            (
                '<img class="report-image" alt="{alt}" src="{src}"/>'
            ).format(
                alt=html.escape(match.group(1)),
                src=image_to_data_uri(match.group(2), base_dir),
            )
        ),
        text,
    )
    text = LINK_RE.sub(
        lambda match: stash(
            '<a href="{href}">{label}</a>'.format(
                href=html.escape(match.group(2), quote=True),
                label=html.escape(match.group(1)),
            )
        ),
        text,
    )
    text = INLINE_CODE_RE.sub(
        lambda match: stash(f"<code>{html.escape(match.group(1))}</code>"),
        text,
    )
    text = html.escape(text)
    text = BOLD_RE.sub(r"<strong>\1</strong>", text)
    for token, fragment in placeholders.items():
        text = text.replace(token, fragment)
    return text.replace("  ", "&nbsp; ")


def parse_table(lines: list[str], start: int, base_dir: Path) -> tuple[str, int]:
    rows: list[list[str]] = []
    index = start
    while index < len(lines):
        stripped = lines[index].strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        rows.append(cells)
        index += 1

    def is_separator(row: list[str]) -> bool:
        return all(TABLE_SEP_CELL_RE.match(cell) for cell in row)

    cleaned_rows = [row for row in rows if not is_separator(row)]
    if not cleaned_rows:
        return "", index

    header = cleaned_rows[0]
    body = cleaned_rows[1:]

    html_parts = ['<table class="report-table">', "<thead>", "<tr>"]
    html_parts.extend(f"<th>{render_inline(cell, base_dir)}</th>" for cell in header)
    html_parts.extend(["</tr>", "</thead>", "<tbody>"])
    for row in body:
        html_parts.append("<tr>")
        html_parts.extend(f"<td>{render_inline(cell, base_dir)}</td>" for cell in row)
        html_parts.append("</tr>")
    html_parts.extend(["</tbody>", "</table>"])
    return "\n".join(html_parts), index


def parse_center_block(lines: list[str], start: int, base_dir: Path) -> tuple[str, int]:
    index = start + 1
    inner_parts = ['<div class="center-block">']
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "</div>":
            inner_parts.append("</div>")
            return "\n".join(inner_parts), index + 1
        if not stripped:
            index += 1
            continue
        if stripped.lower() == "<br>":
            inner_parts.append("<br/>")
        else:
            inner_parts.append(f"<p>{render_inline(stripped.rstrip(), base_dir)}</p>")
        index += 1
    inner_parts.append("</div>")
    return "\n".join(inner_parts), index


def parse_equation(lines: list[str], start: int) -> tuple[str, int]:
    index = start + 1
    equation_lines: list[str] = []
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == r"\]":
            break
        equation_lines.append(stripped)
        index += 1
    formula = " ".join(line for line in equation_lines if line)
    fragment = f'<div class="equation-block">{html.escape(formula)}</div>'
    return fragment, min(index + 1, len(lines))


def markdown_to_html(markdown_text: str, base_dir: Path) -> str:
    lines = markdown_text.splitlines()
    parts: list[str] = []
    paragraph_buffer: list[str] = []
    in_code_block = False
    code_lang = ""
    code_lines: list[str] = []
    current_list: str | None = None

    def flush_paragraph() -> None:
        nonlocal paragraph_buffer
        if paragraph_buffer:
            joined = " ".join(item.strip() for item in paragraph_buffer if item.strip())
            if joined:
                parts.append(f"<p>{render_inline(joined, base_dir)}</p>")
        paragraph_buffer = []

    def close_list() -> None:
        nonlocal current_list
        if current_list is not None:
            parts.append(f"</{current_list}>")
            current_list = None

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if in_code_block:
            if stripped.startswith("```"):
                code_html = html.escape("\n".join(code_lines))
                parts.append(f'<pre class="code-block"><code class="lang-{html.escape(code_lang)}">{code_html}</code></pre>')
                code_lines = []
                code_lang = ""
                in_code_block = False
            else:
                code_lines.append(line)
            index += 1
            continue

        if not stripped:
            flush_paragraph()
            close_list()
            index += 1
            continue

        if stripped.startswith("<div align=\"center\">"):
            flush_paragraph()
            close_list()
            block_html, index = parse_center_block(lines, index, base_dir)
            parts.append(block_html)
            continue

        if stripped == r"\[":
            flush_paragraph()
            close_list()
            equation_html, index = parse_equation(lines, index)
            parts.append(equation_html)
            continue

        if stripped.startswith("```"):
            flush_paragraph()
            close_list()
            in_code_block = True
            code_lang = stripped[3:].strip()
            index += 1
            continue

        if stripped == "---":
            flush_paragraph()
            close_list()
            parts.append("<hr/>")
            index += 1
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            close_list()
            table_html, index = parse_table(lines, index, base_dir)
            if table_html:
                parts.append(table_html)
                continue

        heading_match = HEADING_RE.match(stripped)
        if heading_match:
            flush_paragraph()
            close_list()
            level = len(heading_match.group(1))
            title = heading_match.group(2).strip()
            anchor = slugify(title)
            parts.append(f'<h{level} id="{anchor}">{render_inline(title, base_dir)}</h{level}>')
            index += 1
            continue

        unordered_match = UNORDERED_LIST_RE.match(stripped)
        if unordered_match:
            flush_paragraph()
            if current_list != "ul":
                close_list()
                current_list = "ul"
                parts.append("<ul>")
            parts.append(f"<li>{render_inline(unordered_match.group(1), base_dir)}</li>")
            index += 1
            continue

        ordered_match = ORDERED_LIST_RE.match(stripped)
        if ordered_match:
            flush_paragraph()
            if current_list != "ol":
                close_list()
                current_list = "ol"
                parts.append("<ol>")
            parts.append(f"<li>{render_inline(ordered_match.group(1), base_dir)}</li>")
            index += 1
            continue

        if stripped.startswith("<") and stripped.endswith(">"):
            flush_paragraph()
            close_list()
            parts.append(stripped)
            index += 1
            continue

        paragraph_buffer.append(line)
        index += 1

    flush_paragraph()
    close_list()

    return """<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8"/>
  <title>Báo cáo kết môn CyberShield AI</title>
  <style>
    @page {
      margin: 2.5cm;
    }
    body {
      font-family: "Times New Roman", serif;
      font-size: 14pt;
      line-height: 1.5;
      color: #111;
    }
    h1, h2, h3, h4, h5, h6 {
      font-weight: bold;
      margin-top: 20pt;
      margin-bottom: 10pt;
    }
    h1 {
      font-size: 18pt;
      text-align: center;
    }
    h2 {
      font-size: 16pt;
    }
    h3 {
      font-size: 15pt;
    }
    p {
      margin: 0 0 10pt 0;
      text-align: justify;
    }
    ul, ol {
      margin-top: 0;
      margin-bottom: 10pt;
    }
    li {
      margin-bottom: 4pt;
    }
    hr {
      border: none;
      border-top: 1px solid #666;
      margin: 14pt 0;
    }
    code {
      font-family: Consolas, monospace;
      font-size: 11pt;
      background: #f4f4f4;
      padding: 1pt 3pt;
    }
    .code-block {
      font-family: Consolas, monospace;
      font-size: 11pt;
      background: #f7f7f7;
      border: 1px solid #d9d9d9;
      padding: 10pt;
      white-space: pre-wrap;
      margin: 10pt 0;
    }
    .report-table {
      width: 100%;
      border-collapse: collapse;
      margin: 10pt 0 14pt 0;
      table-layout: fixed;
    }
    .report-table th,
    .report-table td {
      border: 1px solid #444;
      padding: 6pt;
      vertical-align: top;
    }
    .report-table th {
      background: #efefef;
      text-align: center;
    }
    .report-image {
      max-width: 100%;
      display: block;
      margin: 8pt auto;
    }
    .center-block {
      text-align: center;
      margin: 12pt 0;
    }
    .center-block p {
      text-align: center;
      margin-bottom: 6pt;
    }
    .equation-block {
      text-align: center;
      font-style: italic;
      margin: 10pt 0;
    }
    a {
      color: #0000cc;
      text-decoration: underline;
    }
  </style>
</head>
<body>
""" + "\n".join(parts) + """
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a markdown report to HTML for Word export.")
    parser.add_argument("source", type=Path, help="Path to the markdown report.")
    parser.add_argument("output", type=Path, help="Path to the generated HTML file.")
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    markdown_text = source.read_text(encoding="utf-8")
    html_text = markdown_to_html(markdown_text, source.parent)
    output.write_text(html_text, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
