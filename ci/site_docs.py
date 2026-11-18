#!/usr/bin/env python3
"""The guide and the decisions as pages of the website, in Line map (DESIGN.md).

    python3 ci/site_docs.py              write docs/guide/*.html, docs/guide/index.html, docs/guide/search.json
                                         and docs/*.html beside the decisions (docs/adr-*.md, docs/security-review-2.md)
    python3 ci/site_docs.py --check      fail if one of them is not what the markdown makes now, or a link does not resolve
    python3 ci/site_docs.py --self-test  the converter on each thing the guide uses

Stdlib only. GitHub Pages serves docs/ as it is (docs/.nojekyll), so the pages are built here and committed, like
ci/site_numbers.py's output. The markdown subset is what the guide uses: headings, paragraphs, bullet and numbered
lists (nested, with code in them), GFM tables, fenced code (its language kept as a class), `code`, **strong**, *em*,
[links](x.md#a), a rule, and the <picture> blocks that show a drawing in light and dark. Text is escaped; the one raw
HTML the converter lets through is that <picture> block, tag by tag and attribute by attribute.

A link to another .md of docs/ becomes the .html beside it (its #anchor checked against that page's headings); a
file under docs/ stays a relative link; a file or folder elsewhere in the repo becomes a GitHub link. Pages take
their look from docs/site.css (the tokens, the bar) and docs/docs.css; docs/docs.js filters docs/guide/search.json.
"""
import argparse
import html
import json
import pathlib
import posixpath
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO = "https://github.com/ChaseSunstrom/kith"
# Reading order of the guide; a page not named comes after, by name.
ORDER = ["os", "cluster", "workloads", "storage", "hardware", "packages", "access", "api", "kubernetes", "ui", "development", "numbers"]
ICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='10 4 44 56'%3E%3Cg stroke='%238a8f9c' stroke-width='4' stroke-linecap='round'%3E%3Cpath d='M22 14V50M24 36 42 20M26 38 42 50'/%3E%3C/g%3E%3Ccircle cx='24' cy='37' r='6.5' fill='%235b8cff'/%3E%3C/svg%3E"
MARK = ('<svg class="mark" viewBox="12 6 40 52" aria-hidden="true">'
        '<line x1="22" y1="14" x2="22" y2="50"/><line x1="24" y1="36" x2="42" y2="20"/><line x1="26" y1="38" x2="42" y2="50"/>'
        '<circle cx="22" cy="14" r="4"/><circle cx="22" cy="50" r="4"/><circle cx="43" cy="19" r="4.5"/><circle cx="43" cy="50" r="4.5"/>'
        '<circle class="ring" cx="24" cy="37" r="5.5"/><circle class="hub" cx="24" cy="37" r="5.5"/></svg>')

FENCE = re.compile(r"^\s*```(\S*)\s*$")
ITEM = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")
HEAD = re.compile(r"^(#{1,6})\s+(.*?)(?:\s+#+)?\s*$")
RULE = re.compile(r"^\s*(?:-{3,}|\*{3,})\s*$")
SEPARATOR = re.compile(r"^\s*\|?(?:\s*:?-+:?\s*\|)+(?:\s*:?-+:?\s*)?$")
LINK = re.compile(r"\[((?:[^\[\]]|\[[^\]]*\])+)\]\(([^()\s]+)(?:\s+&quot;[^&]*&quot;)?\)")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
TAG = re.compile(r'<(/?)(picture|source|img)((?:\s+(?:media|srcset|src|alt|width|height)="[^"<>]*")*)\s*/?>')
ATTR = re.compile(r'(media|srcset|src|alt|width|height)="([^"<>]*)"')


def esc(text):
    return html.escape(text, quote=False)


def attr(text):
    return html.escape(text, quote=True)


def indent(line):
    return len(line) - len(line.lstrip(" "))


def slug(text):
    """GitHub's heading id: lower case, punctuation gone, spaces to hyphens (so links written for GitHub still land)."""
    return re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")


def plain(markup):
    return html.unescape(re.sub(r"<[^>]+>", "", markup))


def bullet_or_first(line):
    m = ITEM.match(line)
    return bool(m) and (m.group(2) in "-*" or m.group(2) == "1.")


def starts_block(line, nxt=None):
    return bool(FENCE.match(line) or HEAD.match(line) or RULE.match(line) or bullet_or_first(line)
                or line.lstrip().startswith("<picture")
                or (line.lstrip().startswith("|") and nxt is not None and SEPARATOR.match(nxt)))


class Doc:
    """One markdown file: `src` is its path from the repo root (docs/guide/os.md), `known` the md files that become pages."""

    def __init__(self, src, text, known):
        self.src, self.known = src, known
        self.heads, self.refs, self.problems, self.ids = [], [], [], set()
        self.body = "\n".join(self.blocks(text.replace("\r\n", "\n").replace("\t", "    ").split("\n")))
        self.title = next((t for lv, _, t in self.heads if lv == 1), posixpath.basename(src))

    # ----- links
    def href(self, url):
        if url.startswith("#"):
            self.refs.append((self.src, self.src, url[1:]))
            return url
        if SCHEME.match(url):
            if url.split(":")[0].lower() not in ("http", "https", "mailto"):
                self.problems.append(f"{self.src}: a link to {url[:40]}")
                return "#"
            return url
        path, _, frag = url.partition("#")
        here = posixpath.dirname(self.src)
        target = posixpath.normpath(posixpath.join(here, path))
        if path.startswith("/") or target.startswith("..") or not (ROOT / target).exists():
            self.problems.append(f"{self.src}: a link to {url}, which is not a file or folder of the repo")
            return "#"
        tail = "#" + frag if frag else ""
        if target in self.known:
            self.refs.append((self.src, target, frag))
            return posixpath.relpath(target[:-3] + ".html", here) + tail
        if target.startswith("docs/") and (ROOT / target).is_file():
            return posixpath.relpath(target, here) + tail
        kind = "tree" if (ROOT / target).is_dir() else "blob"
        return f"{REPO}/{kind}/main/{target}{tail}"

    # ----- inline
    def inline(self, text):
        keep = []

        def stash(markup):
            keep.append(markup)
            return f"\x00{len(keep) - 1}\x00"

        def code(m):
            body = m.group(2).replace("\n", " ")
            if len(body) > 2 and body[0] == body[-1] == " " and body.strip():
                body = body[1:-1]
            return stash(f"<code>{esc(body)}</code>")

        text = text.replace("\x00", "")
        text = re.sub(r"(`+)(.+?)(?<!`)\1(?!`)", code, text, flags=re.S)
        text = re.sub(r"\\([\\`*_{}\[\]()#+\-.!|<>])", lambda m: stash(esc(m.group(1))), text)
        text = html.escape(text, quote=False).replace('"', "&quot;")

        def link(m):
            inner = self.emphasis(m.group(1))
            return stash(f'<a href="{attr(self.href(html.unescape(m.group(2))))}">{inner}</a>')

        text = LINK.sub(link, text)
        text = self.emphasis(text).replace("&quot;", '"')
        for _ in range(4):
            text = re.sub(r"\x00(\d+)\x00", lambda m: keep[int(m.group(1))], text)
        return text

    @staticmethod
    def emphasis(text):
        text = re.sub(r"(?<![\w*])\*\*(?=\S)(.+?)(?<=\S)\*\*(?![\w*])", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])", r"<em>\1</em>", text)
        return re.sub(r"(?<!\w)_(?=[^\s_])(.+?)(?<=[^\s_])_(?!\w)", r"<em>\1</em>", text)

    # ----- blocks
    def heading(self, level, text):
        markup = self.inline(text)
        base = slug(plain(markup))
        ident, n = base, 0
        while ident in self.ids:
            n += 1
            ident = f"{base}-{n}"
        self.ids.add(ident)
        self.heads.append((level, ident, plain(markup)))
        link = f' <a class="anchor" href="#{attr(ident)}" aria-label="Link to this section">#</a>' if level > 1 else ""
        return f'<h{level} id="{attr(ident)}">{markup}{link}</h{level}>'

    def picture(self, lines):
        raw = "\n".join(lines)
        out, at = [], 0
        for m in TAG.finditer(raw):
            if raw[at:m.start()].strip():
                self.problems.append(f"{self.src}: HTML other than <picture>, <source> and <img> with plain attributes")
            at = m.end()
            if m.group(1):
                out.append(f"</{m.group(2)}>")
                continue
            parts = []
            for name, value in ATTR.findall(m.group(3)):
                value = html.unescape(value)
                if name == "src" or name == "srcset":
                    value = self.href(value)
                parts.append(f' {name}="{attr(value)}"')
            out.append(f"<{m.group(2)}{''.join(parts)}>")
        if raw[at:].strip():
            self.problems.append(f"{self.src}: HTML other than <picture>, <source> and <img> with plain attributes")
        return "".join(out)

    def table(self, lines):
        def cells(row):
            row = row.strip().removeprefix("|")
            row = row if row.endswith("\\|") else row.removesuffix("|")
            return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", row)]

        head, body = cells(lines[0]), [cells(r) for r in lines[2:]]
        width = len(head)
        out = ["<div class=\"table\"><table><thead><tr>" + "".join(f"<th>{self.inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
        for row in body:
            row = (row + [""] * width)[:width]
            out.append("<tr>" + "".join(f"<td>{self.inline(c)}</td>" for c in row) + "</tr>")
        out.append("</tbody></table></div>")
        return "".join(out)

    def list(self, lines, i):
        n = len(lines)
        first = ITEM.match(lines[i])
        base, ordered = len(first.group(1)), first.group(2)[0].isdigit()
        items, loose = [], False
        while i < n:
            m = ITEM.match(lines[i])
            if not m or len(m.group(1)) != base or m.group(2)[0].isdigit() != ordered:
                break
            col, item, fenced, i = m.start(3), [m.group(3)], False, i + 1
            while i < n:
                ln = lines[i]
                if fenced:
                    item.append(ln[min(indent(ln), col):])
                    fenced = not ln.strip().startswith("```")
                    i += 1
                    continue
                if not ln.strip():
                    j = i
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n and indent(lines[j]) > base:
                        item += [""] * (j - i)
                        loose, i = True, j
                        continue
                    break
                ind = indent(ln)
                if ind > base:
                    item.append(ln[min(ind, col):])
                    fenced = bool(FENCE.match(ln))
                    i += 1
                elif ind == base and not ITEM.match(ln) and item[-1].strip() and not starts_block(ln):
                    item.append(ln.strip())  # a lazy continuation of the paragraph
                    i += 1
                else:
                    break
            items.append(item)
            j = i
            while j < n and not lines[j].strip():
                j += 1
            nxt = ITEM.match(lines[j]) if j < n else None
            if j > i and nxt and len(nxt.group(1)) == base and nxt.group(2)[0].isdigit() == ordered:
                loose, i = True, j
        tag = "ol" if ordered else "ul"
        start = int(first.group(2)[:-1]) if ordered else 1
        # the CSS draws the numbers with a counter, which ignores start: reset it to one before the first
        opening = f'<ol start="{start}" style="counter-reset:n {start - 1}">' if start != 1 else f"<{tag}>"
        lis = "".join(f"<li>{''.join(self.blocks(it, tight=not loose))}</li>" for it in items)
        return f"{opening}{lis}</{tag}>", i

    def blocks(self, lines, tight=False):
        out, i, n = [], 0, len(lines)
        while i < n:
            line = lines[i]
            nxt = lines[i + 1] if i + 1 < n else None
            if not line.strip():
                i += 1
            elif FENCE.match(line):
                lang, j = FENCE.match(line).group(1), i + 1
                while j < n and lines[j].strip() != "```":
                    j += 1
                cut = indent(line)
                text = "\n".join(ln[min(indent(ln), cut):] for ln in lines[i + 1:j])
                klass = f' class="language-{attr(lang)}"' if lang else ""
                out.append(f"<pre><code{klass}>{esc(text)}\n</code></pre>")
                i = j + 1
            elif HEAD.match(line):
                m = HEAD.match(line)
                out.append(self.heading(len(m.group(1)), m.group(2)))
                i += 1
            elif RULE.match(line):
                out.append("<hr>")
                i += 1
            elif line.lstrip().startswith("<picture"):
                j = i
                while j < n and "</picture>" not in lines[j]:
                    j += 1
                out.append(f'<p class="picture">{self.picture(lines[i:j + 1])}</p>')
                i = j + 1
            elif line.lstrip().startswith("|") and nxt is not None and SEPARATOR.match(nxt):
                j = i + 2
                while j < n and lines[j].lstrip().startswith("|"):
                    j += 1
                out.append(self.table(lines[i:j]))
                i = j
            elif ITEM.match(line):
                markup, i = self.list(lines, i)
                out.append(markup)
            else:
                j = i + 1
                while j < n and lines[j].strip() and not starts_block(lines[j], lines[j + 1] if j + 1 < n else None):
                    j += 1
                text = self.inline(" ".join(ln.strip() for ln in lines[i:j]))
                out.append(text if tight else f"<p>{text}</p>")
                i = j
        return out

    def summary(self):
        """The first paragraph that is not a status line, as one plain sentence or two."""
        lead = ""  # a paragraph that ends in a colon only introduces what follows; used when nothing else is left
        for block in re.findall(r"<p>(.*?)</p>", self.body, flags=re.S):
            text = plain(block).strip()
            if not text or text.startswith("Status:"):
                continue
            if text.endswith(":"):
                lead = lead or text
                continue
            if len(text) <= 220:
                return text
            cut = text[:200].rsplit(" ", 1)[0].rstrip(",;:")
            return cut + "..."
        return lead


# ----- the site's pages

class Page:
    def __init__(self, src, known):
        self.src = src
        self.out = src[:-3] + ".html"
        self.doc = Doc(src, (ROOT / src).read_text(encoding="utf-8"), known)
        self.title = self.doc.title
        name = self.title.removeprefix("Decision: ")
        head, colon, _ = name.partition(":")
        self.label = head if colon and len(head.split()) <= 3 else name
        self.url = posixpath.relpath(self.out, "docs")  # from docs/


def sources():
    guide = {p.stem: f"docs/guide/{p.name}" for p in (ROOT / "docs/guide").glob("*.md")}
    first = [guide.pop(name) for name in ORDER if name in guide]
    # only these names: write mode owns docs/adr-*.html and docs/security-review-*.html, never another docs/*.html
    decisions = [f"docs/{p.name}" for p in sorted([*(ROOT / "docs").glob("adr-*.md"), *(ROOT / "docs").glob("security-review-*.md")])]
    return first + [guide[name] for name in sorted(guide)], decisions


def rail(pages, decisions, here):
    """The pages as stops on a line; the page you are on, blue, with its own headings under it (`here` None: the index)."""
    frm = posixpath.dirname(here.out if here else "docs/guide/index.html")

    def stop(p, label=None, out=None):
        mine = p is here
        link = f'<a href="{posixpath.relpath(out or p.out, frm)}"' + (' aria-current="page"' if mine else "") + f">{esc(label or p.label)}</a>"
        inner = ""
        if mine:
            levels = [h for h in p.doc.heads if h[0] in (2, 3)]
            top = min((lv for lv, _, _ in levels), default=2)  # a page with only h3s has them at the top level
            items = "".join(f'<li class="{"h2" if lv == top else "h3"}"><a href="#{attr(i)}">{esc(t)}</a></li>' for lv, i, t in levels)
            inner = f'<ol class="inner">{items}</ol>' if items else ""
        return f'<li{" class=here" if mine else ""}>{link}{inner}</li>'

    everything = f'<li{" class=here" if here is None else ""}><a href="{posixpath.relpath("docs/guide/index.html", frm)}"' + (' aria-current="page"' if here is None else "") + ">All the pages</a></li>"
    return ('<ol class="stops">' + everything + "".join(stop(p) for p in pages) + "</ol>"
            '<p class="rail-group">Decisions and reviews</p><ol class="stops">' + "".join(stop(p) for p in decisions) + "</ol>")


def shell(title, description, up, rail_html, body, foot, source=None):
    return f"""<!doctype html>
<html lang="en" data-root="{up}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{esc(title)}: kith</title>
<meta name="description" content="{attr(description)}">
<link rel="icon" href="{ICON}">
<link rel="stylesheet" href="{up}site.css">
<link rel="stylesheet" href="{up}docs.css">
<script src="{up}docs.js" defer></script>
</head>
<body>
<!-- Made by ci/site_docs.py{f' from {source}' if source else ''}: change the markdown, then run it again. -->
<header class="bar">
  <a class="brand" href="{up}index.html" aria-label="kith: the front page">
    {MARK}
    <b>kith</b>
  </a>
  <nav aria-label="Sections">
    <a href="{up}guide/index.html">Guide</a>
    <a href="{up}install.html">Install</a>
    <a class="more" href="{up}guide/index.html#decisions">Decisions</a>
    <a class="more" href="{up}index.html#numbers">Numbers</a>
  </nav>
  <a class="button quiet" href="{REPO}">GitHub</a>
</header>
<div class="doc">
<aside class="side">
  <form class="find" role="search" hidden>
    <label for="q">Search the headings</label>
    <input id="q" type="search" placeholder="Search the headings" autocomplete="off" spellcheck="false">
  </form>
  <ol class="found" aria-live="polite" hidden></ol>
  <details class="rail" open>
    <summary>The guide</summary>
    <nav aria-label="The guide's pages">{rail_html}</nav>
  </details>
</aside>
<div class="page" role="main">
{body}
{foot}
</div>
</div>
</body>
</html>
"""


def build():
    """Everything the site's docs are, as {repo path: text}, and what is wrong with the markdown."""
    guide, decisions = sources()
    known = set(guide) | set(decisions)
    pages = [Page(s, known) for s in guide]
    notes = [Page(s, known) for s in decisions]
    allp = pages + notes
    out, problems = {}, []
    by_src = {p.src: p for p in allp}
    for p in allp:
        problems += p.doc.problems
        for src, target, frag in p.doc.refs:
            if frag and frag not in by_src[target].doc.ids:
                problems.append(f"{src}: a link to {target}#{frag}, which has no such heading")
    for n, p in enumerate(allp):
        up = "../" * (p.out.count("/") - 1)
        near = [("Previous", "prev", allp[n - 1]) if n else None, ("Next", "next", allp[n + 1]) if n + 1 < len(allp) else None]
        links = "".join(f'<a class="{r}" rel="{r}" href="{posixpath.relpath(q.out, posixpath.dirname(p.out))}"><span>{w}</span>{esc(q.label)}</a>' for w, r, q in filter(None, near))
        foot = f'<footer class="tail"><nav aria-label="Next page">{links}</nav><p class="fine">This page is <a href="{REPO}/blob/main/{p.src}">{p.src}</a>.</p></footer>'
        body = f'<article>\n{p.doc.body}\n</article>'
        out[p.out] = shell(p.title, p.doc.summary(), up, rail(pages, notes, p), body, foot, p.src)
    out["docs/guide/index.html"] = shell("The guide", "kith's guide and the decisions behind it, one page for each part.", "../", rail(pages, notes, None), index_body(pages, notes), "")
    search = [{"u": "guide/index.html", "t": "The guide", "h": ""}]
    for p in allp:
        search.append({"u": p.url, "t": p.title, "h": ""})
        search += [{"u": f"{p.url}#{i}", "t": p.title, "h": t} for lv, i, t in p.doc.heads if lv in (2, 3)]
    out["docs/guide/search.json"] = "[\n" + ",\n".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in search) + "\n]\n"
    return out, problems + chrome(out)


def index_body(pages, notes):
    def entry(p):
        steps = " ".join(f'<a href="{posixpath.relpath(p.out, "docs/guide")}#{attr(i)}">{esc(t)}</a>' for lv, i, t in p.doc.heads if lv == 2)
        return (f'<li><a class="name" href="{posixpath.relpath(p.out, "docs/guide")}">{esc(p.title)}</a>'
                f'<p>{esc(p.doc.summary())}</p>' + (f'<p class="page-heads">{steps}</p>' if steps and p.src.startswith("docs/guide/") else "") + "</li>")
    return ('<article>\n<h1 id="the-guide">The guide</h1>\n'
            "<p>What kith does and how to run it, one page for each part. Each is a markdown file in the repository; these are the same words.</p>\n"
            f'<ol class="pages">{"".join(entry(p) for p in pages)}</ol>\n'
            '<h2 id="decisions">Decisions and reviews</h2>\n'
            "<p>Why a part is the way it is: what was asked, what was chosen, what was left out.</p>\n"
            f'<ol class="pages">{"".join(entry(p) for p in notes)}</ol>\n</article>')


def mark_whole(svg=MARK):
    """What of the mark's drawing (strokes and rings included) lies outside its viewBox: [] when it is all there."""
    x0, y0, w, h = map(float, re.search(r'viewBox="([^"]+)"', svg).group(1).split())
    num = lambda tag, name: float(re.search(rf'{name}="([-\d.]+)"', tag).group(1))
    out = []
    for tag in re.findall(r"<line [^>]*>", svg):  # stroke 4, round caps: 2 each way
        for x, y in ((num(tag, "x1"), num(tag, "y1")), (num(tag, "x2"), num(tag, "y2"))):
            if not (x0 <= x - 2 and x + 2 <= x0 + w and y0 <= y - 2 and y + 2 <= y0 + h):
                out.append(tag)
    for tag in re.findall(r"<circle [^>]*>", svg):
        x, y, r = num(tag, "cx"), num(tag, "cy"), num(tag, "r")
        if not (x0 <= x - r and x + r <= x0 + w and y0 <= y - r and y + r <= y0 + h):
            out.append(tag)
    return out


def chrome(out):
    """What every page of the site's docs must carry: a whole mark, an Install link, a way to the page before and after;
    and the script and styles that give code its Copy button and the page its reading line, calm under reduced motion."""
    bad = [f"the header's mark has a part outside its viewBox: {t}" for t in mark_whole()]
    for f, text in out.items():
        if not f.endswith(".html"):
            continue
        for want in ('<a href="%sinstall.html">Install</a>' % ("../" * (f.count("/") - 1)), MARK):
            if want not in text:
                bad.append(f"{f}: no {want[:30]} in its header")
        if f != "docs/guide/index.html" and not re.search(r'<footer class="tail"><nav aria-label="Next page"><a class="(prev|next)" rel=', text):
            bad.append(f"{f}: no link to the page before or after")
    js, css = ((ROOT / "docs" / n).read_text(encoding="utf-8") for n in ("docs.js", "docs.css"))
    for what, ok in (
        ("docs.js: a Copy button that writes a block's text to the clipboard", "navigator.clipboard.writeText" in js and '"Copied"' in js and "1500" in js),
        ("docs.js: the reading line (--run)", '"--run"' in js),
        ("docs.css: the Copy button and the reading line kept calm with prefers-reduced-motion",
         bool(re.search(r"prefers-reduced-motion: no-preference\)[^{]*\{[^}]*\.copy", css)) and ".page::before" in css and "--run" in css),
    ):
        if not ok:
            bad.append(f"missing: {what}")
    return bad


def used_tokens():
    """Every var(--x) of docs.css must be one site.css defines (the page may be redrawn there)."""
    have = set(re.findall(r"(--[\w-]+)\s*:", (ROOT / "docs/site.css").read_text(encoding="utf-8")))
    mine = (ROOT / "docs/docs.css").read_text(encoding="utf-8")
    own = set(re.findall(r"(--[\w-]+)\s*:", mine))
    return sorted(set(re.findall(r"var\((--[\w-]+)", mine)) - have - own)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    out, problems = build()
    stale = [f for f, text in out.items() if not (ROOT / f).is_file() or (ROOT / f).read_text(encoding="utf-8") != text]
    # what is ours and no longer made: the pages of docs/guide, and the ADR and review pages of docs/. Never another docs/*.html.
    ours = [*(ROOT / "docs/guide").glob("*.html"), *(ROOT / "docs").glob("adr-*.html"), *(ROOT / "docs").glob("security-review-*.html")]
    stale += [str(f.relative_to(ROOT)) for f in ours if str(f.relative_to(ROOT)) not in out]
    missing = used_tokens()
    if problems or missing:
        print("\n".join(problems) + ("\ndocs.css uses tokens site.css does not define: " + " ".join(missing) if missing else ""), file=sys.stderr)
        return 1
    if args.check:
        if stale:
            print("stale (run python3 ci/site_docs.py): " + " ".join(stale), file=sys.stderr)
            return 1
        print(f"docs pages current: {len(out)} files")
        return 0
    for f in stale:
        if f not in out:
            (ROOT / f).unlink()
    for f, text in out.items():
        (ROOT / f).write_text(text, encoding="utf-8")
    print(f"wrote {len(out)} files")
    return 0


# ----- the test: each thing the guide uses, and what must not get through

def self_test():
    def one(text):
        return Doc("docs/guide/os.md", text, {"docs/guide/os.md", "docs/guide/api.md"})

    def md(text):
        return one(text).body

    def eq(got, want):
        assert got == want, f"\n got: {got!r}\nwant: {want!r}"

    eq(md("# One\n\n## Two words, and: a `code`"), '<h1 id="one">One</h1>\n<h2 id="two-words-and-a-code">Two words, and: a <code>code</code> <a class="anchor" href="#two-words-and-a-code" aria-label="Link to this section">#</a></h2>')
    d = one("# A\n\n## Same\n\n## Same\n")
    eq([i for _, i, _ in d.heads], ["a", "same", "same-1"])
    eq(md("one\ntwo `a < b` and *em*, **strong**, _also_ snake_case_name"), "<p>one two <code>a &lt; b</code> and <em>em</em>, <strong>strong</strong>, <em>also</em> snake_case_name</p>")
    eq(md("2 * 3 * 4 and 5*6"), "<p>2 * 3 * 4 and 5*6</p>")
    eq(md("a \\*b\\* c"), "<p>a *b* c</p>")
    # text is escaped; nothing typed becomes a tag or an attribute
    eq(md('<script>alert("x")</script> & <b>'), "<p>&lt;script&gt;alert(\"x\")&lt;/script&gt; &amp; &lt;b&gt;</p>")
    eq(md("[x](https://e.org/?a=1&b=\"2)"), '<p><a href="https://e.org/?a=1&amp;b=&quot;2">x</a></p>')
    assert "javascript" not in one("[x](javascript:alert)").body and one("[x](javascript:alert)").problems
    eq(md("- a\n- b\n  - c\n  - d\n- e"), "<ul><li>a</li><li>b<ul><li>c</li><li>d</li></ul></li><li>e</li></ul>")
    eq(md("1. one\n   goes on\n2. two\n\n   - sub\n3. three"), "<ol><li><p>one goes on</p></li><li><p>two</p><ul><li>sub</li></ul></li><li><p>three</p></li></ol>")
    eq(md("- run:\n  ```sh\n  a - b\n  - not an item\n\n  c\n  ```\n- next"), '<ul><li>run:<pre><code class="language-sh">a - b\n- not an item\n\nc\n</code></pre></li><li>next</li></ul>')
    eq(md("```yaml\nkind: <x> & y\n```\n\n```\nplain\n```"), '<pre><code class="language-yaml">kind: &lt;x&gt; &amp; y\n</code></pre>\n<pre><code>plain\n</code></pre>')
    eq(md("| A | B |\n| --- | --- |\n| `x\\|y` | <i> |\n| short |"),
       '<div class="table"><table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td><code>x|y</code></td><td>&lt;i&gt;</td></tr><tr><td>short</td><td></td></tr></tbody></table></div>')
    eq(md("a\n\n---\n\nb"), "<p>a</p>\n<hr>\n<p>b</p>")
    eq(md("para\n- item"), "<p>para</p>\n<ul><li>item</li></ul>")
    # links: another page, its anchor, a repo file, a repo folder, an outside address
    d = one("[a](api.md#x), [b](../../SECURITY.md), [c](../../packages/web), [d](https://e.org), [e](#top), [f](../assets/../../docs/index.html)")
    eq(d.body, '<p><a href="api.html#x">a</a>, <a href="%s/blob/main/SECURITY.md">b</a>, <a href="%s/tree/main/packages/web">c</a>, <a href="https://e.org">d</a>, <a href="#top">e</a>, <a href="../index.html">f</a></p>' % (REPO, REPO))
    eq(d.refs[0], ("docs/guide/os.md", "docs/guide/api.md", "x"))
    assert one("[x](nothing-here.md)").problems and one("[x](../../../etc/passwd)").problems
    eq(md("[over\ntwo lines](api.md)"), '<p><a href="api.html">over two lines</a></p>')
    # the <picture> of a drawing: tags and attributes allowed, paths rewritten, anything else refused
    pic = '<picture>\n  <source media="(prefers-color-scheme: dark)" srcset="../../docs/assets/screens/ui-phone-dark.png">\n  <img src="../../docs/assets/screens/ui-phone-light.png" alt="a &amp; b" width="24%">\n</picture>'
    assert one(pic).problems == []
    eq(md(pic), '<p class="picture"><picture><source media="(prefers-color-scheme: dark)" srcset="../assets/screens/ui-phone-dark.png"><img src="../assets/screens/ui-phone-light.png" alt="a &amp; b" width="24%"></picture></p>')
    assert one('<picture><img src="x.png" onerror="alert(1)"></picture>').problems
    assert one("<picture><script>x</script></picture>").problems
    assert one("\x00 `a` \x000\x00").body.count("\x00") == 0
    # a numbered list that starts at 6 (after a paragraph that split it) keeps its numbers, in the markup and for the CSS counter
    eq(md("6. a\n7. b"), '<ol start="6" style="counter-reset:n 5"><li>a</li><li>b</li></ol>')
    # a summary skips a paragraph that only introduces what follows
    eq(one("# T\n\nThe parts:\n\n- a\n\nReal one.").summary(), "Real one.")
    eq(one("# T\n\nOnly this:\n").summary(), "Only this:")
    # the header's mark is checked against its own viewBox: a part outside it is named
    assert mark_whole() == [] and mark_whole(MARK.replace("12 6 40 52", "12 6 20 52")) != []
    print("site_docs self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
