# Vendored assets

## `inter-latin.ttf`

The Latin subset of **Inter**, converted from `web/public/fonts/inter-latin.woff2` — the file this
repository already ships for the web client (`ENC-135`). Licensed under the SIL Open Font License;
the licence text is `web/public/fonts/LICENSE` and covers this file too.

**Converted, not downloaded.** `fontTools` was used to clear the `woff2` flavour and write a plain
TTF; nothing was fetched. That matters for provenance: the glyphs a watermark draws are the same
glyphs the interface renders, from one set of bytes somebody already reviewed, rather than a second
download nobody diffed against the first.

    python3 -c "from fontTools.ttLib import TTFont; f=TTFont('web/public/fonts/inter-latin.woff2'); f.flavor=None; f.save('crates/preview/assets/inter-latin.ttf')"

**Why a TTF at all.** `ab_glyph` rasterises OpenType outlines and cannot read `woff2`, which is
Brotli-compressed — decompressing at runtime would mean a compression dependency in the request
path to save 74 KB on disk.

**Coverage: 230 codepoints.** Latin and Latin-Extended. No CJK, Arabic or Cyrillic —
`crates/preview/src/composite.rs` documents what the compositor does when a name falls outside that,
and `ENC-173` tracks widening it.
