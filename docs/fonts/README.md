# The face

`overpass.woff2` is [Overpass](https://github.com/RedHatOfficial/Overpass) (SIL Open Font
License 1.1, in `OFL.txt`; the copyright and the licence are also in the file's own name
table), cut down to Latin. The website loads it, and kithd carries the same file for its
web UI (`crates/kithd/src/ui.rs`).

Made from `ofl/overpass/Overpass[wght].ttf` of [google/fonts](https://github.com/google/fonts)
(sha256 `970717df17a7f9911dee45f60695d05bfa9d745fa0a11fc5c348371fa21f0073`) with
[fontTools](https://github.com/fonttools/fonttools) 4.63 and brotli:

```sh
python3 -m fontTools.subset 'Overpass[wght].ttf' \
  --unicodes='U+0020-007E,U+00A0-00FF,U+2013,U+2014,U+2018,U+2019,U+201C,U+201D,U+2026,U+00B7,U+2192' \
  --layout-features='kern,liga,tnum,calt' --name-IDs='0,1,2,3,4,5,6,13,14' \
  --flavor=woff2 --output-file=overpass.woff2
```

A character outside those ranges is drawn in the reader's own sans.
