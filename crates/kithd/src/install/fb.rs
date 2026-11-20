//! The installer drawn on the framebuffer, in the look of docs/install.html's Line map
//! (T-0751): paper, a rail of stops with the current one in the accent, text from a glyph
//! atlas. The colours are the tokens of docs/site.css, read at build time (build.rs).
//!
//! Answers stay typed lines; serial consoles keep their text. Where there is no 32 bpp
//! framebuffer (or none at all) nothing is drawn.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

include!(concat!(env!("OUT_DIR"), "/site.rs"));

/// The picture's size limits: a framebuffer past these is not one the installer draws on.
const MAX_SIDE: usize = 8192;
const MAX_BYTES: usize = 64 << 20;

/// The Line map's proportions at this screen's size (docs/site.css's --rail, --stop and
/// --stroke, and --gutter, at the sizes the page has on a desktop).
const MARGIN: usize = 56;
const RAIL_X: usize = 56;
const STOP: usize = 20;
const STROKE: usize = 3;
const FIRST_STOP_Y: usize = 240;
const STOP_GAP: usize = 56;
const QUESTION_SCALE: usize = 3;
const LABEL_SCALE: usize = 2;
/// A glyph's rows (the font's `[u8; 9]`): `CAP_H` down to the baseline, then two below it for
/// the tails of g, j, p, q, y, the comma and the semicolon. Lines are `LINE_H` rows apart.
const GLYPH_H: usize = 9;
const CAP_H: usize = 7;
const LINE_H: usize = GLYPH_H + 3;

/// The rail's stops, in the order the installer asks its questions (install.rs's `interview`).
pub const STOPS: [&str; 6] = ["Disk", "Name", "Address", "Join", "Encryption", "Erase"];
/// The footers: of a question, and of the recovery key's screen.
pub const ANSWER: &str = "Type the answer on a line, then press Enter.";
pub const KEY: &str = "Write the key down, then press Enter. It is shown once.";

/// Where each channel sits in a pixel's 32-bit word: the bit offsets the kernel reports
/// (`fb_var_screeninfo`'s red, green and blue `offset`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    pub red: u32,
    pub green: u32,
    pub blue: u32,
}

/// Red in the low byte, as on most x86 boards (the tests' two orders; the device gives its own).
#[cfg(test)]
pub const RGB: Order = Order {
    red: 0,
    green: 8,
    blue: 16,
};
/// Blue in the low byte.
#[cfg(test)]
pub const BGR: Order = Order {
    red: 16,
    green: 8,
    blue: 0,
};

/// A picture in memory: what is drawn here is written to the framebuffer whole.
#[derive(Clone, Debug)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    /// Bytes from one row to the next (at least `width * 4`).
    pub stride: usize,
    pub order: Order,
    pub bytes: Vec<u8>,
}

/// What the kernel says the framebuffer is: `virtual_size`, `bits_per_pixel` and `stride`
/// under /sys/class/graphics/fb0, read by `parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
}

impl Geometry {
    /// `None` unless the framebuffer is 32 bits a pixel and its rows hold the pixels.
    pub fn parse(virtual_size: &str, bits_per_pixel: &str, stride: &str) -> Option<Geometry> {
        let (width, height) = virtual_size.trim().split_once(',')?;
        let (width, height): (usize, usize) = (width.trim().parse().ok()?, height.trim().parse().ok()?);
        let bits: u32 = bits_per_pixel.trim().parse().ok()?;
        let stride: usize = stride.trim().parse().ok()?;
        let fits = (1..=MAX_SIDE).contains(&width)
            && (1..=MAX_SIDE).contains(&height)
            && stride >= width * 4
            && stride.checked_mul(height)? <= MAX_BYTES;
        (bits == 32 && fits).then_some(Geometry { width, height, stride })
    }
}

impl Frame {
    /// A black picture of the geometry, in the order the device writes its channels.
    pub fn new(geometry: Geometry, order: Order) -> Frame {
        Frame {
            width: geometry.width,
            height: geometry.height,
            stride: geometry.stride,
            order,
            bytes: vec![0; geometry.stride * geometry.height],
        }
    }

    fn at(&self, x: usize, y: usize) -> usize {
        y * self.stride + x * 4
    }

    /// The colour of the pixel at (`x`, `y`), decoded through the frame's order.
    #[cfg(test)]
    pub fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let at = self.at(x, y);
        let word = u32::from_ne_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ]);
        [
            (word >> self.order.red) as u8,
            (word >> self.order.green) as u8,
            (word >> self.order.blue) as u8,
        ]
    }

    /// Set the pixel at (`x`, `y`) (what is outside the picture is left out).
    fn put(&mut self, x: usize, y: usize, [r, g, b]: [u8; 3]) {
        if x >= self.width || y >= self.height {
            return;
        }
        let word =
            (u32::from(r) << self.order.red) | (u32::from(g) << self.order.green) | (u32::from(b) << self.order.blue);
        let at = self.at(x, y);
        self.bytes[at..at + 4].copy_from_slice(&word.to_ne_bytes());
    }

    fn rect(&mut self, x: usize, y: usize, width: usize, height: usize, colour: [u8; 3]) {
        for row in y..y + height {
            for column in x..x + width {
                self.put(column, row, colour);
            }
        }
    }

    /// Draw `text` at (`x`, `y`), each glyph `scale` times its size of the atlas, in ink
    /// only (no blending: the colours are the tokens'). Returns where the text ends.
    fn text(&mut self, x: usize, y: usize, scale: usize, text: &str, colour: [u8; 3]) -> usize {
        let mut left = x;
        for c in text.chars() {
            let code = if (' '..='~').contains(&c) {
                c as usize
            } else {
                '?' as usize
            };
            for (row, bits) in GLYPHS[code - 0x20].iter().enumerate() {
                for column in 0..5 {
                    if (bits >> (4 - column)) & 1 == 1 {
                        self.rect(left + column * scale, y + row * scale, scale, scale, colour);
                    }
                }
            }
            left += 6 * scale;
        }
        left
    }
}

/// Something a picture can be shown on: the framebuffer, or a test's recorder.
pub trait Panel {
    fn show(&mut self, frame: &Frame) -> io::Result<()>;
}

/// Break `text` into lines of at most `width` characters, at its spaces. A word longer than
/// a line (a recovery key) is cut into pieces of `width` characters, so none is clipped.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let chars: Vec<char> = word.chars().collect();
        for piece in chars.chunks(width) {
            let piece: String = piece.iter().collect();
            if !line.is_empty() && line.chars().count() + 1 + piece.chars().count() > width {
                lines.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&piece);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// The lines of `question` as drawn on a `width`-pixel picture, each with its scale: the
/// question's own lines are kept, and each is wrapped at the question's size; a line with a
/// word too long for that (a recovery key) is drawn smaller, whole.
fn layout(question: &str, width: usize) -> Vec<(String, usize)> {
    let room = width.saturating_sub(2 * MARGIN);
    let mut lines = Vec::new();
    for source in question.split('\n') {
        let longest = source
            .split_whitespace()
            .map(|word| word.chars().count())
            .max()
            .unwrap_or(0);
        let scale = if longest <= room / (6 * QUESTION_SCALE) {
            QUESTION_SCALE
        } else {
            LABEL_SCALE
        };
        let pieces = wrap(source, room / (6 * scale));
        if pieces.is_empty() {
            lines.push((String::new(), scale));
        }
        lines.extend(pieces.into_iter().map(|line| (line, scale)));
    }
    lines
}

/// Draw the install question `question` with the rail of `stops`, `current` being the stop
/// it belongs to: the stops before it in ink, it in the accent, the ones after it outlined,
/// and `footer` at the foot. Only the colours of the site's tokens are used.
pub fn draw_question(frame: &mut Frame, stops: &[&str], current: usize, question: &str, footer: &str) {
    frame.rect(0, 0, frame.width, frame.height, SITE_BG);
    let mut y = MARGIN;
    for (line, scale) in layout(question, frame.width) {
        frame.text(MARGIN, y, scale, &line, SITE_TEXT);
        y += LINE_H * scale;
    }
    let rail: Vec<(&str, &str)> = stops.iter().map(|&label| (label, "")).collect();
    draw_rail(frame, &rail, current);
    frame.text(
        MARGIN,
        frame.height.saturating_sub(MARGIN),
        LABEL_SCALE,
        footer,
        SITE_DIM,
    );
}

/// The rail's stops of an install that has its answers (the question rail's words, then the
/// write and the key): `done` of them are done, as the install goes.
pub const PROGRESS: [&str; 8] = [
    "Answers",
    "Disk",
    "Name",
    "Address",
    "Join",
    "Encryption",
    "Writing",
    "Key",
];

/// Where the progress screens' words and bar sit: the sentence under the title, the bar under
/// that (the rail starts below them).
const LINE_Y: usize = 104;
const BAR_Y: usize = 156;
const BAR_H: usize = 14;

/// The middle of stop `i` of `count` on a picture `height` tall: `STOP_GAP` apart, closer
/// where that many would run off a short screen.
fn stop_centre(height: usize, count: usize, i: usize) -> usize {
    let room = height.saturating_sub(MARGIN + FIRST_STOP_Y + STOP);
    FIRST_STOP_Y + STOP_GAP.min(room / count.saturating_sub(1).max(1)) * i
}

/// The rail: the line down the stops, and each stop with its label and its detail (what was
/// answered). Before `current` a stop is done (ink, with a tick), at it the accent, after it
/// outlined. `current == stops.len()` is all done.
fn draw_rail(frame: &mut Frame, stops: &[(&str, &str)], current: usize) {
    let (height, count) = (frame.height, stops.len());
    let centre = |i: usize| stop_centre(height, count, i);
    let last = centre(stops.len().saturating_sub(1));
    frame.rect(
        RAIL_X + (STOP - STROKE) / 2,
        FIRST_STOP_Y,
        STROKE,
        last - FIRST_STOP_Y,
        SITE_HAIR,
    );
    for (i, (label, detail)) in stops.iter().enumerate() {
        let top = centre(i) - STOP / 2;
        let (fill, text) = match i.cmp(&current) {
            std::cmp::Ordering::Less => (SITE_TEXT, SITE_TEXT),
            std::cmp::Ordering::Equal => (SITE_ACCENT, SITE_TEXT),
            std::cmp::Ordering::Greater => (SITE_BG, SITE_DIM),
        };
        frame.rect(RAIL_X, top, STOP, STOP, fill);
        if i < current {
            // (The tick: two strokes of 3-pixel dots, in paper.)
            for (x, y) in [(4, 9), (6, 11), (8, 13), (10, 11), (12, 9), (14, 7)] {
                frame.rect(RAIL_X + x, top + y, 3, 3, SITE_BG);
            }
        }
        if i > current {
            frame.rect(RAIL_X, top, STOP, STROKE, SITE_HAIR);
            frame.rect(RAIL_X, top + STOP - STROKE, STOP, STROKE, SITE_HAIR);
            frame.rect(RAIL_X, top, STROKE, STOP, SITE_HAIR);
            frame.rect(RAIL_X + STOP - STROKE, top, STROKE, STOP, SITE_HAIR);
        }
        let y = centre(i) - CAP_H * LABEL_SCALE / 2;
        let end = frame.text(RAIL_X + 2 * STOP, y, LABEL_SCALE, label, text);
        if !detail.is_empty() && i <= current {
            frame.text(end + 3 * 6 * LABEL_SCALE, y, LABEL_SCALE, detail, SITE_DIM);
        }
    }
}

/// Draw an install that is under way: `title`, a sentence `line` under it (two lines at most),
/// the bar when `bar` is `Some(percent)`, the rail of `stops` (label and detail) with `done` of
/// them done, and `footer` at the foot. Only the colours of the site's tokens are used.
pub fn draw_progress(
    frame: &mut Frame,
    stops: &[(&str, &str)],
    done: usize,
    bar: Option<u64>,
    title: &str,
    line: &str,
    footer: &str,
) {
    frame.rect(0, 0, frame.width, frame.height, SITE_BG);
    let mut y = MARGIN;
    for (piece, scale) in layout(title, frame.width) {
        frame.text(MARGIN, y, scale, &piece, SITE_TEXT);
        y += LINE_H * scale;
    }
    let room = frame.width.saturating_sub(2 * MARGIN);
    for (n, piece) in wrap(line, room / (6 * LABEL_SCALE)).iter().take(2).enumerate() {
        frame.text(MARGIN, LINE_Y + n * LINE_H * LABEL_SCALE, LABEL_SCALE, piece, SITE_DIM);
    }
    if let Some(percent) = bar {
        let percent = percent.min(100);
        frame.rect(MARGIN, BAR_Y, room, BAR_H, SITE_HAIR);
        frame.rect(MARGIN, BAR_Y, room * percent as usize / 100, BAR_H, SITE_ACCENT);
        let said = format!("{percent}%");
        frame.text(MARGIN, BAR_Y + BAR_H + 10, LABEL_SCALE, &said, SITE_TEXT);
    }
    draw_rail(frame, stops, done);
    frame.text(
        MARGIN,
        frame.height.saturating_sub(MARGIN),
        LABEL_SCALE,
        footer,
        SITE_DIM,
    );
}

/// Draw the end of an install: `title` and `text` over the rail with every stop done.
pub fn draw_end(frame: &mut Frame, stops: &[(&str, &str)], title: &str, text: &str) {
    draw_progress(frame, stops, stops.len(), None, title, text, "");
}

/// Show the picture `shown`, wait for a key (`wait_for_key`), then show it cleared, whatever
/// happened before: a show that failed part-way leaves part of the picture, so it is cleared
/// too, and no key is waited for on a picture that is not there. Nothing is written anywhere
/// but to the panel.
pub fn hold_until_key(
    panel: &mut dyn Panel,
    shown: &Frame,
    wait_for_key: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let waited = panel.show(shown).and_then(|()| wait_for_key());
    let mut cleared = shown.clone();
    cleared.bytes.fill(0);
    let cleared = panel.show(&cleared);
    waited.and(cleared)
}

/// The geometry the kernel gives the framebuffer at `sysfs` (the `fb0` directory of
/// /sys/class/graphics), when it is 32 bits a pixel.
pub fn geometry(sysfs: &Path) -> Option<Geometry> {
    let read = |name: &str| std::fs::read_to_string(sysfs.join(name)).ok();
    Geometry::parse(&read("virtual_size")?, &read("bits_per_pixel")?, &read("stride")?)
}

/// The framebuffer, `/dev/fb0`, with the console (`/dev/tty0`) in graphics mode while it is
/// held, so that the kernel draws no text over the picture; text again when dropped.
pub struct Device {
    file: File,
    tty: Option<File>,
    geometry: Geometry,
    order: Order,
    /// The kernel's console log level before the picture, put back when it is dropped.
    loglevel: Option<String>,
}

/// The kernel's console log levels (`console_loglevel`, then three more), and the first of
/// them as one the picture needs: only emergencies reach the console.
const LOGLEVEL: &str = "/proc/sys/kernel/printk";

/// The framebuffer, when there is one this installer draws on.
pub fn open() -> Option<Device> {
    let geometry = geometry(Path::new("/sys/class/graphics/fb0"))?;
    let file = OpenOptions::new().write(true).open("/dev/fb0").ok()?;
    let [red, green, blue] = kith_dm_sys::fb_channels(&file).ok()?;
    let fits = |bit: u32| bit <= 24 && bit.is_multiple_of(8);
    if ![red, green, blue].into_iter().all(fits) || red == green || green == blue || red == blue {
        return None;
    }
    let tty = OpenOptions::new()
        .write(true)
        .open("/dev/tty0")
        .ok()
        .filter(|tty| kith_dm_sys::set_graphics(tty, true).is_ok());
    // (The graphics mode keeps the kernel's text off the picture on the screen; the level keeps it
    // off a console that is drawn on another way. A machine that lets neither be set is drawn on.)
    let loglevel = std::fs::read_to_string(LOGLEVEL)
        .ok()
        .filter(|_| std::fs::write(LOGLEVEL, "1").is_ok());
    Some(Device {
        file,
        tty,
        geometry,
        order: Order { red, green, blue },
        loglevel,
    })
}

impl Device {
    /// A black picture of the framebuffer's size, to draw on.
    pub fn frame(&self) -> Frame {
        Frame::new(self.geometry, self.order)
    }
}

impl Panel for Device {
    fn show(&mut self, frame: &Frame) -> io::Result<()> {
        if frame.stride != self.geometry.stride || frame.height != self.geometry.height || frame.order != self.order {
            return Err(io::Error::other("the picture is not the framebuffer's"));
        }
        self.file.write_all_at(&frame.bytes, 0)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(tty) = &mut self.tty {
            // (The console keeps its text while it draws none, and the questions and the key were
            // printed to it: cleared first (home, erase screen, erase scrollback), they do not
            // come back with the text.)
            let _ = tty.write_all(b"\x1b[H\x1b[2J\x1b[3J");
            let _ = kith_dm_sys::set_graphics(tty, false);
        }
        if let Some(levels) = &self.loglevel {
            let _ = std::fs::write(LOGLEVEL, levels.trim());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SITE_CSS: &str = include_str!("../../../../docs/site.css");
    const QUESTION: &str = "Install kith OS on which disk?";

    fn screen(stride: usize, order: Order) -> Frame {
        Frame::new(
            Geometry {
                width: 800,
                height: 600,
                stride,
            },
            order,
        )
    }

    /// The first `:root` block of docs/site.css, the one the build reads.
    fn root_block() -> &'static str {
        let root = SITE_CSS.find(":root {").expect("docs/site.css has a :root block");
        &SITE_CSS[root..root + SITE_CSS[root..].find('}').expect("closed")]
    }

    fn hex(value: &str) -> [u8; 3] {
        let n = u32::from_str_radix(value.get(..6).expect("six hex digits"), 16).expect("a hex colour");
        [(n >> 16) as u8, (n >> 8) as u8, n as u8]
    }

    /// The colour the site gives `--name`.
    fn site(name: &str) -> [u8; 3] {
        let prefix = format!("--{name}:");
        let line = root_block()
            .lines()
            .find(|line| line.trim().starts_with(&prefix))
            .expect(name);
        hex(line.split('#').nth(1).expect("a hex colour"))
    }

    /// Every colour of the first `:root` block.
    fn site_colours() -> Vec<[u8; 3]> {
        root_block()
            .lines()
            .filter_map(|line| line.split('#').nth(1))
            .map(hex)
            .collect()
    }

    fn pixels(frame: &Frame) -> Vec<[u8; 3]> {
        (0..frame.height)
            .flat_map(|y| (0..frame.width).map(move |x| (x, y)))
            .map(|(x, y)| frame.pixel(x, y))
            .collect()
    }

    fn accent_rows(frame: &Frame) -> Vec<usize> {
        let accent = site("accent");
        (0..frame.height)
            .filter(|&y| (0..frame.width).any(|x| frame.pixel(x, y) == accent))
            .collect()
    }

    #[test]
    fn fb_question_is_mostly_paper_with_the_accent_on_the_current_stop() {
        let mut frame = screen(3200, RGB);
        draw_question(&mut frame, &STOPS, 1, QUESTION, ANSWER);
        let all = pixels(&frame);
        let on_paper = all.iter().filter(|&&p| p == site("bg")).count();
        assert!(
            on_paper * 10 >= all.len() * 6,
            "only {on_paper} of {} pixels are paper",
            all.len()
        );
        assert!(
            !accent_rows(&frame).is_empty(),
            "the current stop is not drawn in the accent"
        );
    }

    #[test]
    fn fb_the_accent_moves_with_the_current_stop() {
        let mut first = screen(3200, RGB);
        draw_question(&mut first, &STOPS, 1, QUESTION, ANSWER);
        let mut last = screen(3200, RGB);
        draw_question(&mut last, &STOPS, 4, QUESTION, ANSWER);
        let (a, b) = (accent_rows(&first), accent_rows(&last));
        assert!(!a.is_empty() && !b.is_empty());
        assert!(
            a.iter().sum::<usize>() / a.len() < b.iter().sum::<usize>() / b.len(),
            "stop 4 is not below stop 1"
        );
    }

    #[test]
    fn fb_only_token_colours_are_drawn() {
        let mut frame = screen(3200, RGB);
        draw_question(&mut frame, &STOPS, 1, QUESTION, ANSWER);
        let tokens = site_colours();
        for p in pixels(&frame) {
            assert!(tokens.contains(&p), "{p:?} is not a colour of docs/site.css's :root");
        }
    }

    #[test]
    fn fb_a_wide_stride_and_bgr_draw_the_same_picture() {
        let mut rgb = screen(3200, RGB);
        draw_question(&mut rgb, &STOPS, 2, QUESTION, ANSWER);
        let mut bgr = screen(832 * 4, BGR);
        draw_question(&mut bgr, &STOPS, 2, QUESTION, ANSWER);
        for y in 0..600 {
            for x in 0..800 {
                assert_eq!(rgb.pixel(x, y), bgr.pixel(x, y), "pixel {x},{y} differs");
            }
        }
        for y in 0..600 {
            assert!(
                bgr.bytes[y * 3328 + 3200..y * 3328 + 3328].iter().all(|&b| b == 0),
                "row {y} padding was drawn on"
            );
        }
    }

    #[test]
    fn fb_16_bpp_or_no_device_is_text() {
        assert_eq!(Geometry::parse("800,600", "16", "1600"), None);
        assert_eq!(
            Geometry::parse("800,600", "32", "3200"),
            Some(Geometry {
                width: 800,
                height: 600,
                stride: 3200
            })
        );
        assert_eq!(
            Geometry::parse("800,600", "32", "1000"),
            None,
            "a stride too short for its row is refused"
        );
        assert_eq!(geometry(Path::new("/nonexistent/fb0")), None);
    }

    #[test]
    fn fb_a_word_longer_than_a_line_is_broken_not_clipped() {
        let key = format!("kith1.{}", "0123456789abcdef".repeat(4));
        let lines = wrap(&key, 20);
        assert!(lines.iter().all(|line| line.chars().count() <= 20), "{lines:?}");
        assert_eq!(lines.concat(), key);
    }

    #[test]
    fn fb_key_screen_holds_until_a_key_then_clears() {
        struct Recorder<'a> {
            log: &'a RefCell<Vec<&'static str>>,
        }
        impl Panel for Recorder<'_> {
            fn show(&mut self, frame: &Frame) -> io::Result<()> {
                let blank = frame.bytes.iter().all(|&b| b == 0);
                self.log.borrow_mut().push(if blank { "clear" } else { "show" });
                Ok(())
            }
        }
        let log = RefCell::new(Vec::new());
        let mut shown = screen(3200, RGB);
        draw_question(&mut shown, &STOPS, STOPS.len() - 1, "kith1.0123456789abcdef", KEY);
        let mut panel = Recorder { log: &log };
        hold_until_key(&mut panel, &shown, || {
            log.borrow_mut().push("key");
            Ok(())
        })
        .expect("held");
        assert_eq!(*log.borrow(), ["show", "key", "clear"]);
    }

    #[test]
    fn fb_key_screen_clears_even_when_the_first_show_fails() {
        struct Torn<'a> {
            log: &'a RefCell<Vec<&'static str>>,
        }
        impl Panel for Torn<'_> {
            fn show(&mut self, frame: &Frame) -> io::Result<()> {
                let blank = frame.bytes.iter().all(|&b| b == 0);
                self.log.borrow_mut().push(if blank { "clear" } else { "show" });
                if blank {
                    Ok(())
                } else {
                    Err(io::Error::other("part of the picture written"))
                }
            }
        }
        let log = RefCell::new(Vec::new());
        let mut shown = screen(3200, RGB);
        draw_question(&mut shown, &STOPS, STOPS.len() - 1, "kith1.0123456789abcdef", KEY);
        let mut panel = Torn { log: &log };
        let held = hold_until_key(&mut panel, &shown, || {
            log.borrow_mut().push("key");
            Ok(())
        });
        assert!(held.is_err(), "the failed show is reported");
        assert_eq!(
            *log.borrow(),
            ["show", "clear"],
            "a picture half-written is cleared, and no key is waited for"
        );
    }

    #[test]
    fn fb_the_recovery_key_is_on_a_line_of_its_own_at_800_px() {
        let key = "kith1.0123456789abcdef0123456789abcdef0";
        assert_eq!(key.len(), 39);
        assert_eq!(
            layout(&format!("Recovery key:\n{key}"), 800),
            [
                ("Recovery key:".to_string(), QUESTION_SCALE),
                (key.to_string(), LABEL_SCALE)
            ],
            "the key is drawn whole, at the smaller size that fits it"
        );
    }

    #[test]
    fn fb_newlines_in_a_question_are_kept() {
        let question = "Install kith OS on which disk?\nvda 2 GB\n\nvdb 4 GB";
        let lines: Vec<String> = layout(question, 800).into_iter().map(|(line, _)| line).collect();
        assert_eq!(lines, ["Install kith OS on which disk?", "vda 2 GB", "", "vdb 4 GB"]);
    }

    fn steps() -> Vec<(&'static str, &'static str)> {
        PROGRESS.iter().map(|&label| (label, "detail")).collect()
    }

    /// The pixel at the middle of the left edge of stop `i`'s square.
    fn stop_edge(frame: &Frame, i: usize) -> [u8; 3] {
        frame.pixel(RAIL_X + 1, stop_centre(frame.height, PROGRESS.len(), i))
    }

    #[test]
    fn fb_progress_marks_the_stops_done_current_and_to_come() {
        let mut frame = screen(3200, RGB);
        draw_progress(&mut frame, &steps(), 3, None, "Writing", "Do not power off.", "");
        for i in 0..PROGRESS.len() {
            let want = match i.cmp(&3) {
                std::cmp::Ordering::Less => site("text"),
                std::cmp::Ordering::Equal => site("accent"),
                std::cmp::Ordering::Greater => site("hair"),
            };
            assert_eq!(stop_edge(&frame, i), want, "stop {i}");
        }
        // A done stop carries a tick in paper; one to come is outlined and empty inside.
        let top = |i: usize| stop_centre(frame.height, PROGRESS.len(), i) - STOP / 2;
        assert_eq!(frame.pixel(RAIL_X + 5, top(0) + 10), site("bg"), "stop 0 has no tick");
        assert_eq!(frame.pixel(RAIL_X + 10, top(5) + 10), site("bg"));
        let last = stop_centre(frame.height, PROGRESS.len(), PROGRESS.len() - 1);
        assert!(
            last + STOP / 2 < frame.height - MARGIN,
            "the rail fits an 800x600 screen"
        );
    }

    #[test]
    fn fb_progress_bar_width_follows_the_percent() {
        let width = 800 - 2 * MARGIN;
        let accent_in_bar = |percent: u64| {
            let mut frame = screen(3200, RGB);
            draw_progress(&mut frame, &steps(), 6, Some(percent), "Writing", "", "");
            (0..800)
                .filter(|&x| frame.pixel(x, BAR_Y + BAR_H / 2) == site("accent"))
                .count()
        };
        assert_eq!(accent_in_bar(0), 0);
        assert_eq!(accent_in_bar(10), width / 10);
        assert_eq!(accent_in_bar(37), width * 37 / 100, "finer than tenths");
        assert_eq!(accent_in_bar(100), width);
        assert_eq!(accent_in_bar(250), width, "more than all is all");
        let mut none = screen(3200, RGB);
        draw_progress(&mut none, &steps(), 6, None, "Writing", "", "");
        assert!(
            (0..800).all(|x| none.pixel(x, BAR_Y + BAR_H / 2) == site("bg")),
            "no bar where there is no progress"
        );
    }

    #[test]
    fn fb_end_screen_has_its_text_and_every_stop_done() {
        let mut frame = screen(3200, RGB);
        let text = "Powering off. Take the installer out, then start this machine from its disk.";
        draw_end(&mut frame, &steps(), "kith OS is installed", text);
        let mut title = screen(3200, RGB);
        title.rect(0, 0, 800, 600, site("bg"));
        title.text(MARGIN, MARGIN, QUESTION_SCALE, "kith OS is installed", site("text"));
        for y in MARGIN..MARGIN + GLYPH_H * QUESTION_SCALE {
            for x in 0..800 {
                assert_eq!(frame.pixel(x, y), title.pixel(x, y), "title pixel {x},{y}");
            }
        }
        let mut line = screen(3200, RGB);
        line.rect(0, 0, 800, 600, site("bg"));
        let room = (800 - 2 * MARGIN) / (6 * LABEL_SCALE);
        for (n, piece) in wrap(text, room).iter().enumerate() {
            line.text(
                MARGIN,
                LINE_Y + n * LINE_H * LABEL_SCALE,
                LABEL_SCALE,
                piece,
                site("dim"),
            );
        }
        for y in LINE_Y..LINE_Y + (LINE_H + GLYPH_H) * LABEL_SCALE {
            for x in 0..800 {
                assert_eq!(frame.pixel(x, y), line.pixel(x, y), "end text pixel {x},{y}");
            }
        }
        assert!(accent_rows(&frame).is_empty(), "nothing is current at the end");
        for i in 0..PROGRESS.len() {
            assert_eq!(stop_edge(&frame, i), site("text"), "stop {i} is done");
        }
    }

    #[test]
    fn fb_progress_and_end_screens_use_only_the_sites_colours() {
        let tokens = site_colours();
        let mut frame = screen(3200, BGR);
        draw_progress(
            &mut frame,
            &steps(),
            6,
            Some(42),
            "Writing",
            "Writing kith OS to vdb.",
            "Wait.",
        );
        let mut end = screen(3200, BGR);
        draw_end(&mut end, &steps(), "kith OS is installed", "Powering off.");
        for p in pixels(&frame).into_iter().chain(pixels(&end)) {
            assert!(tokens.contains(&p), "{p:?} is not a colour of docs/site.css's :root");
        }
    }

    /// Whether any pixel of the box (x, y, w, h) on `frame` is not paper.
    fn has_ink(frame: &Frame, x: usize, y: usize, w: usize, h: usize) -> bool {
        (y..y + h).any(|row| (x..x + w).any(|column| frame.pixel(column, row) != site("bg")))
    }

    #[test]
    fn fb_descenders_hang_below_the_baseline_and_stay_in_their_line() {
        // A glyph is nine rows: seven down to the baseline, two below it.
        for scale in [1, 2, 3] {
            let mut frame = screen(3200, RGB);
            frame.rect(0, 0, 800, 600, site("bg"));
            let top = 100;
            let tails = "gjpqy,;";
            frame.text(MARGIN, top, scale, tails, site("text"));
            for (n, c) in tails.chars().enumerate() {
                let x = MARGIN + n * 6 * scale;
                assert!(
                    has_ink(&frame, x, top + 7 * scale, 5 * scale, 2 * scale),
                    "{c:?} has no tail below the baseline at scale {scale}"
                );
            }
            // Nothing runs past its nine rows into the line below (a line is twelve rows apart).
            assert!(
                !has_ink(&frame, 0, top + 9 * scale, 800, 3 * scale),
                "a tail spills into the next line at scale {scale}"
            );
            // The letters without tails have none.
            let mut plain = screen(3200, RGB);
            plain.rect(0, 0, 800, 600, site("bg"));
            plain.text(MARGIN, top, scale, "aceiortu.:", site("text"));
            assert!(
                !has_ink(&plain, 0, top + 7 * scale, 800, 5 * scale),
                "a glyph without a tail has ink below the baseline at scale {scale}"
            );
        }
    }

    #[test]
    fn fb_key_screen_writes_no_log_or_kernel_ring() {
        let production = include_str!("fb.rs").split("#[cfg(test)]").next().expect("the module");
        for sink in [
            "eprint", "println", "print!", "kmsg", "log::", "info!", "warn!", "debug!", "trace!", "syslog",
        ] {
            assert!(!production.contains(sink), "fb.rs writes with `{sink}`");
        }
    }
}
