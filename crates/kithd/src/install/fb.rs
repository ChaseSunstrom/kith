//! The installer drawn on the framebuffer, in the look of docs/install.html's Line map
//! (T-0751): paper, a rail of stops with the current one in the accent, text from a glyph
//! atlas. The colours are the tokens of docs/site.css, read at build time (build.rs).
//!
//! Answers stay typed lines; serial consoles keep their text. Where there is no 32 bpp
//! framebuffer (or none at all) nothing is drawn.

use std::fs::{File, OpenOptions};
use std::io;
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
pub const RGB: Order = Order { red: 0, green: 8, blue: 16 };
/// Blue in the low byte.
#[cfg(test)]
pub const BGR: Order = Order { red: 16, green: 8, blue: 0 };

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
        let word = u32::from_ne_bytes([self.bytes[at], self.bytes[at + 1], self.bytes[at + 2], self.bytes[at + 3]]);
        [(word >> self.order.red) as u8, (word >> self.order.green) as u8, (word >> self.order.blue) as u8]
    }

    /// Set the pixel at (`x`, `y`) (what is outside the picture is left out).
    fn put(&mut self, x: usize, y: usize, [r, g, b]: [u8; 3]) {
        if x >= self.width || y >= self.height {
            return;
        }
        let word = (u32::from(r) << self.order.red)
            | (u32::from(g) << self.order.green)
            | (u32::from(b) << self.order.blue);
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
            let code = if (' '..='~').contains(&c) { c as usize } else { '?' as usize };
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

/// Draw the install question `question` with the rail of `stops`, `current` being the stop
/// it belongs to: the stops before it in ink, it in the accent, the ones after it outlined,
/// and `footer` at the foot. Only the colours of the site's tokens are used.
pub fn draw_question(frame: &mut Frame, stops: &[&str], current: usize, question: &str, footer: &str) {
    frame.rect(0, 0, frame.width, frame.height, SITE_BG);
    let per_line = frame.width.saturating_sub(2 * MARGIN) / (6 * QUESTION_SCALE);
    let mut y = MARGIN;
    for line in wrap(question, per_line) {
        frame.text(MARGIN, y, QUESTION_SCALE, &line, SITE_TEXT);
        y += 10 * QUESTION_SCALE;
    }
    let last = FIRST_STOP_Y + STOP_GAP * stops.len().saturating_sub(1);
    frame.rect(RAIL_X + (STOP - STROKE) / 2, FIRST_STOP_Y, STROKE, last - FIRST_STOP_Y, SITE_HAIR);
    for (i, label) in stops.iter().enumerate() {
        let centre = FIRST_STOP_Y + STOP_GAP * i;
        let top = centre - STOP / 2;
        let (fill, text) = match i.cmp(&current) {
            std::cmp::Ordering::Less => (SITE_TEXT, SITE_DIM),
            std::cmp::Ordering::Equal => (SITE_ACCENT, SITE_TEXT),
            std::cmp::Ordering::Greater => (SITE_BG, SITE_DIM),
        };
        frame.rect(RAIL_X, top, STOP, STOP, fill);
        if i > current {
            frame.rect(RAIL_X, top, STOP, STROKE, SITE_HAIR);
            frame.rect(RAIL_X, top + STOP - STROKE, STOP, STROKE, SITE_HAIR);
            frame.rect(RAIL_X, top, STROKE, STOP, SITE_HAIR);
            frame.rect(RAIL_X + STOP - STROKE, top, STROKE, STOP, SITE_HAIR);
        }
        frame.text(RAIL_X + 2 * STOP, centre - 7 * LABEL_SCALE / 2, LABEL_SCALE, label, text);
    }
    frame.text(MARGIN, frame.height.saturating_sub(MARGIN), LABEL_SCALE, footer, SITE_DIM);
}

/// Show the picture `shown`, wait for a key (`wait_for_key`), then show it cleared, whatever
/// the wait gave. Nothing is written anywhere but to the panel.
pub fn hold_until_key(
    panel: &mut dyn Panel,
    shown: &Frame,
    wait_for_key: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    panel.show(shown)?;
    let waited = wait_for_key();
    let mut cleared = shown.clone();
    cleared.bytes.fill(0);
    panel.show(&cleared)?;
    waited
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
}

/// The framebuffer, when there is one this installer draws on.
pub fn open() -> Option<Device> {
    let geometry = geometry(Path::new("/sys/class/graphics/fb0"))?;
    let file = OpenOptions::new().write(true).open("/dev/fb0").ok()?;
    let [red, green, blue] = kith_dm_sys::fb_channels(&file).ok()?;
    let fits = |bit: u32| bit <= 24 && bit % 8 == 0;
    if ![red, green, blue].into_iter().all(fits) || red == green || green == blue || red == blue {
        return None;
    }
    let tty = OpenOptions::new()
        .write(true)
        .open("/dev/tty0")
        .ok()
        .filter(|tty| kith_dm_sys::set_graphics(tty, true).is_ok());
    Some(Device { file, tty, geometry, order: Order { red, green, blue } })
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
        if let Some(tty) = &self.tty {
            let _ = kith_dm_sys::set_graphics(tty, false);
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
        Frame::new(Geometry { width: 800, height: 600, stride }, order)
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
        let line = root_block().lines().find(|line| line.trim().starts_with(&prefix)).expect(name);
        hex(line.split('#').nth(1).expect("a hex colour"))
    }

    /// Every colour of the first `:root` block.
    fn site_colours() -> Vec<[u8; 3]> {
        root_block().lines().filter_map(|line| line.split('#').nth(1)).map(hex).collect()
    }

    fn pixels(frame: &Frame) -> Vec<[u8; 3]> {
        (0..frame.height).flat_map(|y| (0..frame.width).map(move |x| (x, y))).map(|(x, y)| frame.pixel(x, y)).collect()
    }

    fn accent_rows(frame: &Frame) -> Vec<usize> {
        let accent = site("accent");
        (0..frame.height).filter(|&y| (0..frame.width).any(|x| frame.pixel(x, y) == accent)).collect()
    }

    #[test]
    fn fb_question_is_mostly_paper_with_the_accent_on_the_current_stop() {
        let mut frame = screen(3200, RGB);
        draw_question(&mut frame, &STOPS, 1, QUESTION, ANSWER);
        let all = pixels(&frame);
        let on_paper = all.iter().filter(|&&p| p == site("bg")).count();
        assert!(on_paper * 10 >= all.len() * 6, "only {on_paper} of {} pixels are paper", all.len());
        assert!(!accent_rows(&frame).is_empty(), "the current stop is not drawn in the accent");
    }

    #[test]
    fn fb_the_accent_moves_with_the_current_stop() {
        let mut first = screen(3200, RGB);
        draw_question(&mut first, &STOPS, 1, QUESTION, ANSWER);
        let mut last = screen(3200, RGB);
        draw_question(&mut last, &STOPS, 4, QUESTION, ANSWER);
        let (a, b) = (accent_rows(&first), accent_rows(&last));
        assert!(!a.is_empty() && !b.is_empty());
        assert!(a.iter().sum::<usize>() / a.len() < b.iter().sum::<usize>() / b.len(), "stop 4 is not below stop 1");
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
            assert!(bgr.bytes[y * 3328 + 3200..y * 3328 + 3328].iter().all(|&b| b == 0), "row {y} padding was drawn on");
        }
    }

    #[test]
    fn fb_16_bpp_or_no_device_is_text() {
        assert_eq!(Geometry::parse("800,600", "16", "1600"), None);
        assert_eq!(Geometry::parse("800,600", "32", "3200"), Some(Geometry { width: 800, height: 600, stride: 3200 }));
        assert_eq!(Geometry::parse("800,600", "32", "1000"), None, "a stride too short for its row is refused");
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
    fn fb_key_screen_writes_no_log_or_kernel_ring() {
        let production = include_str!("fb.rs").split("#[cfg(test)]").next().expect("the module");
        for sink in ["eprint", "println", "print!", "kmsg", "log::", "info!", "warn!", "debug!", "trace!", "syslog"] {
            assert!(!production.contains(sink), "fb.rs writes with `{sink}`");
        }
    }
}
