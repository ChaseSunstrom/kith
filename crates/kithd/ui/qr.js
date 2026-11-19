// A QR code for the page: ISO 18004, byte mode, error correction L, versions 1 to 40, the mask
// that costs least (the standard's four penalties, scored as qrencode scores them), drawn on a
// canvas, so the page's policy (`img-src 'self'`, no inline anything) has nothing to stop. It is
// here for one thing: a peer's WireGuard configuration, shown to a phone's camera once. The
// matrix is the same as `qrencode -8 -l L` gives: crates/kithd/ui/test.mjs holds the proof.
//
// Nothing here keeps what it is given: a function of its arguments, and a canvas drawn on.

// Index: version - 1. Error correction codewords per block, and blocks, at level L.
const ECC = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30];
const BLOCKS = [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25];

/** The codewords a version holds, data and error correction. */
function codewords(version) {
  let modules = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const marks = Math.floor(version / 7) + 2;
    modules -= (25 * marks - 10) * marks - 55;
    if (version >= 7) modules -= 36;
  }
  return Math.floor(modules / 8);
}

/** How many bytes the largest code (version 40) holds at level L. */
export const MOST = codewords(40) - ECC[39] * BLOCKS[39] - 3;

// GF(256) with x^8 + x^4 + x^3 + x^2 + 1.
const EXP = new Uint8Array(510);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = EXP[i + 255] = x;
  LOG[x] = i;
  x = (x << 1) ^ (x & 128 ? 0x11d : 0);
}
const times = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

/** The `count` error correction codewords of `data`. */
function remainder(data, count) {
  let divisor = [1];
  for (let i = 0; i < count; i++) {
    const next = new Array(divisor.length + 1).fill(0);
    divisor.forEach((c, j) => {
      next[j] ^= c;
      next[j + 1] ^= times(c, EXP[i]);
    });
    divisor = next;
  }
  const rest = new Array(count).fill(0);
  for (const byte of data) {
    const factor = byte ^ rest.shift();
    rest.push(0);
    divisor.slice(1).forEach((c, i) => {
      rest[i] ^= times(c, factor);
    });
  }
  return rest;
}

/** The bytes of the text, as the code carries them: padded to the version, blocks interleaved with their error correction. */
function stream(bytes, version) {
  const room = codewords(version) - ECC[version - 1] * BLOCKS[version - 1];
  const bits = [];
  const put = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(4, 4); // byte mode
  put(bytes.length, version < 10 ? 8 : 16);
  for (const byte of bytes) put(byte, 8);
  put(0, Math.min(4, room * 8 - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < room * 8; pad ^= 0xec ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));

  const [count, per, total] = [BLOCKS[version - 1], ECC[version - 1], codewords(version)];
  const short = count - (total % count);
  const shortLength = Math.floor(total / count);
  const blocks = [];
  for (let i = 0, k = 0; i < count; i++) {
    const part = data.slice(k, k + shortLength - per + (i < short ? 0 : 1));
    k += part.length;
    const check = remainder(part, per);
    if (i < short) part.push(0); // (a hole where the longer blocks have one more)
    blocks.push(part.concat(check));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, j) => {
      if (i !== shortLength - per || j >= short) out.push(block[i]);
    });
  }
  return out;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => ((((x + y) % 2) + ((x * y) % 3)) % 2) === 0,
];

/** The code's function modules (finders, timing, alignment, version) drawn; `fixed` is where they are. */
function frame(version) {
  const size = 17 + 4 * version;
  const dark = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, on) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    dark[y][x] = on;
    fixed[y][x] = true;
  };
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) set(cx + dx, cy + dy, ![2, 4].includes(Math.max(Math.abs(dx), Math.abs(dy))));
    }
  }
  const marks = version === 1 ? 0 : Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (marks * 2 - 2)) * 2;
  const at = [6];
  for (let p = size - 7; at.length < marks; p -= step) at.splice(1, 0, p);
  at.forEach((cx, i) => at.forEach((cy, j) => {
    if ((i === 0 && j === 0) || (i === 0 && j === marks - 1) || (i === marks - 1 && j === 0)) return;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }));
  if (version >= 7) {
    let rest = version;
    for (let i = 0; i < 12; i++) rest = (rest << 1) ^ ((rest >>> 11) * 0x1f25);
    const bits = (version << 12) | rest;
    for (let i = 0; i < 18; i++) {
      const on = ((bits >>> i) & 1) !== 0;
      set(size - 11 + (i % 3), Math.floor(i / 3), on);
      set(Math.floor(i / 3), size - 11 + (i % 3), on);
    }
  }
  const into = { size, dark, fixed, set };
  format(into, 0); // (the format bits are the mask's to say later: here, only where they go)
  return into;
}

/** The format bits (level L, `mask`) written round the finders, and the dark module. */
function format(into, mask) {
  const { size, set } = into;
  let rest = (1 << 3) | mask; // level L is 01
  const data = rest;
  for (let i = 0; i < 10; i++) rest = (rest << 1) ^ ((rest >>> 9) * 0x537);
  const bits = ((data << 10) | rest) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6));
  set(8, 8, bit(7));
  set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true);
}

/** The standard's four penalties of a finished code, as qrencode adds them up. */
function penalty(dark) {
  const size = dark.length;
  let total = 0;
  let blacks = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (dark[y][x]) blacks++;
  const area = size * size;
  total += Math.floor(Math.abs(Math.floor((200 * blacks + area) / area / 2) - 50) / 5) * 10;
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const four = [dark[y][x], dark[y][x + 1], dark[y + 1][x], dark[y + 1][x + 1]];
      if (four.every(Boolean) || !four.some(Boolean)) total += 3;
    }
  }
  const lines = [];
  for (let a = 0; a < size; a++) {
    lines.push(dark[a]);
    lines.push(dark.map((row) => row[a]));
  }
  for (const line of lines) {
    // The lengths of its runs, light first (a line that starts dark has an empty light run before it).
    const runs = [];
    if (line[0]) runs.push(-1);
    runs.push(1);
    for (let i = 1; i < size; i++) {
      if (line[i] !== line[i - 1]) runs.push(1);
      else runs[runs.length - 1]++;
    }
    runs.forEach((run, i) => {
      if (run >= 5) total += 3 + (run - 5);
      if (i % 2 === 1 && i >= 3 && i < runs.length - 2 && run % 3 === 0) {
        const unit = run / 3;
        if ([runs[i - 2], runs[i - 1], runs[i + 1], runs[i + 2]].every((r) => r === unit)
          && (i === 3 || runs[i - 3] >= 4 * unit || i + 4 >= runs.length || runs[i + 3] >= 4 * unit)) total += 40;
      }
    });
  }
  return total;
}

/**
 * The QR code of `text` (UTF-8, byte mode, level L): rows of booleans, true for a dark module.
 * The smallest version that holds it; one of more than `MOST` bytes is an error.
 */
export function qr(text) {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  while (version <= 40 && 4 + (version < 10 ? 8 : 16) + bytes.length * 8 > (codewords(version) - ECC[version - 1] * BLOCKS[version - 1]) * 8) version++;
  if (version > 40) throw new Error(`too long for a QR code: ${bytes.length} bytes, and ${MOST} is the most`);
  const all = stream(bytes, version);
  const base = frame(version);
  const { size, fixed } = base;
  const place = base.dark.map((row) => row.slice());
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!fixed[y][x] && i < all.length * 8) {
          place[y][x] = ((all[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
          i++;
        }
      }
    }
  }
  let best = null;
  for (let mask = 0; mask < 8; mask++) {
    // (The format bits are drawn on a copy, and counted with the rest: the standard scores the symbol.)
    const grid = place.map((row, y) => row.map((on, x) => (fixed[y][x] ? on : on !== MASKS[mask](x, y))));
    const made = { size, set: (x, y, on) => { grid[y][x] = on; } };
    format(made, mask);
    const cost = penalty(grid);
    if (!best || cost < best.cost) best = { cost, grid };
  }
  return best.grid;
}

/** Draws a matrix on a canvas, black on white with the four modules' quiet zone a scanner wants, whatever the page's theme. */
export function draw(canvas, matrix, scale = 5) {
  const quiet = 4;
  const side = (matrix.length + 2 * quiet) * scale;
  canvas.width = canvas.height = side;
  const pen = canvas.getContext('2d');
  pen.fillStyle = '#ffffff';
  pen.fillRect(0, 0, side, side);
  pen.fillStyle = '#000000';
  matrix.forEach((row, y) => row.forEach((on, x) => {
    if (on) pen.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
  }));
}
