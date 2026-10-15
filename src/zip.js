// Minimal zero-dependency ZIP extractor (central-directory based).
// Extension archives are plain ZIPs: entries are either stored (0) or
// deflated (8), never encrypted, and far below zip64 limits.
import { inflateRawSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

// Chrome/Edge extensions ship at most a few thousand small files. These
// caps reject corrupt or maliciously-crafted archives before they can
// exhaust memory. A single deflate pass is physically bounded to roughly
// 1032:1 (LZ77 + Huffman limits), so a compression-ratio heuristic adds
// little real protection — an absolute size cap plus a declared-vs-actual
// length check (below) catches forged or corrupt metadata more reliably.
const MAX_ENTRIES = 20000;
const MAX_ENTRY_UNCOMPRESSED = 200 * 1024 * 1024; // 200MB
const MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024; // 500MB

const CRC_TABLE = buildCrcTable();

function buildCrcTable() {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
}

/** Standard CRC-32 (zip/gzip polynomial), zero dependencies. */
export function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function findEocd(buf) {
  // EOCD is at the very end, preceded by an optional comment (max 65535 bytes).
  const min = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new Error('Invalid ZIP: end-of-central-directory record not found.');
}

/**
 * List entries from a ZIP buffer. Returns [{ name, isDirectory, uncompressedSize, data() }].
 */
export function readZipEntries(buf) {
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  if (count > MAX_ENTRIES) {
    throw new Error(`Invalid ZIP: ${count} entries exceeds the ${MAX_ENTRIES}-entry limit.`);
  }
  const cdOffset = buf.readUInt32LE(eocd + 16);

  const entries = [];
  let p = cdOffset;

  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== CENTRAL_SIG) {
      throw new Error('Invalid ZIP: bad central directory entry.');
    }
    const method = buf.readUInt16LE(p + 10);
    const crcExpected = buf.readUInt32LE(p + 16);
    const compressedSize = buf.readUInt32LE(p + 20);
    const uncompressedSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);

    if (uncompressedSize > MAX_ENTRY_UNCOMPRESSED) {
      throw new Error(
        `Invalid ZIP: ${name} declares ${uncompressedSize} bytes uncompressed, over the ${MAX_ENTRY_UNCOMPRESSED}-byte limit.`
      );
    }

    entries.push({
      name,
      isDirectory: name.endsWith('/'),
      uncompressedSize,
      data() {
        if (buf.readUInt32LE(localOffset) !== LOCAL_SIG) {
          throw new Error(`Invalid ZIP: bad local header for ${name}.`);
        }
        // Local header name/extra lengths can differ from the central
        // directory's, so re-read them to find the data offset.
        const lNameLen = buf.readUInt16LE(localOffset + 26);
        const lExtraLen = buf.readUInt16LE(localOffset + 28);
        const start = localOffset + 30 + lNameLen + lExtraLen;
        const raw = buf.subarray(start, start + compressedSize);

        let out;
        if (method === 0) {
          out = Buffer.from(raw);
        } else if (method === 8) {
          try {
            // maxOutputLength makes zlib itself stop allocating once the
            // cap is reached, instead of fully inflating a huge payload
            // and only then noticing the declared-size mismatch below.
            out = inflateRawSync(raw, { maxOutputLength: MAX_ENTRY_UNCOMPRESSED });
          } catch (err) {
            if (err.code === 'ERR_BUFFER_TOO_LARGE') {
              throw new Error(
                `Invalid ZIP: ${name} inflates to more than the ${MAX_ENTRY_UNCOMPRESSED}-byte limit (possible decompression bomb).`
              );
            }
            throw err;
          }
        } else {
          throw new Error(`Unsupported compression method ${method} for ${name}.`);
        }

        if (out.length !== uncompressedSize) {
          throw new Error(
            `Invalid ZIP: ${name} inflated to ${out.length} bytes, not the declared ${uncompressedSize} (corrupt or tampered archive).`
          );
        }
        // A declared CRC of 0 is a real, valid CRC32 value, not a "skip
        // this check" sentinel — always verify it.
        if (crc32(out) !== crcExpected) {
          throw new Error(`Invalid ZIP: CRC mismatch for ${name} (corrupt or tampered archive).`);
        }
        return out;
      },
    });

    p += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

/**
 * Extract a ZIP buffer to destDir. Rejects entries that would escape
 * destDir (zip-slip) and entries/totals that exceed the size guards above
 * — important when unpacking untrusted extensions.
 * Returns the number of files written.
 */
export function extractZip(buf, destDir) {
  const root = path.resolve(destDir);
  mkdirSync(root, { recursive: true });

  const entries = readZipEntries(buf);

  // Check the aggregate declared size across every entry before inflating
  // any of them, so a bomb spread across many entries is caught up front
  // instead of after already extracting some of them.
  let totalUncompressed = 0;
  for (const entry of entries) {
    totalUncompressed += entry.uncompressedSize;
    if (totalUncompressed > MAX_TOTAL_UNCOMPRESSED) {
      throw new Error(
        `Invalid ZIP: total uncompressed size exceeds the ${MAX_TOTAL_UNCOMPRESSED}-byte limit (possible decompression bomb).`
      );
    }
  }

  let fileCount = 0;
  for (const entry of entries) {
    const dest = path.resolve(root, entry.name);
    if (dest !== root && !dest.startsWith(root + path.sep)) {
      throw new Error(`Blocked zip-slip path in archive: ${entry.name}`);
    }
    if (entry.isDirectory) {
      mkdirSync(dest, { recursive: true });
    } else {
      mkdirSync(path.dirname(dest), { recursive: true });
      writeFileSync(dest, entry.data());
      fileCount++;
    }
  }
  return fileCount;
}
