// Minimal zero-dependency ZIP extractor (central-directory based).
// Extension archives are plain ZIPs: entries are either stored (0) or
// deflated (8), never encrypted, and far below zip64 limits.
import { inflateRawSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

function findEocd(buf) {
  // EOCD is at the very end, preceded by an optional comment (max 65535 bytes).
  const min = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  throw new Error('Invalid ZIP: end-of-central-directory record not found.');
}

/**
 * List entries from a ZIP buffer. Returns [{ name, isDirectory, data() }].
 */
export function readZipEntries(buf) {
  const eocd = findEocd(buf);
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  const entries = [];
  let p = cdOffset;

  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== CENTRAL_SIG) {
      throw new Error('Invalid ZIP: bad central directory entry.');
    }
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);

    entries.push({
      name,
      isDirectory: name.endsWith('/'),
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
        if (method === 0) return Buffer.from(raw);
        if (method === 8) return inflateRawSync(raw);
        throw new Error(`Unsupported compression method ${method} for ${name}.`);
      },
    });

    p += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

/**
 * Extract a ZIP buffer to destDir. Rejects entries that would escape
 * destDir (zip-slip) — important when unpacking untrusted extensions.
 * Returns the number of files written.
 */
export function extractZip(buf, destDir) {
  const root = path.resolve(destDir);
  mkdirSync(root, { recursive: true });

  let fileCount = 0;
  for (const entry of readZipEntries(buf)) {
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
