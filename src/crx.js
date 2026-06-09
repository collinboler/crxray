// A CRX file is a signed ZIP: a small header (signatures/public keys)
// prepended to an ordinary ZIP archive.
//
// CRX3: "Cr24" | uint32le version=3 | uint32le headerLen | header | ZIP
// CRX2: "Cr24" | uint32le version=2 | uint32le keyLen | uint32le sigLen | key | sig | ZIP

const MAGIC = 'Cr24';
const ZIP_MAGIC = 0x04034b50;

/**
 * Strip the CRX header and return the embedded ZIP as a Buffer.
 * Also accepts a plain ZIP (some mirrors serve unwrapped archives).
 */
export function crxToZip(buf) {
  if (buf.length >= 4 && buf.readUInt32LE(0) === ZIP_MAGIC) {
    return buf; // already a plain ZIP
  }

  if (buf.length < 16 || buf.toString('latin1', 0, 4) !== MAGIC) {
    throw new Error('Not a CRX file (missing Cr24 magic). The store may have returned an error page.');
  }

  const version = buf.readUInt32LE(4);
  let zipStart;

  if (version === 3) {
    const headerLen = buf.readUInt32LE(8);
    zipStart = 12 + headerLen;
  } else if (version === 2) {
    const keyLen = buf.readUInt32LE(8);
    const sigLen = buf.readUInt32LE(12);
    zipStart = 16 + keyLen + sigLen;
  } else {
    throw new Error(`Unsupported CRX version: ${version}`);
  }

  if (zipStart >= buf.length) {
    throw new Error('Corrupt CRX: header extends past end of file.');
  }

  const zip = buf.subarray(zipStart);
  if (zip.readUInt32LE(0) !== ZIP_MAGIC) {
    throw new Error('Corrupt CRX: no ZIP archive found after header.');
  }
  return zip;
}
