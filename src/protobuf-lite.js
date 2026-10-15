/**
 * Minimal protobuf wire-format reader, scoped to what CRX3's header needs:
 * flat messages made of varint and length-delimited (wire type 2) fields.
 * Not a general protobuf implementation — just enough to read/skip the
 * handful of field shapes CrxFileHeader and SignedData actually use.
 */
export function readFields(buf) {
  const fields = {};
  let i = 0;

  while (i < buf.length) {
    const [tag, tagLen] = readVarint(buf, i);
    i += tagLen;
    const fieldNumber = tag >>> 3;
    const wireType = tag & 0x7;

    let value;
    if (wireType === 0) {
      const [v, len] = readVarint(buf, i);
      value = v;
      i += len;
    } else if (wireType === 2) {
      const [len, lenLen] = readVarint(buf, i);
      i += lenLen;
      if (i + len > buf.length) {
        throw new Error(`protobuf-lite: length-delimited field ${fieldNumber} extends past end of buffer`);
      }
      value = buf.subarray(i, i + len);
      i += len;
    } else if (wireType === 1) {
      if (i + 8 > buf.length) {
        throw new Error(`protobuf-lite: truncated 64-bit field ${fieldNumber}`);
      }
      value = buf.subarray(i, i + 8);
      i += 8;
    } else if (wireType === 5) {
      if (i + 4 > buf.length) {
        throw new Error(`protobuf-lite: truncated 32-bit field ${fieldNumber}`);
      }
      value = buf.subarray(i, i + 4);
      i += 4;
    } else {
      throw new Error(`protobuf-lite: unsupported wire type ${wireType} for field ${fieldNumber}`);
    }

    (fields[fieldNumber] ??= []).push(value);
  }

  return fields;
}

function readVarint(buf, offset) {
  let result = 0n;
  let shift = 0n;
  let i = offset;
  for (;;) {
    if (i >= buf.length) {
      throw new Error('protobuf-lite: truncated varint (ran past end of buffer)');
    }
    const byte = buf[i++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return [Number(result), i - offset];
}
