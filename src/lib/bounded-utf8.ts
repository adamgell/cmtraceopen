const DIGEST_SUFFIX_BYTE_LENGTH = 31;

interface Utf8Scan {
  byteLength: number;
  firstDigestLane: number;
  secondDigestLane: number;
  prefixEnd: number;
  prefixHasLoneSurrogate: boolean;
}

function scanUtf8(value: string, prefixByteLimit: number): Utf8Scan {
  let first = 2_166_136_261;
  let second = (first ^ 0x9e37_79b9) >>> 0;
  let byteLength = 0;
  let prefixEnd = 0;
  let prefixHasLoneSurrogate = false;
  const hash = (byte: number) => {
    first = Math.imul(first ^ byte, 16_777_619) >>> 0;
    second = Math.imul(second ^ (byte ^ 0xa5), 16_777_619) >>> 0;
  };

  for (let index = 0; index < value.length;) {
    const firstUnit = value.charCodeAt(index);
    let codePoint = firstUnit;
    let codeUnitLength = 1;
    let loneSurrogate = false;
    if (firstUnit >= 0xd800 && firstUnit <= 0xdbff) {
      const secondUnit = value.charCodeAt(index + 1);
      if (secondUnit >= 0xdc00 && secondUnit <= 0xdfff) {
        codePoint =
          0x1_0000 + ((firstUnit - 0xd800) << 10) + (secondUnit - 0xdc00);
        codeUnitLength = 2;
      } else {
        codePoint = 0xfffd;
        loneSurrogate = true;
      }
    } else if (firstUnit >= 0xdc00 && firstUnit <= 0xdfff) {
      codePoint = 0xfffd;
      loneSurrogate = true;
    }

    let codePointByteLength: number;
    if (codePoint <= 0x7f) {
      codePointByteLength = 1;
      hash(codePoint);
    } else if (codePoint <= 0x7ff) {
      codePointByteLength = 2;
      hash(0xc0 | (codePoint >> 6));
      hash(0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      codePointByteLength = 3;
      hash(0xe0 | (codePoint >> 12));
      hash(0x80 | ((codePoint >> 6) & 0x3f));
      hash(0x80 | (codePoint & 0x3f));
    } else {
      codePointByteLength = 4;
      hash(0xf0 | (codePoint >> 18));
      hash(0x80 | ((codePoint >> 12) & 0x3f));
      hash(0x80 | ((codePoint >> 6) & 0x3f));
      hash(0x80 | (codePoint & 0x3f));
    }
    if (byteLength + codePointByteLength <= prefixByteLimit) {
      prefixEnd = index + codeUnitLength;
      prefixHasLoneSurrogate ||= loneSurrogate;
    }
    byteLength += codePointByteLength;
    index += codeUnitLength;
  }

  return {
    byteLength,
    firstDigestLane: first,
    secondDigestLane: second,
    prefixEnd,
    prefixHasLoneSurrogate,
  };
}

function textDigest(first: number, second: number): string {
  return `${first.toString(16).padStart(8, "0")}${second
    .toString(16)
    .padStart(8, "0")}`;
}

function replaceLoneSurrogates(value: string): string {
  let result = "";
  let segmentStart = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1;
        continue;
      }
    } else if (unit < 0xdc00 || unit > 0xdfff) {
      continue;
    }
    result += `${value.slice(segmentStart, index)}\ufffd`;
    segmentStart = index + 1;
  }
  return `${result}${value.slice(segmentStart)}`;
}

/** Bounds UTF-8 without splitting a code point and preserves a digest of the full value. */
export function boundUtf8WithDigest(value: string, byteLimit: number): string {
  const prefixByteLimit = Math.max(0, byteLimit - DIGEST_SUFFIX_BYTE_LENGTH);
  const scan = scanUtf8(value, prefixByteLimit);
  if (scan.byteLength <= byteLimit) return value;
  if (DIGEST_SUFFIX_BYTE_LENGTH > byteLimit) {
    throw new Error("The UTF-8 bound is too small for its digest suffix.");
  }

  const suffix = `…[truncated:${textDigest(
    scan.firstDigestLane,
    scan.secondDigestLane,
  )}]`;
  const prefix = value.slice(0, scan.prefixEnd);
  return `${
    scan.prefixHasLoneSurrogate ? replaceLoneSurrogates(prefix) : prefix
  }${suffix}`;
}
