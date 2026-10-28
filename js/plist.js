/*
 * WebSigner - minimal property list parser (XML and binary bplist00).
 * Exposes window.WSPlist = { parse(bytes), parseXML(text), extractFromCMS(bytes) }.
 * Dates become Date objects, <data> becomes Uint8Array.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
(function (root) {
  "use strict";

  var APPLE_EPOCH_MS = Date.UTC(2001, 0, 1);

  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, function (_, e) {
      switch (e) {
        case "lt": return "<";
        case "gt": return ">";
        case "amp": return "&";
        case "quot": return "\"";
        case "apos": return "'";
      }
      return String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    });
  }

  function base64ToBytes(b64) {
    var bin = atob(b64.replace(/\s+/g, ""));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- XML ----------
  function parseXML(text) {
    var tokens = [];
    var re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[\s\S]*?>|<(\/?)([A-Za-z]+)[^>]*?(\/?)>|([^<]+)/g;
    var m;
    while ((m = re.exec(text))) {
      if (m[2]) tokens.push({ close: !!m[1], name: m[2], self: !!m[3] });
      else if (m[4] !== undefined) tokens.push({ text: m[4] });
    }
    var pos = 0;

    function nextTag() {
      while (pos < tokens.length && tokens[pos].text !== undefined) pos++;
      return tokens[pos++];
    }

    function readText(name) {
      var s = "";
      while (pos < tokens.length && tokens[pos].text !== undefined) s += tokens[pos++].text;
      var end = tokens[pos++];
      if (!end || !end.close || end.name !== name) throw new Error("plist: expected </" + name + ">");
      return decodeEntities(s);
    }

    function value(tag) {
      if (!tag || tag.close) throw new Error("plist: unexpected end of document");
      switch (tag.name) {
        case "dict": {
          var obj = {};
          if (tag.self) return obj;
          for (;;) {
            var t = nextTag();
            if (t.close && t.name === "dict") return obj;
            if (t.name !== "key") throw new Error("plist: expected <key>");
            var key = t.self ? "" : readText("key");
            obj[key] = value(nextTag());
          }
        }
        case "array": {
          var arr = [];
          if (tag.self) return arr;
          for (;;) {
            var a = nextTag();
            if (a.close && a.name === "array") return arr;
            arr.push(value(a));
          }
        }
        case "string": return tag.self ? "" : readText("string");
        case "integer": return parseInt(readText("integer"), 10);
        case "real": return parseFloat(readText("real"));
        case "true": return true;
        case "false": return false;
        case "date": return new Date(readText("date"));
        case "data": return base64ToBytes(tag.self ? "" : readText("data"));
      }
      throw new Error("plist: unsupported element <" + tag.name + ">");
    }

    var first = nextTag();
    if (!first || first.name !== "plist") throw new Error("plist: missing <plist> root");
    return value(nextTag());
  }

  // ---------- binary (bplist00) ----------
  function parseBinary(bytes) {
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var len = bytes.length;
    var trailer = len - 32;
    var offsetSize = bytes[trailer + 6];
    var refSize = bytes[trailer + 7];
    var numObjects = readUInt(trailer + 8, 8);
    var topObject = readUInt(trailer + 16, 8);
    var tableOffset = readUInt(trailer + 24, 8);

    function readUInt(off, size) {
      var v = 0;
      for (var i = 0; i < size; i++) v = v * 256 + bytes[off + i];
      return v;
    }

    function objectOffset(ref) {
      if (ref >= numObjects) throw new Error("bplist: bad object reference");
      return readUInt(tableOffset + ref * offsetSize, offsetSize);
    }

    function readCount(off, info) {
      // Returns [count, offset of payload].
      if (info !== 0xF) return [info, off + 1];
      var marker = bytes[off + 1];
      var size = 1 << (marker & 0xF);
      return [readUInt(off + 2, size), off + 2 + size];
    }

    function readObject(ref, depth) {
      if (depth > 512) throw new Error("bplist: nesting too deep");
      var off = objectOffset(ref);
      var marker = bytes[off];
      var type = marker >> 4;
      var info = marker & 0xF;
      var c, i, out;
      switch (type) {
        case 0x0:
          if (info === 0x8) return false;
          if (info === 0x9) return true;
          return null;
        case 0x1: {
          var n = 1 << info;
          if (n === 8) return Number(dv.getBigInt64(off + 1));
          if (n === 16) return Number(dv.getBigInt64(off + 9));
          return readUInt(off + 1, n);
        }
        case 0x2:
          return info === 2 ? dv.getFloat32(off + 1) : dv.getFloat64(off + 1);
        case 0x3:
          return new Date(APPLE_EPOCH_MS + dv.getFloat64(off + 1) * 1000);
        case 0x4:
          c = readCount(off, info);
          return bytes.slice(c[1], c[1] + c[0]);
        case 0x5:
          c = readCount(off, info);
          out = "";
          for (i = 0; i < c[0]; i++) out += String.fromCharCode(bytes[c[1] + i]);
          return out;
        case 0x6:
          c = readCount(off, info);
          out = "";
          for (i = 0; i < c[0]; i++) out += String.fromCharCode(dv.getUint16(c[1] + i * 2));
          return out;
        case 0x8:
          return { UID: readUInt(off + 1, info + 1) };
        case 0xA:
        case 0xC:
          c = readCount(off, info);
          out = [];
          for (i = 0; i < c[0]; i++) out.push(readObject(readUInt(c[1] + i * refSize, refSize), depth + 1));
          return out;
        case 0xD: {
          c = readCount(off, info);
          out = {};
          var valuesOff = c[1] + c[0] * refSize;
          for (i = 0; i < c[0]; i++) {
            var k = readObject(readUInt(c[1] + i * refSize, refSize), depth + 1);
            out[k] = readObject(readUInt(valuesOff + i * refSize, refSize), depth + 1);
          }
          return out;
        }
      }
      throw new Error("bplist: unsupported object type 0x" + type.toString(16));
    }

    return readObject(topObject, 0);
  }

  function bytesToLatin1(bytes, start, end) {
    var s = "";
    for (var i = start; i < end; i += 8192) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(end, i + 8192)));
    }
    return s;
  }

  function indexOf(bytes, needle, from) {
    outer: for (var i = from || 0; i <= bytes.length - needle.length; i++) {
      for (var j = 0; j < needle.length; j++) if (bytes[i + j] !== needle.charCodeAt(j)) continue outer;
      return i;
    }
    return -1;
  }

  function parse(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytesToLatin1(bytes, 0, Math.min(8, bytes.length)) === "bplist00") return parseBinary(bytes);
    return parseXML(new TextDecoder("utf-8").decode(bytes));
  }

  // A .mobileprovision is a CMS (PKCS#7) envelope around an XML plist.
  function extractFromCMS(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    var start = indexOf(bytes, "<?xml");
    var end = start === -1 ? -1 : indexOf(bytes, "</plist>", start);
    if (end === -1) throw new Error("No property list found in provisioning profile");
    return parseXML(new TextDecoder("utf-8").decode(bytes.subarray(start, end + 8)));
  }

  root.WSPlist = { parse: parse, parseXML: parseXML, extractFromCMS: extractFromCMS };
})(typeof window !== "undefined" ? window : globalThis);
