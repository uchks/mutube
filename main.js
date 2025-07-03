const MODULE = "YouTubeUnstable";
const base = Module.findBaseAddress(MODULE);

function jsStringToNative(str) {
  // convert a JavaScript string to a char* buffer
  // make sure string is ASCII only so we don't have to deal with length issues related to UTF-8
  const vals = [];
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    if (charCode < 0 || charCode > 255) {
      throw new Error("Prefix contains non-ASCII character at index " + i);
    }
    vals.push(str.charCodeAt(i));
  }

  vals.push(0); // null terminator

  const tmpBuf = Memory.alloc(vals.length);
  Memory.writeByteArray(tmpBuf, vals);
  return tmpBuf;
}

const insertPtr = Module.findExportByName(
  "libc++.1.dylib",
  "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm"
);
const insertFn = new NativeFunction(insertPtr, "pointer", [
  "pointer",  // std::string this
  "ulong",  // size_t pos
  "pointer",  // const char* s
  "ulong",  // size_t n
]);

function prepend(strPtr, prefix) {
  const tmpBuf = jsStringToNative(prefix);
  insertFn(strPtr, 0, tmpBuf, prefix.length);
}

function readStdString(str) {
  // std::string layout:
  // short strings just have the last byte as length, rest is for data
  // long strings:
  // 0x00: data pointer
  // 0x08: length
  // 0x0c: capacity (upper bit set to 1)

  const capacity = str.add(16).readU64();
  const topBit = capacity.shr(63);
  if (topBit.toNumber() !== 0) {
    // long string
    const chars = str.readPointer();
    const length = str.add(8).readU32();

    const res = chars.readUtf8String(length);
    return { length, capacity: capacity.xor(uint64(1).shl(63)), res };
  } else {
    // short string optimization
    // length is just the upper byte
    const length = capacity.shr(64 - 8);
    const chars = str.readUtf8String(length);
    return { length, capacity: length, res: chars };
  }
}

// unused for now, but useful for debugging by modifying existing JS.
const replacePtr = Module.findExportByName(
  "libc++.1.dylib",
  "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7replaceEmmPKc"
);
console.log('replacePtr:', replacePtr);
const replaceFn = new NativeFunction(replacePtr, "pointer", [
  "pointer",  // std::string this
  "ulong",  // size_t pos
  "ulong",  // size_t len
  "pointer",  // const char* s
]);

function replace(str, substr, newStr) {
  // replace a substring in a std::string with a new string
  // replaces the first occurrence of substr with newStr only
  const strData = readStdString(str);
  // find first occurrence of substr in strData.res
  const index = strData.res.indexOf(substr);
  if (index === -1) {
    return false; // substring not found, nothing to replace
  }

  const tmpBuf = jsStringToNative(newStr);

  console.log(`replaceFn: replacing "${substr}" at index ${index} with "${newStr}" in std::string at ${str}`);
  replaceFn(
    str,
    index,  // position to start replacing
    substr.length,  // length of the substring to replace
    tmpBuf  // new string to insert
  );
  return true;
}

// Add TizenTube script to the page. Don't inject more than once.
//
// Restore 4k support by hooking window.MediaSource.isTypeSupported.
// When sideloaded, isTypeSupported returns false for vp9 codecs (unless experimental=allowed is set).
// Not quite sure why, but most likely due to lack of entitlements when sideloaded. (see https://github.com/PoomSmart/YTUHD).
// Also unsure why but even with experimental=allowed, it returns false for vp9 with width=3840 and height=2160.
// So we remove width= and height= from the mimeType string before calling the original isTypeSupported.
const injectedContent = `
(function () {
if (document.mutube) return;
document.mutube = true;

var script = document.createElement('script');
script.src = "https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js";
script.async = true;
document.head.appendChild(script);

const originalIsTypeSupported = window.MediaSource.isTypeSupported.bind(window.MediaSource);

window.MediaSource.isTypeSupported = function(mimeType) {
  const parts = mimeType
    .split(';')
    .map(part => part.trim())
    .filter(part => part);

  const filtered = parts.filter(part => {
    const lower = part.toLowerCase();
    return !(lower.startsWith('width=') || lower.startsWith('height='));
  });

  let cleaned = filtered.join('; ');
  if (!/experimental=/.test(cleaned)) {
    cleaned += '; experimental=allowed';
  }
  return originalIsTypeSupported(cleaned);
};
})();

`;

// HTMLScriptElement::Execute
// https://cobalt.googlesource.com/cobalt/+/19.lts.1+/src/cobalt/dom/html_script_element.cc#593
Interceptor.attach(base.add(0xed4a30), {
  onEnter(args) {
    const content = args[1];
    if (readStdString(content).res.includes("yttv")) {
      prepend(content, injectedContent);
    }
  },
});

// DirectiveList::AddDirective
// https://cobalt.googlesource.com/cobalt/+/19.lts.1+/src/cobalt/csp/directive_list.cc#834
Interceptor.attach(base.add(0x152ccc8), {
  onEnter(args) {
    prepend(
      args[2],
      "sponsorblock.inf.re sponsor.ajay.app dearrow-thumb.ajay.app cdn.jsdelivr.net "
    );
  },
});
