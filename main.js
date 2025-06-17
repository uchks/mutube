const MODULE = "YouTubeUnstable";
const base = Module.findBaseAddress(MODULE);

const insertPtr = Module.findExportByName(
    "libc++.1.dylib",
    "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm"
);
const insertFn = new NativeFunction(insertPtr, "pointer", [
    "pointer",
    "ulong",
    "pointer",
    "ulong",
]);

function prepend(strPtr, prefix) {
    // convert prefix to a ASCII string array
    const vals = [];
    for (let i = 0; i < prefix.length; i++) {
    const charCode = prefix.charCodeAt(i);
    if (charCode < 0 || charCode > 255) {
        throw new Error("Prefix contains non-ASCII character at index " + i);
    }
    vals.push(prefix.charCodeAt(i));
    }

    vals.push(0); // null terminator

    const tmpBuf = Memory.alloc(vals.length);
    Memory.writeByteArray(tmpBuf, vals);

    insertFn(strPtr, 0 /*pos*/, tmpBuf, prefix.length);
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

// add a script to the page with source https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js
// check if the script is already injected
const injectedContent = `/* frida */
(function () {
if (document.mutube) return;
document.mutube = true;
var script = document.createElement('script');
script.src = "https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js";
script.async = true;
document.head.appendChild(script);
})();

`;

// HTMLScriptElement::Execute
// https://cobalt.googlesource.com/cobalt/+/19.lts.1+/src/cobalt/dom/html_script_element.cc#593
Interceptor.attach(base.add(0x00ed4a30), {
    onEnter(args) {
    const content = args[1];
    const str = readStdString(content);
    if (str.length > 0 && str.res.includes("yttv")) {
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
    const name = readStdString(args[1]);
    const value = readStdString(args[2]);
    },
});