33c3 Feuerfuchs
===

This challenge was created by Samuel Groß (saelo).
The purpose of this repo is just to reproduce the exploit for the sake of learning more about JavaScript-Engine exploitation.

*   [files](https://github.com/saelo/feuerfuchs)
*   [Write-up](https://bruce30262.github.io/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge/)

## Build Vuln-JSC (Ubuntu 18.04)

The challenge was created for the latest firefox version during 33c3 CTF (December 2016), which corresponds to version 50.1.0.
You can download the release [here](https://ftp.mozilla.org/pub/firefox/releases/50.1.0/source/firefox-50.1.0.source.tar.xz)

I had to fix a small issue in their build system, which you can find in build/icu.patch
If you want to use the debug build the `#ifdef DEBUG` assertions in `js/src/vm/SelfHosting.cpp` are stopping the exploit.
I created the build/debug.patch to remove them.

You can find the resulting build-script in [build/build.sh](build/build.sh).

For the exploit development I've build a standalone js-shell as well, [here](https://github.com/m1ghtym0/browser-pwn#spidermonkey) you can find the build instructions.

## Run

```
cd build/firefox-50.1.0.source
./mach run
```

## Vuln

The [patch](build/feuerfuchs.patch) adds a length and offset setter to the TypedArray implementation.
Both setters ensure the integrity of the underlying ArrayBuffer bounds.
The TypedArray implementation is written in C++ and you can find it in `js/src/vm/TypedArrayObject(.cpp|.h)`.
We can check in the builtin TypedArray functions if these setters break any of their assumptions specifically regarding the size and bounds checks.
Interesting candidates are for example `TypedArraySlice` and `TypedArrayCopyWithin`.
In both cases `toInteger` is called on the `start` and `end` parameters, which would allow us to subsequently modify the length and offset.
However, `TypedArraySlice` is only operating on the JavaScript object and does not give us an out-of-bounds access.
`TypedArrayCopyWithin` on the other hand calls the `MoveTypedArrayElements`, which is implemented in C++.
Let's check what it passs as the dest, source and count values.

1. Fetch the this->length:

    ```
    var len = TypedArrayLength(obj);
    ```

2. Casts dest index to Integer and clamps it to the array bounds:

    ```
    var relativeTarget = ToInteger(target);

    var to = relativeTarget < 0 ? std_Math_max(len + relativeTarget, 0)
                                : std_Math_min(relativeTarget, len)
    ```

3. Casts start index to Integer and clamps it to the array bounds:

    ```
    var relativeStart = ToInteger(start);

    var from = relativeStart < 0 ? std_Math_max(len + relativeStart, 0)
                                 : std_Math_min(relativeStart, len)
    ```

4. Casts end index to Integer and clamps it to the array bounds:

    ```
    var relativeEnd = end === undefined ? len
                                        : ToInteger(end);

    var final = relativeEnd < 0 ? std_Math_max(len + relativeEnd, 0)
                                : std_Math_min(relativeEnd, len);
    ```                                
    Note that in the previous three steps, the `toInteger` call allows us to modify the current Array's offset and length.

5. Calculates the amount of elements to copy and clamps it to the range of the array:

    ```
    var count = std_Math_min(final - from, len - to)
    ```

6. Call `MoveTypedArrayElements`:

    ```
    if (count > 0)
        MoveTypedArrayElements(obj, to | 0, from | 0, count | 0)
    ```
    
    Note that because we could modify the `obj` offset and size, from+count can be outside of the underlying ArrayBuffers bounds now.


Let's check `MoveTypedArrayElements` in `js/src/vm/SelfHosting.cpp`:


```
intrinsic_MoveTypedArrayElements(JSContext* cx, unsigned argc, Value* vp)
...
    Rooted<TypedArrayObject*> tarray(cx, &args[0].toObject().as<TypedArrayObject>());
    uint32_t to = uint32_t(args[1].toInt32());
    uint32_t from = uint32_t(args[2].toInt32());
    uint32_t count = uint32_t(args[3].toInt32())
...
    #ifdef DEBUG
        {    
            uint32_t viewByteLength = tarray->byteLength();
            MOZ_ASSERT(byteSize <= viewByteLength);
            MOZ_ASSERT(byteDest < viewByteLength);
            MOZ_ASSERT(byteSrc < viewByteLength);
            MOZ_ASSERT(byteDest <= viewByteLength - byteSize);
            MOZ_ASSERT(byteSrc <= viewByteLength - byteSize);
        }    
    #endif
...
    SharedMem<uint8_t*> data = tarray->viewDataEither().cast<uint8_t*>();
    jit::AtomicOperations::memmoveSafeWhenRacy(data + byteDest, data + byteSrc, byteSize)
```

Interestingly, there is a check to ensure that the arguments are in the bounds of the current Array,
but this is only done in the `#ifdef DEBUG` statement and therefore, not compiled into the release version.
Consequently, the resulting memmove gives us an out of bounds memory access.

## Exploit

See the annotated [pwn.js](pwn.js).
Execute it by running `./mach run` and open the [pwn.html](pwn.html) file.



