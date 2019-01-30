33c3 Feuerfuchs
===

This challenge was created by Samuel Groß (saelo).
The purpose of this repo is just to reproduce the exploit for the sake of learning more about JavaScript-Engine exploitation.

*   [files](https://github.com/saelo/feuerfuchs)
*   [Write-up](https://bruce30262.github.io/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge/)

## Vuln

## Build Vuln-JSC (Ubuntu 18.04)

The challenge was created for the latest firefox version during 33c3 CTF (December 2016), which corresponds to version 50.1.0.
You can download the release [here](https://ftp.mozilla.org/pub/firefox/releases/50.1.0/source/firefox-50.1.0.source.tar.xz)

I had to build one thing in their build system, which you can find in build/icu.patch
If you want to use the debug build the following assertions in `js/src/vm/SelfHosting.cp` are stopping the exploit, therefore, I created the build/debug.patch to remove them.

```
intrinsic_MoveTypedArrayElements(JSContext* cx, unsigned argc, Value* vp)
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
jit::AtomicOperations::memmoveSafeWhenRacy(data + byteDest, data + byteSrc, byteSize);
```
You can find the resulting build-script in [build/build.sh](build/build.sh).

## Run

```
cd build/firefox-50.1.0.source
./mach run
```
