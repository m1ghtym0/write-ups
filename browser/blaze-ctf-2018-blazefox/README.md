Blazectf 2018 Blazefox
===

This challenge was created by  itszn.
The purpose of this repo is just to reproduce the exploit for the sake of learning more about JavaScript-Engine exploitation.

*   [files](https://mightym0.de/write-ups/browser/blazectf-2018-blazefox/blaze_firefox_small.tar.gz)
*   [binaries](https://mightym0.de/write-ups/browser/blazectf-2018-blazefox/blaze_firefox_dist_large.tar.gz)

## Build Vuln-JSC (Ubuntu 18.04)

The challenge was created for the following firefox version:
```
python bootstrap.py
hg clone https://hg.mozilla.org/mozilla-central
hg checkout ee6283795f41
hg import blaze.patch --no-commit
./mach build
```

However you can just use the prebuild challenge files.
If you want to build a standalone js-shell when building the exploit check my build instructions [here](https://github.com/m1ghtym0/browser-pwn#spidermonkey) you can find the build instructions.
The corresponding git-commit is `eb618784556b`.

## Run

You can either follow the instructions to run the docker container or run it locally with the provided binary and profile folder:

```
tar xvf blaze_firefox_dist_large.tar.gz
cd dist
dpkg -x obj-x86_64-pc-linux-gnu-release.deb ./deb
deb/firefox/dist/bin/firefox -profile firefox/slothProfile
```

Note that is important to run it with the provided profile to disable to sandbox.

## Vuln

The provided patch is pretty simple.
It just adds the `blaze` method to an array which sets the length of the array to 420, giving it an out-of-bounds access.
Exploiting this is straight forward and the only hurdle is to think about what to place in memory after the array.
One straight forward approach is to just use an `TypedArrayObject` and get an arbitrary read/write by modifying it's data pointer.

## Exploit

The exploit follows a typical pattern to other firefox exploits with similiar vulnerabilities as for example:

*   https://github.com/m1ghtym0/write-ups/tree/master/browser/33c3ctf-feuerfuchs
*   https://phoenhex.re/2017-06-21/firefox-structuredclone-refleak

See the annotated [pwn.js](pwn.js).
Execute it by running `deb/firefox/dist/bin/firefox -profile firefox/slothProfile` and open the [pwn.html](pwn.html) file.
Note that the libc-offsets are calculated for libc-2.27 in my latest Ubuntu 18.04 version and not for the docker-container with Ubuntu 16.04.



