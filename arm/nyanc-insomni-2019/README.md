nyanc - Insomni 19
===

OMG, an innovative note challenge... or not

Files are here

Challenge runs on ubuntu 18.04 aarch64, chrooted


## Setup AARCH-64 VM

See `vm/README.md`

If you want aarch64 debugging in you gdb, see [get_gdb.sh](get_gdb.sh) or run your own setup.
If you're rocking my gdbserver setup try:

```
./gdb -ex "target remote :1234"
```

## VULN

Reverse the challenge yourself to get an understanding of what's happening.

The problem is that we can allocate chunks of size 0, however when reading the content,
it reads `size-1 = -1` many bytes.
This will cause read to fail, but store a 16-bit unsigned representation of this size `0xffff` as the length.
This gives us an overwrite when modifying the chunks content.

## Exploit

One problem for us is that we can't just call free.
The way we get freed chunks is by reducing the top chunks size through our overwrite.
See [house_of_orange](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c).

From there we can use this trick multiple times to trigger a tcache-poisoning and get a libc-leak, stack-leak and finally an arbitrary write.
See [tcache_poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c).

In the last step we can't juts pop a shell, because we're chrooted.
Instead we have to write a short rop-chain to trigger `mprotect` and finally run our shellcode to leak the flag.

See the exploit files for more details.
