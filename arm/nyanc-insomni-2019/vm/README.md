Setup ARM-64 VM
====

## Install dependencies

```
apt install qemu-efi-aarch64 qemu-system-aarch64
```

## Setup Image

```
./get_img.sh
./gen_uefi.sh
```

## Run Image

```
./run_qemu.sh()
```

You have to reset the root password or deal with the Ubuntu Cloud Image ssh-key stuff to get root access.
Here is some more description on how to setup Ubuntu-Cloud-Images: https://askubuntu.com/questions/281763/is-there-any-prebuilt-qemu-ubuntu-image32bit-online/1081171#1081171

Furthermore, you should enable root-ssh-login and work with an ssh-accessf from now on.


### Setup environment

Install the stuff you need, my setup is a simple gdbserver:

```
apt install tmux vim gdbserver
```

Then copy the [challenge](../challenge) and [run](../run) script into the vm (via ssh/network for example).
Uncomment the particular line in the run script and run the challenge with:

```
./run ./challenge/nyanc z4242
```
