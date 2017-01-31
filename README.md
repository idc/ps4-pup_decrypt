# pup_decrypt
A utility to invoke the PS4 kernel to decrypt the contents of an update file.

The default (hardcoded) operation is to decrypt `/mnt/usb0/PS4UPDATE.PUP`.

This will output a number of files (depending if a normal or a recovery update):
* `/mnt/usb0/PS4UPDATE1.PUP.dec`
* `/mnt/usb0/PS4UPDATE2.PUP.dec`
* `/mnt/usb0/PS4UPDATE3.PUP.dec`
* `/mnt/usb0/PS4UPDATE4.PUP.dec`

These decrypted updates can then be unpacked using [pup_unpack](https://github.com/idc/ps4-pup_unpack/).

## Notes
The PS4 will refuse to decrypt updates in some cases:
* Versions older than the installed version (for the most part, there's exceptions for things like beta versions).
* Versions for a different product code (retail cannot decrypt test or debug updates).

[A list of updates decrypted on a 1.76 retail system](RETAIL.md).