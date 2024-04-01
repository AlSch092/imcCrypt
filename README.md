# imcCrypt
IMC Games packet encryption methods for Granado Espada (x86)

## What is this?

Data encryption library for Granado Espada's outbound packets. Inbound packets did not require decrypting at the time this project was made, and still might be the case. This project was made years ago and might require an updated encryption key (found in imcCrypt.h), there's also a chance the current key still works. The encryption method is Blowfish, which uses a boolean mode to either encrypt or decrypt.

## How to use?

This project exports the function "Encrypt", and can be called using `int Encrypt(byte[] inData, byte[] outData, int length);` after compiling the code into a .dll. Since all game packets have a checksum in their header, we can generate this using the dllexported function `ushort AddChecksumToPacket(byte[] outData, int length)`. In cases where your input data size does not divide by 8, you'll need extra space for padding in the encrypted data's buffer because Blowfish is a block cipher. Thus if your `inData` buffer is 6 bytes, you'll want `outData` to be at least 8 bytes. Failing to do so will result in both abnormal program execution and incorrect encrypted output.


## Credits
AlSch092 @ Github
