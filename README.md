# Faster encryption with libcyrpto

This is an implementation of AES-256-GCM    libcrypto on modern processors uses the AES-NI instructions, 
which speed up encryption/decryption by 6-10x.

To APIs are used which need to be incorporated in dart via a FFI.

## File Format

The file format is simple:

  * 12 byte random IV
  * body of encrypted file
  * 16 byte gcm tag (to be read when encrypting)

## Encryption

bool do_encrypt(const char *input_file, const char *output_file, size_t optional_size, const uint8_t key_256[32]);

The following parameters are used:  
  
  * input file  -- must be present
  * output file -- must be able to write to it (will be created if not present)
  * optional_size -- useful when doing benchmarking from /dev/zero to /dev/null.    Specifies "how much data" to encrypt.    If 0, encrypt until EOF.
  * key_256 -- the 32 byte key for AES 256

It returns TRUE is the encryption works, and FALSE if there is a problem.

If there is a problem, there may be output left in output_file

## Decryption

bool do_decrypt(const char *input_file, const char *output_file, const uint8_t key_256[32]);

The following parameters are needed:  

  * input_file - are readable input file which needs to exist (it can be NULL)
  * output_file -- the name of a file (which may be created) which is writable
  * key_256 -- a 32 byte AES key

It returns TRUE if the decryption works without problem (checking the MAC in the input file against the encryption),   
FALSE if there is a problem.

If there is a problem, there may be output in the output file.




## Making software

The makefile is structured with:

  * XCFLAGS -- to pass arbitrary commands to the C compile
  * DEFINES -- software currently uses  
        * -DSAVE_IV -- save IV in the output file during encryption (could be random)  
        * -DZERO_IV -- IV is a byte stream of zeros -- useful for testing and not saving the IV


It needs to be used on a relatively recent version of openssl (it appears the API was extended to help with AEAD encryption)

I know this works (from ubuntu 22.04):  


openssl version
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

and this doesn't (from ubuntu 20.04)
openssl version
OpenSSL 1.1.1f  31 Mar 2020



