# Simple Encryption Abstraction

Canonical name: `ParagonIE\Sapient\Simple`

## Shared-Key Encryption

Shared-key encryption uses XChaCha20-Poly1305 with a 192-bit random
nonce. The nonce is used as the Additional Data argument to libsodium's
`crypto_aead_xchacha20poly1305_ietf_*()` functions.

After encryption, the nonce is prepended to the ciphertext. The encrypted
message (in raw binary) is formatted like this.

    nonce (24 bytes) || ciphertext (0 or more bytes) || tag (16 bytes)

Messages are Base64url encoded in transmission.

----

* PHP: 
  * `ParagonIE\Sapient\Simple::encrypt()`
  * `ParagonIE\Sapient\Simple::decrypt()`

## Public-Key Encryption

Sapient's public-key encryption interface is a sealing API:

* Encrypt a plaintext with a public key,
* Decrypt a ciphertext with a secret key

Under the hood, it does a little bit more work.

First, generate a random X25519 keypair (`$ephSecret`, `$ephPublic`). Then,
calculate the shared key and nonce as follows:

```php
$keystream = sodium_crypto_generichash(
    sodium_crypto_scalarmult($ephSecret, $publicKey) . $ephPublic . $publicKey,
    '', // No key
    56
);
$key   = mb_substr($keystream,  0, 32, '8bit');
$nonce = mb_substr($keystream, 32, 24, '8bit');
```

That is to say, the derived key will be the first 32 bytes of a 56-byte BLAKE2b hash
of the X25519 shared secret and both public keys. The nonce for the message will be
the remaining 24 bytes.

The message is then encrypted with XChaCha20-Poly1305, with the ephemeral public key
prepended to the message (and used as addition data). The encrypted message (in raw
binary) is formatted like this.
                                                      
    ephPublicKey (32 bytes) || ciphertext (0 or more bytes) || tag (16 bytes)

Messages are Base64url encoded in transmission.

----

* PHP: 
  * `ParagonIE\Sapient\Simple::seal()`
  * `ParagonIE\Sapient\Simple::unseal()`