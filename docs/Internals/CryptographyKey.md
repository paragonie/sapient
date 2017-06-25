# Cryptography Keys

Sapient uses data objects to encapsulate cryptography keys to reduce
the likelihood of user error.

For example, an X25519 public key and a Salsa20 shared secret key are
both 32 byte binary strings, but you wouldn't want to use a public key
as your shared secret key.

There are six types of keys:

* `SealingPublicKey` -> X25519 public key
* `SealingSecretKey` -> X25519 secret key
* `SharedAuthenticationKey` -> HMAC-SHA512256 symmetric key 
* `SharedEncryptionKey` -> Salsa20 symmetric key
* `SigningPublicKey` -> Ed25519 public key
* `SigningSecretKey` -> Ed25519 secret key

All six key types that inherit from `CryptographyKey` do not reveal the
actual string in stack traces or `var_dump()`. In order to view a key,
you just need to invoke the `getString()` method. You may optionally pass
`TRUE` to this method if you want raw binary. (It defaults to base64url
encoding).
