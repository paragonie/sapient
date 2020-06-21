# Sapient - Class Documentation

Canonical name: `ParagonIE\Sapient\Sapient`

## Important

For encryption operations, only the body is encrypted. The HTTP headers are not.

For authentication operations, only the body is authenticated. The HTTP headers
are not.

If this is unacceptable for your application, you may consider designing a custom
encapsulation scheme that puts all of the sensitive metadata in the HTTP message
body and, for encryption operations, sending a generic `Content-Type` header (if
this is sensitive information).

## HTTP Cryptography Methods

These methods generally have an API that looks like this:

```php
function doSomethingWithARequest(
    RequestInterface $foo,
    CryptographyKey $bar
): RequestInferface;

function doSomethingWithAResponse(
    ResponseInterface $foo,
    CryptographyKey $bar
): ResponeInferface;
```

### `decryptRequestWithSharedKey()` / `decryptResponseWithSharedKey()` 

Function prototypes:

```php
public function decryptRequestWithSharedKey(
    RequestInterface $request,
    SharedEncryptionKey $key
): RequestIterface;

public function decryptResponseWithSharedKey(
    ResponseInterface $respone,
    SharedEncryptionKey $key
): ResponeInterface;
```

These decrypt the body of the HTTP object with a shared key, which must be
the same key that was used to encrypt the request. If anything fails, an
`InvalidMessageException` will be thrown.

Algorithm: [XChaCha20-Poly1305](Simple.md#shared-key-encryption)

### `encryptRequestWithSharedKey()` / `encryptResponseWithSharedKey()` 

Function prototypes:

```php
public function encryptRequestWithSharedKey(
    RequestInterface $request,
    SharedEncryptionKey $key
): RequestIterface;

public function encryptResponseWithSharedKey(
    ResponseInterface $respone,
    SharedEncryptionKey $key
): ResponeInterface;
```

These encrypt the body of of the HTTP object with a shared key, which must be
the same key that will be used to decrypt the request.

Algorithm: [XChaCha20-Poly1305](Simple.md#shared-key-encryption)

### `sealRequest()` / `sealResponse()`

Function prototypes:

```php
function sealRequest(
    RequestInterface $request,
    SealingPublicKey $publicKey
): RequestInterface;

function sealResponse(
    ResponseInterface $response,
    SealingPublicKey $publicKey
): ResponseInterface;
```

These encrypt the body of an HTTP request or response with the recipient's
public key, and can only be decrypted by the corresponding secret key.

Algorihm: [X25519 + BLAKE2b + XChaCha20-Poly1305](Simple.md#public-key-encryption)

### `unsealRequest()` / `unsealResponse()`

Function prototypes:

```php
function unsealRequest(
    RequestInterface $request,
    SealingSecretKey $secretKey
): RequestInterface;

function unsealResponse(
    ResponseInterface $response,
    SealingSecretKey $secretKey
): ResponseInterface;
```

These methods decrypt the body of an HTTP request or response, using your secret
key, provided they were previously encrypted with your public key.

Algorihm: [X25519 + BLAKE2b + XChaCha20-Poly1305](Simple.md#public-key-encryption)

### `authenticateRequestWithSharedKey()` / `authenticateResponseWithSharedKey()` 

Function prototypes:

```php
authenticateRequestWithSharedKey(
    RequestInterface $request,
    SharedAuthenticationKey $key
): RequestInterface;

function authenticateResponseWithSharedKey(
    ResponseInterface $response,
    SharedAuthenticationKey $key
): ResponseInterface;
```

These methods add an additional header (`Body-HMAC-SHA512256`) which contains the
Base64url-encoded Message Authentication Code of the HTTP message body.

This authenticates an HTTP request or response body with shared-key authentication,
which means any party capable of verifying the authentication header is also capable
of issuing forged headers.

Algorithm: HMAC-SHA512 truncated to 256 bits.

### `verifySymmetricAuthenticatedRequest()` / `verifySymmetricAuthenticatedResponse()`

Function prototypes:

```php
function verifySymmetricAuthenticatedRequest(
    RequestInterface $request,
    SharedAuthenticationKey $key
): RequestInterface;

function verifySymmetricAuthenticatedResponse(
    ResponseInterface $response,
    SharedAuthenticationKey $key
): ResponseInterface;
```

These methods verify that the signature contained in the `Body-HMAC-SHA512256` header
is valid for the body of the HTTP request or response object, given the shared
authentication key.

If there is no header present, a `HeaderMissingException` is thrown.

If the message authentication code is not valid, an `InvalidMessageException` is thrown.

Otherwise, it returns the object verbatim.

Algorithm: HMAC-SHA-512 truncated to 256 bits

### `signRequest()` / `signResponse()`

Function prototypes:

```php
function signRequest(
    RequestInterface $request,
    SigningSecretKey $secretKey
): RequestInterface;

function signResponse(
    ResponseInterface $response,
    SigningSecretKey $publicKey
): ResponseInterface;
```

These methods add an additional header (`Body-Signature-Ed25519`) which contains the
Base64url-encoded Ed25519 signature of the HTTP request or response body.

As with all digital signatures: You sign them with your secret key, and they can be
verified with your public key. Possessing the public key does not grant you the power
to issue forgeries.

Algorithm: Ed25519

### `verifySignedRequest()` / `verifySignedResponse()`

Function prototypes:

```php
function verifySignedRequest(
    RequestInterface $request,
    SigningPublicKey $secretKey
): RequestInterface;

function verifySignedResponse(
    ResponseInterface $response,
    SigningPublicKey $publicKey
): ResponseInterface;
```

These methods verify that the signature contained in the `Body-Signature-Ed25519` header
is valid for the body of the HTTP request or response object, given the correct public key.

If there is no header present, a `HeaderMissingException` is thrown.

If the signature is not valid, an `InvalidMessageException` is thrown.

Otherwise, it returns the object verbatim.

Algorithm: Ed25519

## JSON API Methods

See [the JSON Sugar Trait](Traits/JsonSugar.md) for the JSON API helper methods.

## Adapter Methods

If you're using an adapter that implements [`ConvenienceInterface`](Adapter/ConvenienceInterface.md),
you can quickly create Request/Response objects specific to your framework and then use Sapient to
secure them.

Not all adapters implement this interface.
