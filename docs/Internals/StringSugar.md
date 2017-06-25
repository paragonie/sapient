# String Sugar

These methods take an HTTP request or repsonse object (containing an encrypted or
authenticated message) and a cryptography key and return a string containing the
(unencrypted) message body.

The methods here only verify or decrypt.

If you're looking for ways to encrypt or sign, that's adapter-specific (since it has
to create a `Vendor\Specific\Request` or `Vendor\Specific\Response` object), so look
at the adapter you're using to see if it's implemented.

## Methods

### `decryptStringRequestWithSharedKey()` / `decryptStringResponseWithSharedKey()`

Function prototypes:

```php
function decryptStringRequestWithSharedKey(
    RequestInterface $request,
    SharedEncryptionKey $key
): string;

function decryptStringResponseWithSharedKey(
    ResponseInterface $response,
    SharedEncryptionKey $key
): string;
```

Similar to [the shared-key decryption methods in `Sapient`](Sapient.md#decryptrequestwithsharedkey--decryptresponsewithsharedkey),
except they return a `string` rather than a `RequestInterface` or `ResponseInterface`.

### `unsealStringRequest()` / `unsealStringResponse()`

Function prototypes:

```php
function unsealStringRequest(
    RequestInterface $request,
    SealingSecretKey $secretKey
): string;

function unsealStringResponse(
    ResponseInterface $response,
    SealingSecretKey $secretKey
): string;
```

Similar to [the unsealing methods in `Sapient`](Sapient.md#unsealrequest--unsealresponse),
except they return a `string` rather than a `RequestInterface` or `ResponseInterface`.

### `verifyAuthenticatedStringRequest()` / `verifyAuthenticatedStringResponse()`

Function prototypes:

```php
function verifyAuthenticatedStringRequest(
    RequestInterface $request,
    SharedAuthenticationKey $key
): string;

function verifyAuthenticatedStringResponse(
    ResponseInterface $response,
    SharedAuthenticationKey $key
): string;
```

Similar to the [shared-key auth verification methods in `Sapient`](Sapient.md#verifysymmetricauthenticatedrequest--verifysymmetricauthenticatedresponse),
except they return a `string` rather than a `RequestInterface` or `ResponseInterface`.


### `verifySignedStringRequest()` / `verifySignedStringResponse()`

Function prototypes:

```php
function verifySignedStringRequest(
     RequestInterface $request,
     SigningPublicKey $publicKey
 ): string;

function verifySignedStringResponse(
     ResponseInterface $response,
     SigningPublicKey $publicKey
 ): string;
```

Similar to the [signature verification methods in `Sapient`](Sapient.md#verifysignedrequest--verifysignedresponse),
except they return a `string` rather than a `RequestInterface` or `ResponseInterface`.
