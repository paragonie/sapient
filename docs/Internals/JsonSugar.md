# The JSON Sugar Trait

The methods here are similar to the [string methods](StringSugar.md), except:

1. They assume that the message body is a valid JSON string
2. They dcode the message body into an array

### `decodeSymmetricAuthenticatedJsonRequest()` / `decodeSymmetricAuthenticatedJsonResponse()`

Function prototypes:

```php
function decodeSymmetricAuthenticatedJsonRequest(
    RequestInterface $request,
    SharedAuthenticationKey $key
): array;

function decodeSymmetricAuthenticatedJsonResponse(
    ResponseInterface $response,
    SharedAuthenticationKey $key
): array;
```

### `decodeSignedJsonRequest()` / `decodeSignedJsonResponse()`

Function prototypes:

```php
function decodeSignedJsonRequest(
    RequestInterface $request,
    SigningPublicKey $publicKey
): array;

function decodeSignedJsonResponse(
    ResponseInterface $response,
    SigningPublicKey $publicKey
): array;
```

### `decryptJsonRequestWithSharedKey()` / `decryptJsonResponseWithSharedKey()`

Function prototypes:

```php
function decryptJsonRequestWithSharedKey(
    RequestInterface $request,
    SharedEncryptionKey $key
): array;

function decryptJsonResponseWithSharedKey(
    ResponseInterface $response,
    SharedEncryptionKey $key
): array;
```

### `unsealJsonRequest()` / `unsealJsonResponse()`

Function prototypes:

```php
function unsealJsonRequest(
    RequestInterface $request,
    SealingSecretKey $secretKey
): array;

function unsealJsonResponse(
    ResponseInterface $response,
    SealingSecretKey $secretKey
): array;
```
