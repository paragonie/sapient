# Adapter: Convenience Features

The `ConvenienceInterface` specifies a bunch of method prototypes for creating
`Request` and `Response` objects specific to your framework's PSR-7 implementation.

## Interface Methods

### `createSymmetricAuthenticatedJsonRequest()` / `createSymmetricAuthenticatedJsonResponse()`

```php
function createSymmetricAuthenticatedJsonRequest(
    string $method,
    string $uri,
    array $arrayToJsonify,
    SharedAuthenticationKey $key,
    array $headers = []
): RequestInterface;

function createSymmetricAuthenticatedJsonResponse(
    int $status,
    array $arrayToJsonify,
    SharedAuthenticationKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

```php
function createSymmetricEncryptedJsonRequest(
    string $method,
    string $uri,
    array $arrayToJsonify,
    SharedEncryptionKey $key,
    array $headers = []
): RequestInterface;

function createSymmetricEncryptedJsonResponse(
    int $status,
    array $arrayToJsonify,
    SharedEncryptionKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSealedJsonRequest()` / `createSealedJsonResponse()`

```php
function createSealedJsonRequest(
    string $method,
    string $uri,
    array $arrayToJsonify,
    SealingPublicKey $key,
    array $headers = []
): RequestInterface;

function createSealedJsonResponse(
    int $status,
    array $arrayToJsonify,
    SealingPublicKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSignedJsonRequest()` / `createSignedJsonResponse()` 

```php
function createSignedJsonRequest(
    string $method,
    string $uri,
    array $arrayToJsonify,
    SigningSecretKey $key,
    array $headers = []
): RequestInterface;

public function createSignedJsonResponse(
    int $status,
    array $arrayToJsonify,
    SigningSecretKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSymmetricAuthenticatedRequest()` / `createSymmetricAuthenticatedResponse()` 

```php
public function createSymmetricAuthenticatedRequest(
    string $method,
    string $uri,
    string $body,
    SharedAuthenticationKey $key,
    array $headers = []
): RequestInterface;

public function createSymmetricAuthenticatedResponse(
    int $status,
    string $body,
    SharedAuthenticationKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSymmetricEncryptedRequest()` / `createSymmetricEncryptedResponse()`

```php
function createSymmetricEncryptedRequest(
    string $method,
    string $uri,
    string $body,
    SharedEncryptionKey $key,
    array $headers = []
): RequestInterface;

function createSymmetricEncryptedResponse(
    int $status,
    string $body,
    SharedEncryptionKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSealedRequest()` / `createSealedResponse()`

```php
function createSealedRequest(
    string $method,
    string $uri,
    string $body,
    SealingPublicKey $key,
    array $headers = []
): RequestInterface;

function createSealedResponse(
    int $status,
    string $body,
    SealingPublicKey $key,
    array $headers = [],
    string $version = '1.1'
): ResponseInterface;
```

### `createSignedRequest()` / `createSignedResponse()`

```php
function createSignedRequest(
    string $method,
    string $uri,
    string $body,
    SigningSecretKey $key,
    array $headers = []
): RequestInterface;

function createSignedResponse(
    int $status,
    string $body,
    SigningSecretKey $key,
    array $headers = [],
    string $version = '1.1'
);
```
