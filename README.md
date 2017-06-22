# Sapient: Secure API toolkit

[![Build Status](https://travis-ci.org/paragonie/sapient.svg?branch=master)](https://travis-ci.org/paragonie/sapient)
[![Latest Stable Version](https://poser.pugx.org/paragonie/sapient/v/stable)](https://packagist.org/packages/paragonie/sapient)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/sapient/v/unstable)](https://packagist.org/packages/paragonie/sapient)
[![License](https://poser.pugx.org/paragonie/sapient/license)](https://packagist.org/packages/paragonie/sapient)

**Sapient** secures your PHP applications' server-to-server HTTP(S) traffic even in the wake of a
TLS security breakdown (compromised certificate authority, etc.).

> See [our blog post about using Sapient to harden your PHP-powered APIs](https://paragonie.com/blog/2017/06/hardening-your-php-powered-apis-with-sapient)
> for more information about its design rationale and motivation.

Requires PHP 7.

Sapient allows you to quickly and easily add application-layer cryptography to your API requests
and responses.

The cryptography is provided by [sodium_compat](https://github.com/paragonie/sodium_compat) (which,
in turn, will use the libsodium extension in PECL if it's installed).

## Features at a Glance

* Works with both `Request` and `Response` objects (PSR-7)
  * Includes a Guzzle adapter for HTTP clients
* Secure APIs:
  * Shared-key encryption
    * XChaCha20-Poly1305
  * Shared-key authentication
    * HMAC-SHA512-256
  * Anonymous public-key encryption
    * X25519 + BLAKE2b + XChaCha20-Poly1305
  * Public-key digital signatures
    * Ed25519
* Works with arrays
  * i.e. the methods with "Json" in the name
  * Sends/receives signed or encrypted JSON
* Works with strings
  * i.e. the methods without "Json" in the name
* Digital signatures and authentication are backwards-compatible
  with unsigned JSON API clients and servers
  * The signaure and authentication tag will go into HTTP headers,
    rather than the request/response body.

Additionally, Sapient is covered by both **unit tests** (provided by [PHPUnit](https://github.com/sebastianbergmann/phpunit)) and
**automated static analysis** (provided by [Psalm](https://github.com/vimeo/psalm))

## Example: Mutually Signed JSON API

### Client-Side, Sending a Signed Request, Verifying the Response

```php
<?php

use GuzzleHttp\Client;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle as GuzzleAdapter;
use ParagonIE\Sapient\Sapient;
use ParagonIE\Sapient\CryptographyKeys\SigningPublicKey;
use ParagonIE\Sapient\CryptographyKeys\SigningSecretKey;
use ParagonIE\Sapient\Exception\InvalidMessageException;

$http = new Client([
    'base_uri' => 'https://your-api.example.com'
]);
$sapient = new Sapient(new GuzzleAdapter($http));

// Keys
$clientSigningKey = new SigningSecretKey(
    Base64UrlSafe::decode(
        'AHxoibWhTylBMgFzJp6GGgYto24PVbQ-ognw9SPnvKppfti72R8By8XnIMTJ8HbDTks7jK5GmAnvtzaj3rbcTA=='
    )
);
$serverPublicKey = new SigningPublicKey(
    Base64UrlSafe::decode(
        'NvwsINZ-1y0F11xxed_FEUaL_MVewhdgF9tMYf5qEEw='
    )    
);

// We use an array to define our message
$myMessage = [
    'date' => (new DateTime)->format(DateTime::ATOM),
    'body' => [
        'test' => 'hello world!'        
    ]
];

// Create the signed request:
$request = $sapient->createSignedJsonRequest(
    'POST',
     '/my/api/endpoint',
     $myMessage,
     $clientSigningKey
);

$response = $http->send($request);
try {
    /** @var array $verifiedResponse */
    $verifiedResponse = $sapient->decodeSignedJsonResponse(
        $response,
        $serverPublicKey
    );
} catch (InvalidMessageException $ex) {
    \http_response_code(500);
    exit;
}

```

### Server-Side: Verifying a Signed Request, Signing a Response

```php
 <?php

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\ServerRequest;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle as GuzzleAdapter;
use ParagonIE\Sapient\Sapient;
use ParagonIE\Sapient\CryptographyKeys\SigningPublicKey;
use ParagonIE\Sapient\CryptographyKeys\SigningSecretKey;
use ParagonIE\Sapient\Exception\InvalidMessageException;

$http = new Client([
    'base_uri' => 'https://your-api.example.com'
]);
$sapient = new Sapient(new GuzzleAdapter($http));
 
$clientPublicKey = new SigningPublicKey(
    Base64UrlSafe::decode(
        'aX7Yu9kfAcvF5yDEyfB2w05LO4yuRpgJ77c2o9623Ew='
    )
);
$request = ServerRequest::fromGlobals();
try {
    /** @var array $decodedRequest */
    $decodedRequest = $sapient->decodeSignedJsonRequest(
        $request,
        $clientPublicKey
    );
} catch (InvalidMessageException $ex) {
    \http_response_code(500);
    exit;
}

/* Business logic goes here */

// Signing a response:
$serverSignSecret = new SigningSecretKey(
    Base64UrlSafe::decode(
        'q6KSHArUnD0sEa-KWpBCYLka805gdA6lVG2mbeM9kq82_Cwg1n7XLQXXXHF538URRov8xV7CF2AX20xh_moQTA=='
    )
);

$responseMessage = [
    'date' => (new DateTime)->format(DateTime::ATOM),
    'body' => [
        'status' => 'OK',
        'message' => 'We got your message loud and clear.'
    ]
];

$response = $sapient->createSignedJsonResponse(
    200,
    $responseMessage,
    $serverSignSecret
);
/* If your framework speaks PSR-7, just return the response object and let it
   take care of the rest. */
```
