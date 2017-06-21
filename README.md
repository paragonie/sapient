# Sapient: Secure API toolkit

[![Build Status](https://travis-ci.org/paragonie/sapient.svg?branch=master)](https://travis-ci.org/paragonie/sapient)
[![Latest Stable Version](https://poser.pugx.org/paragonie/sapient/v/stable)](https://packagist.org/packages/paragonie/sapient)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/sapient/v/unstable)](https://packagist.org/packages/paragonie/sapient)
[![License](https://poser.pugx.org/paragonie/sapient/license)](https://packagist.org/packages/paragonie/sapient)

**Sapient** secures your PHP applications' server-to-server HTTP(S) traffic even in the wake of a
TLS security breakdown (compromised certificate authority, etc.).

Requires PHP 7.

Sapient allows you to quickly and easily add application-layer cryptography to your API requests
and responses.

The cryptography is provided by [sodium_compat](https://github.com/paragonie/sodium_compat) (which,
in turn, will use the libsodium extension in PECL if it's installed). The networking features are
provided by [Guzzle](https://github.com/guzzle/guzzle).

## Example: Mutually Signed JSON API

### Client-Side, Sending a Signed Message

```php
<?php

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Sapient;
use ParagonIE\Sapient\CryptographyKeys\SigningSecretKey;

$http = new Sapient([
    'base_uri' => 'https://your-api.example.com'
]);

// Keys
$clientSigningKey = new SigningSecretKey(
    Base64UrlSafe::decode(
        'AHxoibWhTylBMgFzJp6GGgYto24PVbQ-ognw9SPnvKppfti72R8By8XnIMTJ8HbDTks7jK5GmAnvtzaj3rbcTA=='
    )
);

// Generate a signing key
$mySigningKey = SigningSecretKey::generate();

// We use an array to define our message
$myMessage = [
    'date' => (new DateTime)->format(DateTime::ISO8601),
    'body' => [
        'test' => 'hello world!'        
    ]
];

// Create the signed request:
$request = $http->createSignedJsonRequest(
    'POST',
     '/my/api/endpoint',
     $myMessage,
     $clientSigningKey
);

$response = $http->send($request);
```

### Server-Side, Verifying a Signed Request

```php
 <?php
 
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Sapient;
use ParagonIE\Sapient\CryptographyKeys\SigningPublicKey;
use ParagonIE\Sapient\Exception\InvalidMessageException;

$http = new Sapient();
 
$clientPublicKey = new SigningPublicKey(
    Base64UrlSafe::decode(
        'aX7Yu9kfAcvF5yDEyfB2w05LO4yuRpgJ77c2o9623Ew='
    )
);
$request = \GuzzleHttp\Psr7\ServerRequest::fromGlobals();
try {
    $decodedRequest = $http->decodeSignedJsonRequest(
        $request,
        $clientPublicKey
    );
} catch (InvalidMessageException $ex) {
    \http_response_code(500);
    exit;
}
```
