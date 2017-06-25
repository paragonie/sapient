# Tutorial

## Getting Sapient

If you're familiar with Composer, setup is as easy as `php composer.phar require paragonie/sapient:^1`.

If you're not using Composer, you can either adopt Composer or extract the contents of our
`src` directory to an appropriate place in your project and write your own SPL autoloader.

We recommend using Composer and keeping your dependencies up-to-date.

## Using Sapient with Your PHP Framework

If your framework already uses PSR-7 objects, you can simply use the Sapient methods
through a Middleware to add signatures, encryption, etc.

For example, this will first encrypt an HTTP response with the client's public key
(so that only the client may decrypt it), and then sign the encrypted message with
the server's secret key (so that the client can verify it came from the server):

```php
<?php
/**
 * @var Psr\Http\Message\ResponseInterface $nakedResponse
 * @var ParagonIE\Sapient\Sapient $sapient
 * @var ParagonIE\Sapient\CryptographyKeys\SigningSecretKey $signingKey
 * @var ParagonIE\Sapient\CryptographyKeys\SealingPublicKey $clientPublicKey
 */
$sealedResponse = $sapient->sealResponse($nakedResponse, $clientPublicKey);
$signedResponse = $sapient->signResponse($sealedResponse, $signingKey);
```

Before you get to this point, first you'll need to create and store your
cryptography keys.

### Key Management

#### Generating Keys

To generate a new key, you can simply use the `generate()` method on the appropriate
[`CryptographyKey`](Internals/CryptographyKey.md) object.

```php
<?php
use ParagonIE\Sapient\CryptographyKeys\{
    SealingSecretKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningSecretKey
};

$sealSecret = SealingSecretKey::generate();
$signSecret = SigningSecretKey::generate();

$sharedEncryptionKey = SharedEncryptionKey::generate();
$sharedAuthenticationKey = SharedAuthenticationKey::generate();
```

**Note**: You cannot generate public keys. You *can* generate a secret key and then
obtain the associated public key, but it doesn't mane sense to generate a public key
for which you do not know the secret key.

```php
$sealPublic = $sealSecret->getPublicKey();
$signPublic = $signSecret->getPublicKey();
```

#### Saving / Loading `CryptographyKey` objects

Every key object has a `getString()` method which will return a [base64url](https://tools.ietf.org/html/rfc4648#page-7)
encoded string by default. If you want raw binary, pass `true` as the only argument to this method.

You may then store these strings as you would any other secret information.

To **load a `CryptographyKey` from a string**, simply pass it to the constructor, like so:

```php
<?php
use ParagonIE\Sapient\CryptographyKeys\SigningSecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;

/** @var string $yourEncodedStringHere*/

$signSecret = new SigningSecretKey(
    Base64UrlSafe::decode($yourEncodedStringHere)
    // This assumes it was stored with getString() rather than getString(true)
);
```
