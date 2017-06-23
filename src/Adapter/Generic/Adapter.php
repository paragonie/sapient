<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\Adapter\Generic;

use ParagonIE\Sapient\Adapter\AdapterInterface;
use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningSecretKey
};
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface,
    StreamInterface
};

/**
 * Class Guzzle
 * @package ParagonIE\Sapient\Adapter
 */
class Adapter implements AdapterInterface
{
    const GENERIC_NOT_IMPLEMENTED = 'This is not implemented in the generic adapter; please use another adapter (e.g. Guzzle).';

    /**
     * Create an HTTP request object with a JSON body that is authenticated
     * with a pre-shared key. The authentication tag is stored in a
     * Body-HMAC-SHA512256 header.
     *
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSymmetricAuthenticatedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Create an HTTP response object with a JSON body that is authenticated
     * with a pre-shared key. The authentication tag is stored in a
     * Body-HMAC-SHA512256 header.
     *
     * @param int $status
     * @param array $arrayToJsonify
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSymmetricAuthenticatedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Create an HTTP request object with a JSON body that is encrypted
     * with a pre-shared key.
     *
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSymmetricEncryptedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Create an HTTP response object with a JSON body that is encrypted
     * with a pre-shared key.
     *
     * @param int $status
     * @param array $arrayToJsonify
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSymmetricEncryptedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Create an HTTP request object with a JSON body that is encrypted
     * with the server's public key.
     *
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SealingPublicKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSealedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Create an HTTP response object with a JSON body that is encrypted
     * with the server's public key.
     *
     * @param int $status
     * @param array $arrayToJsonify
     * @param SealingPublicKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSealedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Creates a JSON-signed API request to be sent to an API.
     * Enforces hard-coded Ed25519 keys.
     *
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SigningSecretKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSignedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Creates a JSON-signed API response to be returned from an API.
     * Enforces hard-coded Ed25519 keys.
     *
     * @param int $status
     * @param array $arrayToJsonify
     * @param SigningSecretKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSignedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Authenticate your HTTP request with a pre-shared key.
     *
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSymmetricAuthenticatedRequest(
        string $method,
        string $uri,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Authenticate your HTTP response with a pre-shared key.
     *
     * @param int $status
     * @param string $body
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSymmetricAuthenticatedResponse(
        int $status,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Encrypt your HTTP request with a pre-shared key.
     *
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSymmetricEncryptedRequest(
        string $method,
        string $uri,
        string $body,
        SharedEncryptionKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Encrypt your HTTP response with a pre-shared key.
     *
     * @param int $status
     * @param string $body
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSymmetricEncryptedResponse(
        int $status,
        string $body,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Encrypt your HTTP request with the server's public key, so that only
     * the server can decrypt the message.
     *
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SealingPublicKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSealedRequest(
        string $method,
        string $uri,
        string $body,
        SealingPublicKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Encrypt your HTTP response with the client's public key, so that only
     * the client can decrypt the message.
     *
     * @param int $status
     * @param string $body
     * @param SealingPublicKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSealedResponse(
        int $status,
        string $body,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Ed25519-sign a request body.
     *
     * This adds an HTTP header (Body-Signature-Ed25519) which is the base64url
     * encoded Ed25519 signature of the HTTP request body.
     *
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SigningSecretKey $key
     * @param array $headers
     * @return RequestInterface
     * @throws NotImplementedException
     */
    public function createSignedRequest(
        string $method,
        string $uri,
        string $body,
        SigningSecretKey $key,
        array $headers = []
    ): RequestInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Ed25519-sign a response body.
     *
     * This adds an HTTP header (Body-Signature-Ed25519) which is the base64url
     * encoded Ed25519 signature of the HTTP response body.
     *
     * @param int $status
     * @param string $body
     * @param SigningSecretKey $key
     * @param array $headers
     * @param string $version
     * @return ResponseInterface
     * @throws NotImplementedException
     */
    public function createSignedResponse(
        int $status,
        string $body,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        throw new NotImplementedException(static::GENERIC_NOT_IMPLEMENTED);
    }

    /**
     * Adapter-specific way of converting a string into a StreamInterface
     *
     * @param string $input
     * @return StreamInterface
     * @throws \Error
     */
    public function stringToStream(string $input): StreamInterface
    {
        return Stream::fromString($input);
    }
}