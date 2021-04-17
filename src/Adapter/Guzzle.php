<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\Adapter;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\{
    Request,
    Response
};
use function GuzzleHttp\Psr7\stream_for;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Exception\{
    InvalidMessageException
};
use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningSecretKey
};
use ParagonIE\Sapient\Sapient;
use ParagonIE\Sapient\Simple;
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface,
    StreamInterface
};

/**
 * Class Guzzle
 * @package ParagonIE\Sapient\Adapter
 */
class Guzzle implements AdapterInterface, ConvenienceInterface
{
    /**
     * @var Client
     */
    protected $guzzle;

    /**
     * Guzzle constructor.
     * @param Client $guzzleClient
     */
    public function __construct(Client $guzzleClient = null)
    {
        if (!$guzzleClient) {
            $guzzleClient = new Client();
        }
        $this->guzzle = $guzzleClient;
    }

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
     * @throws InvalidMessageException
     */
    public function createSymmetricAuthenticatedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = []
    ): RequestInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSymmetricAuthenticatedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
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
     * @throws InvalidMessageException
     */
    public function createSymmetricAuthenticatedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSymmetricAuthenticatedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
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
     * @throws InvalidMessageException
     */
    public function createSymmetricEncryptedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = []
    ): RequestInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSymmetricEncryptedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
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
     * @throws InvalidMessageException
     */
    public function createSymmetricEncryptedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSymmetricEncryptedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
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
     * @throws InvalidMessageException
     */
    public function createSealedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = []
    ): RequestInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSealedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
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
     * @throws InvalidMessageException
     */
    public function createSealedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSealedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
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
     * @throws InvalidMessageException
     */
    public function createSignedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = []
    ): RequestInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSignedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
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
     * @throws InvalidMessageException
     */
    public function createSignedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        list ($body, $headers) = $this->makeJSON($arrayToJsonify, $headers);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        /** @var array $headers */
        return $this->createSignedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
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
     */
    public function createSymmetricAuthenticatedRequest(
        string $method,
        string $uri,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = []
    ): RequestInterface {
        /** @var array<string, array<int|string, string>> $headers */
        $mac = \ParagonIE_Sodium_Compat::crypto_auth($body, $key->getString(true));
        if (isset($headers[Sapient::HEADER_SIGNATURE_NAME])) {
            $headers[Sapient::HEADER_AUTH_NAME][] = Base64UrlSafe::encode($mac);
        } else {
            $headers[Sapient::HEADER_AUTH_NAME] = Base64UrlSafe::encode($mac);
        }
        return new Request(
            $method,
            $uri,
            $headers,
            $body
        );
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
     */
    public function createSymmetricAuthenticatedResponse(
        int $status,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        /** @var array<string, array> $headers */
        $mac = \ParagonIE_Sodium_Compat::crypto_auth($body, $key->getString(true));
        if (isset($headers[Sapient::HEADER_SIGNATURE_NAME])) {
            $headers[Sapient::HEADER_AUTH_NAME][] = Base64UrlSafe::encode($mac);
        } else {
            $headers[Sapient::HEADER_AUTH_NAME] = Base64UrlSafe::encode($mac);
        }
        return new Response(
            $status,
            $headers,
            $body,
            $version
        );
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
     */
    public function createSymmetricEncryptedRequest(
        string $method,
        string $uri,
        string $body,
        SharedEncryptionKey $key,
        array $headers = []
    ): RequestInterface {
        return new Request(
            $method,
            $uri,
            $headers,
            Base64UrlSafe::encode(Simple::encrypt($body, $key))
        );
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
     */
    public function createSymmetricEncryptedResponse(
        int $status,
        string $body,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        return new Response(
            $status,
            $headers,
            Base64UrlSafe::encode(Simple::encrypt($body, $key)),
            $version
        );
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
     */
    public function createSealedRequest(
        string $method,
        string $uri,
        string $body,
        SealingPublicKey $key,
        array $headers = []
    ): RequestInterface {
        $sealed = Simple::seal(
            $body,
            $key
        );
        return new Request(
            $method,
            $uri,
            $headers,
            Base64UrlSafe::encode($sealed)
        );
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
     */
    public function createSealedResponse(
        int $status,
        string $body,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        $sealed = Simple::seal(
            $body,
            $key
        );
        return new Response(
            $status,
            $headers,
            Base64UrlSafe::encode($sealed),
            $version
        );
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
     */
    public function createSignedRequest(
        string $method,
        string $uri,
        string $body,
        SigningSecretKey $key,
        array $headers = []
    ): RequestInterface {
        /** @var array<string, array<int|string, string>> $headers */
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            $body,
            $key->getString(true)
        );
        if (isset($headers[Sapient::HEADER_SIGNATURE_NAME])) {
            $headers[Sapient::HEADER_SIGNATURE_NAME][] = Base64UrlSafe::encode($signature);
        } else {
            $headers[Sapient::HEADER_SIGNATURE_NAME] = Base64UrlSafe::encode($signature);
        }

        return new Request(
            $method,
            $uri,
            $headers,
            $body
        );
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
     */
    public function createSignedResponse(
        int $status,
        string $body,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): ResponseInterface {
        /** @var array<string, array<int|string, string>> $headers */
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            $body,
            $key->getString(true)
        );
        if (isset($headers[Sapient::HEADER_SIGNATURE_NAME])) {
            $headers[Sapient::HEADER_SIGNATURE_NAME][] = Base64UrlSafe::encode($signature);
        } else {
            $headers[Sapient::HEADER_SIGNATURE_NAME] = Base64UrlSafe::encode($signature);
        }
        return new Response(
            $status,
            $headers,
            $body,
            $version
        );
    }

    /**
     * This is not part of the AdapterInterface.
     *
     * @return Client
     */
    public function getGuzzleClient(): Client
    {
        return $this->guzzle;
    }

    /**
     * Adapter-specific way of converting a string into a StreamInterface
     *
     * @param string $input
     * @return StreamInterface
     * @throws \TypeError
     *
     * @psalm-suppress DeprecatedFunction
     */
    public function stringToStream(string $input): StreamInterface
    {
        /** @var StreamInterface|null $stream */
        $stream = stream_for($input);
        if (!($stream instanceof StreamInterface)) {
            throw new \TypeError('Could not convert string to a stream');
        }
        return $stream;
    }

    /**
     * JSON encode body, add Content-Type header.
     *
     * @param array $arrayToJsonify
     * @param array $headers
     * @return array
     */
    protected function makeJSON(array $arrayToJsonify, array $headers): array
    {
        if (empty($headers['Content-Type'])) {
            $headers['Content-Type'] = 'application/json';
        }
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        return [$body, $headers];
    }
}
