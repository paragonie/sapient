<?php
declare(strict_types=1);
namespace ParagonIE\Sapient;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\AdapterInterface;
use ParagonIE\Sapient\Adapter\Generic\Adapter;
use ParagonIE\Sapient\Exception\{
    HeaderMissingException,
    InvalidMessageException
};
use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningPublicKey,
    SigningSecretKey
};
use ParagonIE\Sapient\Traits\JsonSugar;
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface,
    StreamInterface
};
use SodiumException;

/**
 * Class Sapient
 * @package ParagonIE\Sapient
 *
 * These methods are provided by the adapter:
 * @method RequestInterface createSymmetricAuthenticatedJsonRequest(string $method, string $uri, array $arrayToJsonify, SharedAuthenticationKey $key, array $headers = [])
 * @method ResponseInterface createSymmetricAuthenticatedJsonResponse(int $status, array $arrayToJsonify, SharedAuthenticationKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSymmetricEncryptedJsonRequest(string $method, string $uri, array $arrayToJsonify, SharedEncryptionKey $key, array $headers = [])
 * @method ResponseInterface createSymmetricEncryptedJsonResponse(int $status, array $arrayToJsonify, SharedEncryptionKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSealedJsonRequest(string $method, string $uri, array $arrayToJsonify, SealingPublicKey $key, array $headers = [])
 * @method ResponseInterface createSealedJsonResponse(int $status, array $arrayToJsonify, SealingPublicKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSignedJsonRequest(string $method, string $uri, array $arrayToJsonify, SigningSecretKey $key, array $headers = [])
 * @method ResponseInterface createSignedJsonResponse(int $status, array $arrayToJsonify, SigningSecretKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSymmetricAuthenticatedRequest(string $method, string $uri, string $body, SharedAuthenticationKey $key, array $headers = [])
 * @method ResponseInterface createSymmetricAuthenticatedResponse(int $status, string $body, SharedAuthenticationKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSymmetricEncryptedRequest(string $method, string $uri, string $body, SharedEncryptionKey $key, array $headers = [])
 * @method ResponseInterface createSymmetricEncryptedResponse(int $status, string $body, SharedEncryptionKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSealedRequest(string $method, string $uri, string $body, SealingPublicKey $key, array $headers = [])
 * @method ResponseInterface createSealedResponse(int $status, string $body, SealingPublicKey $key, array $headers = [], string $version = '1.1')
 * @method RequestInterface createSignedRequest(string $method, string $uri, string $body, SigningSecretKey $key, array $headers = [])
 * @method ResponseInterface createSignedResponse(int $status, string $body, SigningSecretKey $key, array $headers = [], string $version = '1.1')
 * @method StreamInterface stringToStream(string $input)
 */
class Sapient
{
    use JsonSugar;

    const HEADER_AUTH_NAME = 'Body-HMAC-SHA512256';
    const HEADER_SIGNATURE_NAME = 'Body-Signature-Ed25519';

    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * Sapient constructor.
     *
     * @param AdapterInterface $adapter
     */
    public function __construct(AdapterInterface $adapter = null)
    {
        if (!$adapter) {
            $adapter = new Adapter();
        }
        $this->adapter = $adapter;
    }

    /**
     * Authenticate an HTTP request with a pre-shared key.
     *
     * @param RequestInterface $request
     * @param SharedAuthenticationKey $key
     * @return RequestInterface
     */
    public function authenticateRequestWithSharedKey(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): RequestInterface {
        $mac = \ParagonIE_Sodium_Compat::crypto_auth(
            (string) (clone $request)->getBody(),
            $key->getString(true)
        );
        return $request->withAddedHeader(
            self::HEADER_AUTH_NAME,
            Base64UrlSafe::encode($mac)
        );
    }

    /**
     * Authenticate an HTTP response with a pre-shared key.
     *
     * @param ResponseInterface $response
     * @param SharedAuthenticationKey $key
     * @return ResponseInterface
     */
    public function authenticateResponseWithSharedKey(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): ResponseInterface {
        $mac = \ParagonIE_Sodium_Compat::crypto_auth(
            (string) (clone $response)->getBody(),
            $key->getString(true)
        );
        return $response->withAddedHeader(
            self::HEADER_AUTH_NAME,
            Base64UrlSafe::encode($mac)
        );
    }

    /**
     * Decrypt an HTTP request with a pre-shared key.
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return RequestInterface
     */
    public function decryptRequestWithSharedKey(
        RequestInterface $request,
        SharedEncryptionKey $key
    ): RequestInterface {
        $encrypted = Base64UrlSafe::decode((string) $request->getBody());
        return $request->withBody(
            $this->adapter->stringToStream(
                Simple::decrypt($encrypted, $key)
            )
        );
    }

    /**
     * Decrypt an HTTP response with a pre-shared key.
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return ResponseInterface
     */
    public function decryptResponseWithSharedKey(
        ResponseInterface $response,
        SharedEncryptionKey $key
    ): ResponseInterface {
        $encrypted = Base64UrlSafe::decode((string) $response->getBody());
        return $response->withBody(
            $this->adapter->stringToStream(
                Simple::decrypt($encrypted, $key)
            )
        );
    }

    /**
     * Encrypt an HTTP request with a pre-shared key.
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return RequestInterface
     */
    public function encryptRequestWithSharedKey(
        RequestInterface $request,
        SharedEncryptionKey $key
    ): RequestInterface {
        $encrypted = Base64UrlSafe::encode(
            Simple::encrypt((string) $request->getBody(), $key)
        );
        return $request->withBody(
            $this->adapter->stringToStream($encrypted)
        );
    }

    /**
     * Encrypt an HTTP response with a pre-shared key.
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return ResponseInterface
     */
    public function encryptResponseWithSharedKey(
        ResponseInterface $response,
        SharedEncryptionKey $key
    ): ResponseInterface {
        $encrypted = Base64UrlSafe::encode(
            Simple::encrypt((string) $response->getBody(), $key)
        );
        return $response->withBody(
            $this->adapter->stringToStream($encrypted)
        );
    }

    /**
     * @return AdapterInterface
     */
    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * Encrypt an HTTP request body with a public key.
     *
     * @param RequestInterface $request
     * @param SealingPublicKey $publicKey
     * @return RequestInterface
     */
    public function sealRequest(
        RequestInterface $request,
        SealingPublicKey $publicKey
    ): RequestInterface {
        $sealed = Simple::seal(
            (string) $request->getBody(),
            $publicKey
        );
        return $request->withBody(
            $this->adapter->stringToStream(
                Base64UrlSafe::encode($sealed)
            )
        );
    }

    /**
     * Encrypt an HTTP response body with a public key.
     *
     * @param ResponseInterface $response
     * @param SealingPublicKey $publicKey
     * @return ResponseInterface
     */
    public function sealResponse(
        ResponseInterface $response,
        SealingPublicKey $publicKey
    ): ResponseInterface {
        $sealed = Simple::seal(
            (string) $response->getBody(),
            $publicKey
        );
        return $response->withBody(
            $this->adapter->stringToStream(
                Base64UrlSafe::encode($sealed)
            )
        );
    }

    /**
     * Add an Ed25519 signature to an HTTP request object.
     *
     * @param RequestInterface $request
     * @param SigningSecretKey $secretKey
     * @return RequestInterface
     */
    public function signRequest(
        RequestInterface $request,
        SigningSecretKey $secretKey
    ): RequestInterface {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            (string) (clone $request)->getBody(),
            $secretKey->getString(true)
        );
        return $request->withAddedHeader(
            (string) static::HEADER_SIGNATURE_NAME,
            Base64UrlSafe::encode($signature)
        );
    }

    /**
     * Add an Ed25519 signature to an HTTP response object.
     *
     * @param ResponseInterface $response
     * @param SigningSecretKey $secretKey
     * @return ResponseInterface
     */
    public function signResponse(
        ResponseInterface $response,
        SigningSecretKey $secretKey
    ): ResponseInterface {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            (string) (clone $response)->getBody(),
            $secretKey->getString(true)
        );
        return $response->withAddedHeader(
            (string) static::HEADER_SIGNATURE_NAME,
            Base64UrlSafe::encode($signature)
        );
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint.
     *
     * @param RequestInterface $request
     * @param SealingSecretKey $secretKey
     * @return RequestInterface
     * @throws InvalidMessageException
     */
    public function unsealRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): RequestInterface {
        $body = Base64UrlSafe::decode((string) $request->getBody());
        $unsealed = Simple::unseal(
            $body,
            $secretKey
        );
        return $request->withBody($this->adapter->stringToStream($unsealed));
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint.
     *
     * @param ResponseInterface $response
     * @param SealingSecretKey $secretKey
     * @return ResponseInterface
     * @throws InvalidMessageException
     */
    public function unsealResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): ResponseInterface {
        $body = Base64UrlSafe::decode((string) $response->getBody());
        $unsealed = Simple::unseal(
            $body,
            $secretKey
        );
        return $response->withBody($this->adapter->stringToStream($unsealed));
    }

    /**
     * Verifies the signature contained in the Body-Signature-Ed25519 header
     * is valid for the HTTP Request body provided. Will either return the
     * request given, or throw an InvalidMessageException if the signature
     * is invalid. Will also throw a HeaderMissingException is there is no
     * Body-Signature-Ed25519 header.
     *
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return RequestInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     * @throws SodiumException
     */
    public function verifySignedRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader((string) static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed request header (' . (string) static::HEADER_SIGNATURE_NAME . ') found.'
            );
        }

        $body = (string) (clone $request)->getBody();
        foreach ($headers as $head) {
            $result = \ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                Base64UrlSafe::decode($head),
                $body,
                $publicKey->getString(true)
            );
            if ($result) {
                return $request;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP request');
    }

    /**
     * Verifies the signature contained in the Body-Signature-Ed25519 header
     * is valid for the HTTP Response body provided. Will either return the
     * response given, or throw an InvalidMessageException if the signature
     * is invalid. Will also throw a HeaderMissingException is there is no
     * Body-Signature-Ed25519 header.
     *
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return ResponseInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     * @throws SodiumException
     */
    public function verifySignedResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): ResponseInterface {
        /** @var array<int, string> */
        $headers = $response->getHeader((string) static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed response header (' . (string) static::HEADER_SIGNATURE_NAME . ') found.'
            );
        }

        $body = (string) (clone $response)->getBody();
        foreach ($headers as $head) {
            $result = \ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                Base64UrlSafe::decode($head),
                $body,
                $publicKey->getString(true)
            );
            if ($result) {
                return $response;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP response');
    }


    /**
     * Verify that the Body-HMAC-SHA512256 header correctly authenticates the
     * HTTP Request. Will either return the request given, or throw an
     * InvalidMessageException if the signature is invalid. Will also throw a
     * HeaderMissingException is there is no Body-HMAC-SHA512256 header.
     *
     * @param RequestInterface $request
     * @param SharedAuthenticationKey $key
     * @return RequestInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     * @throws SodiumException
     */
    public function verifySymmetricAuthenticatedRequest(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader((string) static::HEADER_AUTH_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed request header (' . (string) static::HEADER_AUTH_NAME . ') found.'
            );
        }

        $body = (string) (clone $request)->getBody();
        foreach ($headers as $head) {
            $result = \ParagonIE_Sodium_Compat::crypto_auth_verify(
                Base64UrlSafe::decode($head),
                $body,
                $key->getString(true)
            );
            if ($result) {
                return $request;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP request');
    }

    /**
     * Verify that the Body-HMAC-SHA512256 header correctly authenticates the
     * HTTP Response. Will either return the response given, or throw an
     * InvalidMessageException if the signature is invalid. Will also throw a
     * HeaderMissingException is there is no Body-HMAC-SHA512256 header.
     *
     * @param ResponseInterface $response
     * @param SharedAuthenticationKey $key
     * @return ResponseInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     * @throws SodiumException
     */
    public function verifySymmetricAuthenticatedResponse(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): ResponseInterface {
        /** @var array<int, string> */
        $headers = $response->getHeader((string) static::HEADER_AUTH_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed response header (' . (string) static::HEADER_AUTH_NAME . ') found.'
            );
        }

        $body = (string) (clone $response)->getBody();
        foreach ($headers as $head) {
            $result = \ParagonIE_Sodium_Compat::crypto_auth_verify(
                Base64UrlSafe::decode($head),
                $body,
                $key->getString(true)
            );
            if ($result) {
                return $response;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP response');
    }

    /**
     * Punt adapter methods to the adapter.
     *
     * @param string $name
     * @param array $arguments
     * @return mixed
     * @throws \Error
     */
    public function __call($name, $arguments)
    {
        if (!\method_exists($this->adapter, $name)) {
            throw new \Error('Could not call method ' . $name);
        }
        return $this->adapter->$name(...$arguments);
    }
}
