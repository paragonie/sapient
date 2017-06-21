<?php
declare(strict_types=1);
namespace ParagonIE\Sapient;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\{
    Request,
    Response
};
use function GuzzleHttp\Psr7\stream_for;
use ParagonIE\ConstantTime\Base64UrlSafe;
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
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface
};

/**
 * Class Crypto
 * @package ParagonIE\Psr7Crypto
 */
class Sapient extends Client
{
    const HEADER_AUTH_NAME = 'Body-HMAC-SHA512256';
    const HEADER_SIGNATURE_NAME = 'Body-Signature-Ed25519';

    /**
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @return Request
     * @throws InvalidMessageException
     */
    public function createSymmetricAuthenticatedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = []
    ): Request {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSymmetricAuthenticatedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
    }

    /**
     * @param int $status
     * @param array $arrayToJsonify
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     * @throws InvalidMessageException
     */
    public function createSymmetricAuthenticatedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSymmetricAuthenticatedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @return Request
     * @throws InvalidMessageException
     */
    public function createSymmetricEncryptedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = []
    ): Request {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSymmetricEncryptedRequest(
            $method,
            $uri,
            $body,
            $key,
            $headers
        );
    }

    /**
     * @param int $status
     * @param array $arrayToJsonify
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     * @throws InvalidMessageException
     */
    public function createSymmetricEncryptedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSymmetricEncryptedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param array $arrayToJsonify
     * @param SealingPublicKey $key
     * @param array $headers
     * @return Request
     * @throws InvalidMessageException
     */
    public function createSealedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = []
    ): Request {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSealedRequest(
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
     * @param SealingPublicKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     * @throws InvalidMessageException
     */
    public function createSealedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
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
     * @return Request
     * @throws InvalidMessageException
     */
    public function createSignedJsonRequest(
        string $method,
        string $uri,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = []
    ): Request {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
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
     * @return Response
     * @throws InvalidMessageException
     */
    public function createSignedJsonResponse(
        int $status,
        array $arrayToJsonify,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        /** @var string $body */
        $body = \json_encode($arrayToJsonify, JSON_PRETTY_PRINT);
        if (!\is_string($body)) {
            throw new InvalidMessageException('Cannot JSON-encode this message.');
        }
        return $this->createSignedResponse(
            $status,
            $body,
            $key,
            $headers,
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @return Request
     */
    public function createSymmetricAuthenticatedRequest(
        string $method,
        string $uri,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = []
    ): Request {
        $mac = \ParagonIE_Sodium_Compat::crypto_auth($body, $key->getString(true));
        if (isset($headers[static::HEADER_SIGNATURE_NAME])) {
            $headers[static::HEADER_AUTH_NAME][] = Base64UrlSafe::encode($mac);
        } else {
            $headers[static::HEADER_AUTH_NAME] = Base64UrlSafe::encode($mac);
        }
        return new Request(
            $method,
            $uri,
            $headers,
            $body
        );
    }

    /**
     * @param int $status
     * @param string $body
     * @param SharedAuthenticationKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     */
    public function createSymmetricAuthenticatedResponse(
        int $status,
        string $body,
        SharedAuthenticationKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        $mac = \ParagonIE_Sodium_Compat::crypto_auth($body, $key->getString(true));
        if (isset($headers[static::HEADER_SIGNATURE_NAME])) {
            $headers[static::HEADER_AUTH_NAME][] = Base64UrlSafe::encode($mac);
        } else {
            $headers[static::HEADER_AUTH_NAME] = Base64UrlSafe::encode($mac);
        }
        return new Response(
            $status,
            $headers,
            $body,
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @return Request
     */
    public function createSymmetricEncryptedRequest(
        string $method,
        string $uri,
        string $body,
        SharedEncryptionKey $key,
        array $headers = []
    ): Request {
        return new Request(
            $method,
            $uri,
            $headers,
            Base64UrlSafe::encode(Simple::encrypt($body, $key))
        );
    }

    /**
     * @param int $status
     * @param string $body
     * @param SharedEncryptionKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     */
    public function createSymmetricEncryptedResponse(
        int $status,
        string $body,
        SharedEncryptionKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        return new Response(
            $status,
            $headers,
            Base64UrlSafe::encode(Simple::encrypt($body, $key)),
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SealingPublicKey $key
     * @param array $headers
     * @return Request
     */
    public function createSealedRequest(
        string $method,
        string $uri,
        string $body,
        SealingPublicKey $key,
        array $headers = []
    ): Request {
        $sealed = \ParagonIE_Sodium_Compat::crypto_box_seal(
            $body,
            $key->getString(true)
        );
        return new Request(
            $method,
            $uri,
            $headers,
            Base64UrlSafe::encode($sealed)
        );
    }

    /**
     * @param int $status
     * @param string $body
     * @param SealingPublicKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     */
    public function createSealedResponse(
        int $status,
        string $body,
        SealingPublicKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        $sealed = \ParagonIE_Sodium_Compat::crypto_box_seal(
            $body,
            $key->getString(true)
        );
        return new Response(
            $status,
            $headers,
            Base64UrlSafe::encode($sealed),
            $version
        );
    }

    /**
     * @param string $method
     * @param string $uri
     * @param string $body
     * @param SigningSecretKey $key
     * @param array $headers
     * @return Request
     */
    public function createSignedRequest(
        string $method,
        string $uri,
        string $body,
        SigningSecretKey $key,
        array $headers = []
    ): Request {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            $body,
            $key->getString(true)
        );
        if (isset($headers[static::HEADER_SIGNATURE_NAME])) {
            $headers[static::HEADER_SIGNATURE_NAME][] = Base64UrlSafe::encode($signature);
        } else {
            $headers[static::HEADER_SIGNATURE_NAME] = Base64UrlSafe::encode($signature);
        }

        return new Request(
            $method,
            $uri,
            $headers,
            $body
        );
    }

    /**
     * Ed25519-sign a request body.
     *
     * @param int $status
     * @param string $body
     * @param SigningSecretKey $key
     * @param array $headers
     * @param string $version
     * @return Response
     */
    public function createSignedResponse(
        int $status,
        string $body,
        SigningSecretKey $key,
        array $headers = [],
        string $version = '1.1'
    ): Response {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            $body,
            $key->getString(true)
        );
        if (isset($headers[static::HEADER_SIGNATURE_NAME])) {
            $headers[static::HEADER_SIGNATURE_NAME][] = Base64UrlSafe::encode($signature);
        } else {
            $headers[static::HEADER_SIGNATURE_NAME] = Base64UrlSafe::encode($signature);
        }
        return new Response(
            $status,
            $headers,
            $body,
            $version
        );
    }

    /**
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public function decodeSignedJsonRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            $this->decodeSignedRequest($request, $publicKey),
            true
        );
    }

    /**
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public function decodeSignedRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): string {
        $verified = $this->verifySignedRequest($request, $publicKey);
        return (string) $verified->getBody();
    }

    /**
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public function decodeSignedJsonResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            $this->decodeSignedResponse($response, $publicKey),
            true
        );
    }

    /**
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public function decodeSignedResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): string {
        $verified = $this->verifySignedResponse($response, $publicKey);
        return (string) $verified->getBody();
    }

    /**
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return array
     */
    public function decryptJsonRequestWithSharedKey(
        RequestInterface $request,
        SharedEncryptionKey $key
    ): array {
        $decrypted = $this->decryptRequestWithSharedKey(
            $request,
            $key
        );
        return \json_decode(
            (string) $decrypted->getBody(),
            true
        );
    }
    /**
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return array
     */
    public function decryptJsonResponseWithSharedKey(
        ResponseInterface $response,
        SharedEncryptionKey $key
    ): array {
        $decrypted = $this->decryptResponseWithSharedKey(
            $response,
            $key
        );
        return \json_decode(
            (string) $decrypted->getBody(),
            true
        );
    }

    /**
     * Decrypt a message with a shared key.
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
            stream_for(
                Simple::decrypt($encrypted, $key)
            )
        );
    }

    /**
     * Decrypt a message with a shared key.
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
            stream_for(
                Simple::decrypt($encrypted, $key)
            )
        );
    }

    /**
     * Encrypt a message with a shared key.
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
            stream_for($encrypted)
        );
    }

    /**
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
            stream_for($encrypted)
        );
    }

    /**
     * @param RequestInterface $request
     * @param SealingSecretKey $secretKey
     * @return array
     */
    public function unsealJsonRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            (string) $this->unsealRequest($request, $secretKey)->getBody(),
            true
        );
    }

    /**
     * @param ResponseInterface $response
     * @param SealingSecretKey $secretKey
     * @return array
     */
    public function unsealJsonResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            (string) $this->unsealResponse($response, $secretKey)->getBody(),
            true
        );
    }

    /**
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
        $unsealed = \ParagonIE_Sodium_Compat::crypto_box_seal_open(
            $body,
            $secretKey->getStringForSealOpen()
        );
        if (!\is_string($unsealed)) {
            throw new InvalidMessageException('Invalid message authentication code');
        }
        return $request->withBody(stream_for($unsealed));
    }

    /**
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
        $unsealed = \ParagonIE_Sodium_Compat::crypto_box_seal_open(
            $body,
            $secretKey->getStringForSealOpen()
        );
        if (!\is_string($unsealed)) {
            throw new InvalidMessageException('Invalid message authentication code');
        }
        return $response->withBody(stream_for($unsealed));
    }

    /**
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return RequestInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     */
    public function verifySignedRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader(static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException('No signed request header (' . static::HEADER_SIGNATURE_NAME . ') found.');
        }

        $body = (string) $request->getBody();
        foreach ($headers as $head) {
            $signature = Base64UrlSafe::decode($head);
            if (\ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $body, $publicKey->getString(true))) {
                return $request;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP request');
    }
    
    /**
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return ResponseInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     */
    public function verifySignedResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): ResponseInterface {
        /** @var array<int, string> */
        $headers = $response->getHeader(static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException('No signed response header (' . static::HEADER_SIGNATURE_NAME . ') found.');
        }

        $body = (string) $response->getBody();
        foreach ($headers as $head) {
            $signature = Base64UrlSafe::decode($head);
            if (\ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $body, $publicKey->getString(true))) {
                return $response;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP response');
    }


    /**
     * @param RequestInterface $request
     * @param SharedAuthenticationKey $key
     * @return RequestInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     */
    public function verifySymmetricAuthenticatedRequest(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader(static::HEADER_AUTH_NAME);
        if (!$headers) {
            throw new HeaderMissingException('No signed request header (' . static::HEADER_AUTH_NAME . ') found.');
        }

        $body = (string) $request->getBody();
        foreach ($headers as $head) {
            $mac = Base64UrlSafe::decode($head);
            if (\ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $body, $key->getString(true))) {
                return $request;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP request');
    }

    /**
     * @param ResponseInterface $response
     * @param SharedAuthenticationKey $key
     * @return ResponseInterface
     * @throws HeaderMissingException
     * @throws InvalidMessageException
     */
    public function verifySymmetricAuthenticatedResponse(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): ResponseInterface {
        /** @var array<int, string> */
        $headers = $response->getHeader(static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException('No signed response header (' . static::HEADER_SIGNATURE_NAME . ') found.');
        }

        $body = (string) $response->getBody();
        foreach ($headers as $head) {
            $mac = Base64UrlSafe::decode($head);
            if (\ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $body, $key->getString(true))) {
                return $response;
            }
        }
        throw new InvalidMessageException('No valid signature given for this HTTP response');
    }
}
