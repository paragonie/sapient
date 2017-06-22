<?php
declare(strict_types=1);
namespace ParagonIE\Sapient;

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
 * Class Sapient
 * @package ParagonIE\Sapient
 */
class Sapient
{
    const HEADER_AUTH_NAME = 'Body-HMAC-SHA512256';
    const HEADER_SIGNATURE_NAME = 'Body-Signature-Ed25519';

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid JSON string).
     *
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public static function decodeSignedJsonRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            static::decodeSignedRequest($request, $publicKey),
            true
        );
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then return the body as
     * a string.
     *
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public static function decodeSignedRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): string {
        $verified = static::verifySignedRequest($request, $publicKey);
        return (string) $verified->getBody();
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid JSON string).
     *
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public static function decodeSignedJsonResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            static::decodeSignedResponse($response, $publicKey),
            true
        );
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then return the body as
     * a string.
     *
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public static function decodeSignedResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): string {
        $verified = static::verifySignedResponse($response, $publicKey);
        return (string) $verified->getBody();
    }

    /**
     * Decrypt an HTTP request with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return array
     */
    public static function decryptJsonRequestWithSharedKey(
        RequestInterface $request,
        SharedEncryptionKey $key
    ): array {
        $decrypted = static::decryptRequestWithSharedKey(
            $request,
            $key
        );
        return \json_decode(
            (string) $decrypted->getBody(),
            true
        );
    }
    /**
     * Decrypt an HTTP response with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return array
     */
    public static function decryptJsonResponseWithSharedKey(
        ResponseInterface $response,
        SharedEncryptionKey $key
    ): array {
        $decrypted = static::decryptResponseWithSharedKey(
            $response,
            $key
        );
        return \json_decode(
            (string) $decrypted->getBody(),
            true
        );
    }

    /**
     * Decrypt an HTTP request with a pre-shared key.
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return RequestInterface
     */
    public static function decryptRequestWithSharedKey(
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
     * Decrypt an HTTP response with a pre-shared key.
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return ResponseInterface
     */
    public static function decryptResponseWithSharedKey(
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
     * Encrypt an HTTP request with a pre-shared key.
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return RequestInterface
     */
    public static function encryptRequestWithSharedKey(
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
     * Encrypt an HTTP response with a pre-shared key.
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return ResponseInterface
     */
    public static function encryptResponseWithSharedKey(
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
     * Encrypt an HTTP request body with a public key.
     *
     * @param RequestInterface $request
     * @param SealingPublicKey $publicKey
     * @return RequestInterface
     */
    public static function sealRequest(
        RequestInterface $request,
        SealingPublicKey $publicKey
    ): RequestInterface {
        $sealed = Simple::seal(
            (string) $request->getBody(),
            $publicKey
        );
        return $request->withBody(
            stream_for(
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
    public static function sealResponse(
        ResponseInterface $response,
        SealingPublicKey $publicKey
    ): ResponseInterface {
        $sealed = Simple::seal(
            (string) $response->getBody(),
            $publicKey
        );
        return $response->withBody(
            stream_for(
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
    public static function signRequest(
        RequestInterface $request,
        SigningSecretKey $secretKey
    ): RequestInterface {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            (string) $request->getBody(),
            $secretKey->getString(true)
        );
        return $request->withAddedHeader(
            static::HEADER_SIGNATURE_NAME,
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
    public static function signResponse(
        ResponseInterface $response,
        SigningSecretKey $secretKey
    ): ResponseInterface {
        $signature = \ParagonIE_Sodium_Compat::crypto_sign_detached(
            (string) $response->getBody(),
            $secretKey->getString(true)
        );
        return $response->withAddedHeader(
            static::HEADER_SIGNATURE_NAME,
            Base64UrlSafe::encode($signature)
        );
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param RequestInterface $request
     * @param SealingSecretKey $secretKey
     * @return array
     */
    public static function unsealJsonRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            (string) static::unsealRequest($request, $secretKey)->getBody(),
            true
        );
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param ResponseInterface $response
     * @param SealingSecretKey $secretKey
     * @return array
     */
    public static function unsealJsonResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            (string) static::unsealResponse($response, $secretKey)->getBody(),
            true
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
    public static function unsealRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): RequestInterface {
        $body = Base64UrlSafe::decode((string) $request->getBody());
        $unsealed = Simple::unseal(
            $body,
            $secretKey
        );
        return $request->withBody(stream_for($unsealed));
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
    public static function unsealResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): ResponseInterface {
        $body = Base64UrlSafe::decode((string) $response->getBody());
        $unsealed = Simple::unseal(
            $body,
            $secretKey
        );
        return $response->withBody(stream_for($unsealed));
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
     */
    public static function verifySignedRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader(static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed request header (' . static::HEADER_SIGNATURE_NAME . ') found.'
            );
        }

        $body = (string) $request->getBody();
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
     */
    public static function verifySignedResponse(
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
     */
    public static function verifySymmetricAuthenticatedRequest(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): RequestInterface {
        /** @var array<int, string> */
        $headers = $request->getHeader(static::HEADER_AUTH_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed request header (' . static::HEADER_AUTH_NAME . ') found.'
            );
        }

        $body = (string) $request->getBody();
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
     */
    public static function verifySymmetricAuthenticatedResponse(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): ResponseInterface {
        /** @var array<int, string> */
        $headers = $response->getHeader(static::HEADER_SIGNATURE_NAME);
        if (!$headers) {
            throw new HeaderMissingException(
                'No signed response header (' . static::HEADER_SIGNATURE_NAME . ') found.'
            );
        }

        $body = (string) $response->getBody();
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
     * Magic method in case this is called in an object context.
     *
     * @param string $name
     * @param array $arguments
     * @return mixed
     * @throws \Error
     */
    public function __call($name, $arguments)
    {
        if (\is_callable([$name, $arguments])) {
            throw new \Error('Method not found: ' . $name);
        }
        return self::$name(...$arguments);
    }
}
