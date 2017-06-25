<?php
declare(strict_types=1);

namespace ParagonIE\Sapient\Traits;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningPublicKey,
    SigningSecretKey
};
use ParagonIE\Sapient\Exception\InvalidMessageException;
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface
};
use ParagonIE\Sapient\Simple;

/**
 * Trait StringSugar
 * @package ParagonIE\Sapient
 *
 * @method RequestInterface authenticateRequestWithSharedKey(RequestInterface $request, SharedAuthenticationKey $key)
 * @method ResponseInterface authenticateResponseWithSharedKey(ResponseInterface $response, SharedAuthenticationKey $key)
 * @method RequestInterface decryptRequestWithSharedKey(RequestInterface $request, SharedEncryptionKey $key)
 * @method ResponseInterface decryptResponseWithSharedKey(ResponseInterface $response, SharedEncryptionKey $key)
 * @method RequestInterface encryptRequestWithSharedKey(RequestInterface $request, SharedEncryptionKey $key)
 * @method ResponseInterface encryptResponseWithSharedKey(ResponseInterface $response, SharedEncryptionKey $key)
 * @method RequestInterface sealRequest(RequestInterface $request, SealingPublicKey $publicKey)
 * @method ResponseInterface sealResponse(ResponseInterface $response, SealingPublicKey $publicKey)
 * @method RequestInterface signRequest(RequestInterface $request, SigningSecretKey $secretKey)
 * @method ResponseInterface signResponse(ResponseInterface $response, SigningSecretKey $secretKey)
 * @method RequestInterface unsealRequest(RequestInterface $request, SealingSecretKey $secretKey)
 * @method ResponseInterface unsealResponse(ResponseInterface $response, SealingSecretKey $secretKey)
 * @method RequestInterface verifySignedRequest(RequestInterface $request, SigningPublicKey $publicKey)
 * @method ResponseInterface verifySignedResponse(ResponseInterface $response, SigningPublicKey $publicKey)
 * @method RequestInterface verifySymmetricAuthenticatedRequest(RequestInterface $response, SharedAuthenticationKey $key)
 * @method ResponseInterface verifySymmetricAuthenticatedResponse(ResponseInterface $response, SharedAuthenticationKey $key)
 */
trait StringSugar
{
    /**
     * Decrypt an HTTP request with a pre-shared key, then get the body as a
     * string.
     *
     * @param RequestInterface $request
     * @param SharedEncryptionKey $key
     * @return string
     */
    public function decryptStringRequestWithSharedKey(
        RequestInterface $request,
        SharedEncryptionKey $key
    ): string {
        return Simple::decrypt(
            (string) $request->getBody(),
            $key
        );
    }

    /**
     * Decrypt an HTTP response with a pre-shared key, then get the body as a
     * string.
     *
     * @param ResponseInterface $response
     * @param SharedEncryptionKey $key
     * @return string
     */
    public function decryptStringResponseWithSharedKey(
        ResponseInterface $response,
        SharedEncryptionKey $key
    ): string {
        return Simple::decrypt(
            (string) $response->getBody(),
            $key
        );
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then get the body as a string.
     *
     * @param RequestInterface $request
     * @param SealingSecretKey $secretKey
     * @return string
     * @throws InvalidMessageException
     */
    public function unsealStringRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): string {
        $body = Base64UrlSafe::decode((string) $request->getBody());
        return Simple::unseal(
            $body,
            $secretKey
        );
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then get the body as a string.
     *
     * @param ResponseInterface $response
     * @param SealingSecretKey $secretKey
     * @return string
     * @throws InvalidMessageException
     */
    public function unsealStringResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): string {
        $body = Base64UrlSafe::decode((string) $response->getBody());
        return Simple::unseal(
            $body,
            $secretKey
        );
    }

    /**
     * Verify the Body-HMAC-SHA512256 header, and then return the body as
     * a string.
     *
     * @param RequestInterface $request
     * @param SharedAuthenticationKey $key
     * @return string
     */
    public function verifySymmetricAuthenticatedStringRequest(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): string {
        $verified = $this->verifySymmetricAuthenticatedRequest($request, $key);
        return (string) $verified->getBody();
    }

    /**
     * Verify the Body-HMAC-SHA512256 header, and then return the body as
     * a string.
     *
     * @param ResponseInterface $response
     * @param SharedAuthenticationKey $key
     * @return string
     */
    public function verifySymmetricAuthenticatedStringResponse(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): string {
        $verified = $this->verifySymmetricAuthenticatedResponse($response, $key);
        return (string) $verified->getBody();
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then return the body as
     * a string.
     *
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public function verifySignedStringRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): string {
        $verified = $this->verifySignedRequest($request, $publicKey);
        return (string) $verified->getBody();
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then return the body as
     * a string.
     *
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return string
     */
    public function verifySignedStringResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): string {
        $verified = $this->verifySignedResponse($response, $publicKey);
        return (string) $verified->getBody();
    }
}
