<?php
declare(strict_types=1);

namespace ParagonIE\Sapient\Traits;

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
 * Trait JsonSugar
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
trait JsonSugar
{
    use StringSugar;

    /**
     * @param RequestInterface $request
     * @param SharedAuthenticationKey $key
     * @return array
     */
    public function decodeSymmetricAuthenticatedJsonRequest(
        RequestInterface $request,
        SharedAuthenticationKey $key
    ): array {
        return \json_decode(
            $this->verifySymmetricAuthenticatedStringRequest($request, $key),
            true
        );
    }

    /**
     * @param ResponseInterface $response
     * @param SharedAuthenticationKey $key
     * @return array
     */
    public function decodeSymmetricAuthenticatedJsonResponse(
        ResponseInterface $response,
        SharedAuthenticationKey $key
    ): array {
        return \json_decode(
            $this->verifySymmetricAuthenticatedStringResponse($response, $key),
            true
        );
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid JSON string).
     *
     * @param RequestInterface $request
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public function decodeSignedJsonRequest(
        RequestInterface $request,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            $this->verifySignedStringRequest($request, $publicKey),
            true
        );
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid JSON string).
     *
     * @param ResponseInterface $response
     * @param SigningPublicKey $publicKey
     * @return array
     */
    public function decodeSignedJsonResponse(
        ResponseInterface $response,
        SigningPublicKey $publicKey
    ): array {
        return \json_decode(
            $this->verifySignedStringResponse($response, $publicKey),
            true
        );
    }

    /**
     * Decrypt an HTTP request with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
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
     * Decrypt an HTTP response with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
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
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param RequestInterface $request
     * @param SealingSecretKey $secretKey
     * @return array
     */
    public function unsealJsonRequest(
        RequestInterface $request,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            $this->unsealStringRequest($request, $secretKey),
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
    public function unsealJsonResponse(
        ResponseInterface $response,
        SealingSecretKey $secretKey
    ): array {
        return \json_decode(
            $this->unsealStringResponse($response, $secretKey),
            true
        );
    }
}
