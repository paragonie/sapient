<?php
declare(strict_types=1);
namespace ParagonIE\Sapient;

use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey,
    SharedEncryptionKey
};
use ParagonIE\Sapient\Exception\InvalidMessageException;

/**
 * Class Simple
 * @package ParagonIE\Sapient
 */
abstract class Simple
{
    /**
     * Simple authenticated encryption
     * XChaCha20-Poly1305
     *
     * @param string $plaintext
     * @param SharedEncryptionKey $key
     * @return string
     */
    public static function encrypt(
        string $plaintext,
        SharedEncryptionKey $key
    ): string {
        $nonce = random_bytes(\ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        return $nonce .
            \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                $nonce,
                $nonce,
                $key->getString(true)
            );
    }

    /**
     * Simple authenticated decryption
     * XChaCha20-Poly1305
     *
     * @param string $ciphertext
     * @param SharedEncryptionKey $key
     * @return string
     * @throws InvalidMessageException
     */
    public static function decrypt(
        string $ciphertext,
        SharedEncryptionKey $key
    ): string {
        $nonce = \ParagonIE_Sodium_Core_Util::substr($ciphertext, 0, 24);
        $result = \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            \ParagonIE_Sodium_Core_Util::substr($ciphertext, 24),
            $nonce,
            $nonce,
            $key->getString(true)
        );
        if (!\is_string($result)) {
            throw new InvalidMessageException('Message authentication failed.');
        }
        return $result;
    }

    /**
     * Like libsodium's crypto_kx() but supports an arbitrary output length
     * in the range (16 <= N <= 64).
     *
     * @param SealingSecretKey $secretKey
     * @param SealingPublicKey $publicKey
     * @param bool $serverSide
     * @param int $outputLength
     * @return string
     */
    public static function keyExchange(
        SealingSecretKey $secretKey,
        SealingPublicKey $publicKey,
        bool $serverSide,
        int $outputLength = 32
    ): string {
        if ($serverSide) {
            $suffix = $publicKey->getString(true) .
                $secretKey->getPublickey()->getString(true);
        } else {
            $suffix = $secretKey->getPublickey()->getString(true) .
                $publicKey->getString(true);
        }
        return \ParagonIE_Sodium_Compat::crypto_generichash(
            \ParagonIE_Sodium_Compat::crypto_scalarmult(
                $secretKey->getString(true),
                $publicKey->getString(true)
            ) . $suffix,
            '',
            $outputLength
        );
    }

    /**
     * Encrypt a message with a public key, so that it can only be decrypted
     * with the corresponding secret key.
     *
     * @param string $plaintext
     * @param SealingPublicKey $publicKey
     * @return string
     */
    public static function seal(
        string $plaintext,
        SealingPublicKey $publicKey
    ): string {
        $ephemeralSecret = SealingSecretKey::generate();
        $sharedSecret = static::keyExchange(
            $ephemeralSecret,
            $publicKey,
            false,
            56
        );
        $ephemeralPublicKey = $ephemeralSecret->getPublickey()->getString(true);
        $sharedKey = \ParagonIE_Sodium_Core_Util::substr($sharedSecret, 0, 32);
        $nonce = \ParagonIE_Sodium_Core_Util::substr($sharedSecret, 32, 24);
        try {
            \ParagonIE_Sodium_Compat::memzero($sharedSecret);
        } catch (\Throwable $ex) {
        }

        return $ephemeralPublicKey. \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $ephemeralPublicKey,
            $nonce,
            $sharedKey
        );
    }

    /**
     * Decrypt a message with your secret key.
     *
     * @param string $ciphertext
     * @param SealingSecretKey $secretKey
     * @return string
     * @throws InvalidMessageException
     */
    public static function unseal(
        string $ciphertext,
        SealingSecretKey $secretKey
    ): string {
        $ephemeralPublicKey = \ParagonIE_Sodium_Core_Util::substr($ciphertext, 0, 32);

        $sharedSecret = static::keyExchange(
            $secretKey,
            new SealingPublicKey($ephemeralPublicKey),
            true,
            56
        );
        $sharedKey = \ParagonIE_Sodium_Core_Util::substr($sharedSecret, 0, 32);
        $nonce = \ParagonIE_Sodium_Core_Util::substr($sharedSecret, 32, 24);
        try {
            \ParagonIE_Sodium_Compat::memzero($sharedSecret);
        } catch (\Throwable $ex) {
        }

        $plaintext = \ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            \ParagonIE_Sodium_Core_Util::substr($ciphertext, 32),
            $ephemeralPublicKey,
            $nonce,
            $sharedKey
        );
        if (!\is_string($plaintext)) {
            throw new InvalidMessageException('Incorrect message authentication tag');
        }
        return $plaintext;
    }
}
