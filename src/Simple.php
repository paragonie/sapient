<?php
declare(strict_types=1);
namespace ParagonIE\Sapient;

use ParagonIE\Sapient\CryptographyKeys\SharedEncryptionKey;
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
}
