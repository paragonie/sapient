<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\CryptographyKeys;

use ParagonIE\Sapient\CryptographyKey;

/**
 * Class SealingSecretKey
 * @package ParagonIE\Sapient
 */
class SealingSecretKey extends CryptographyKey
{
    /**
     * SealingSecretKey constructor.
     * @param string $key
     * @throws \RangeException
     */
    public function __construct(string $key)
    {
        if (\ParagonIE_Sodium_Core_Util::strlen($key) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new \RangeException('Key is not the correct size');
        }
        $this->key = $key;
    }

    /**
     * @return string
     */
    public function getStringForSealOpen(): string
    {
        $publicKey = $this->getPublickey();
        return \ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
            $this->getString(true),
            $publicKey->getString(true)
        );
    }

    /**
     * @param SealingPublicKey $publicKey
     * @param bool $serverSide
     * @return SharedEncryptionKey
     */
    public function deriveSharedEncryptionkey(
        SealingPublicKey $publicKey,
        bool $serverSide = false
    ): SharedEncryptionKey {
        if ($serverSide) {
            // You are the server:
            $shared = \ParagonIE_Sodium_Compat::crypto_kx(
                $this->getString(true),
                $publicKey->getString(true),
                $publicKey->getString(true),
                $this->getPublickey()->getString(true),
                true
            );
        } else {
            // You are the client:
            $shared = \ParagonIE_Sodium_Compat::crypto_kx(
                $this->getString(true),
                $publicKey->getString(true),
                $this->getPublickey()->getString(true),
                $publicKey->getString(true),
                true
            );
        }
        return new SharedEncryptionKey($shared);
    }

    /**
     * @return SealingSecretKey
     */
    public static function generate(): SealingSecretKey
    {
        $keypair = \ParagonIE_Sodium_Compat::crypto_box_keypair();
        return new SealingSecretKey(
            \ParagonIE_Sodium_Compat::crypto_box_secretkey($keypair)
        );
    }

    /**
     * @return SealingPublicKey
     */
    public function getPublicKey(): SealingPublicKey
    {
        return new SealingPublicKey(
            \ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($this->key)
        );
    }
}
