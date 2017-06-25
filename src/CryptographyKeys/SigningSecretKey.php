<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\CryptographyKeys;

use ParagonIE\Sapient\CryptographyKey;

/**
 * Class SigningSecretKey
 * @package ParagonIE\Sapient
 */
class SigningSecretKey extends CryptographyKey
{
    /**
     * SigningSecretKey constructor.
     * @param string $key
     * @throws \RangeException
     */
    public function __construct(string $key)
    {
        if (\ParagonIE_Sodium_Core_Util::strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RangeException('Key is not the correct size');
        }
        $this->key = $key;
    }

    /**
     * @return SigningSecretKey
     */
    public static function generate(): SigningSecretKey
    {
        $keypair = \ParagonIE_Sodium_Compat::crypto_sign_keypair();
        return new SigningSecretKey(
            \ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair)
        );
    }

    /**
     * @return SigningPublicKey
     */
    public function getPublicKey(): SigningPublicKey
    {
        return new SigningPublicKey(
            \ParagonIE_Sodium_Compat::crypto_sign_publickey_from_secretkey($this->key)
        );
    }
}
