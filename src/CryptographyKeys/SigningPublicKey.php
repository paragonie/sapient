<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\CryptographyKeys;

use ParagonIE\Sapient\CryptographyKey;

/**
 * Class SigningPublicKey
 * @package ParagonIE\Sapient
 */
class SigningPublicKey extends CryptographyKey
{
    /**
     * SigningPublicKey constructor.
     * @param string $key
     * @throws \RangeException
     */
    public function __construct(string $key)
    {
        if (\ParagonIE_Sodium_Core_Util::strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \RangeException('Key is not the correct size');
        }
        $this->key = $key;
    }
}
