<?php
namespace ParagonIE\Sapient\UnitTests;

use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey,
    SharedEncryptionKey
};
use ParagonIE\Sapient\Simple;
use PHPUnit\Framework\TestCase;

class SimpleTest extends TestCase
{
    /**
     * @covers Simple::encrypt()
     * @covers Simple::decrypt()
     */
    public function testEncryptAndDecrypt()
    {
        $key = SharedEncryptionKey::generate();
        $prev = '';
        $messages = ['', '', 'Hello, this is a unit test', 'Paragon Initiative Enterprises, LLC'];
        foreach ($messages as $message) {
            $encrypted = Simple::encrypt($message, $key);
            $this->assertNotSame($prev, $encrypted, 'Same message twice');
            $this->assertSame(
                40 + \ParagonIE_Sodium_Core_Util::strlen($message),
                \ParagonIE_Sodium_Core_Util::strlen($encrypted),
                'Ciphertext output is too short'
            );
            $this->assertSame(
                $message,
                Simple::decrypt($encrypted, $key),
                'Incorrect plaintext'
            );
            $prev = $encrypted;
        }
    }

    /**
     * @covers Simple::keyExchange()
     */
    public function testKeyExchange()
    {
        $clientSealSecret = SealingSecretKey::generate();
        $clientSealPublic = $clientSealSecret->getPublickey();
        $serverSealSecret = SealingSecretKey::generate();
        $serverSealPublic = $serverSealSecret->getPublickey();

        $left = Simple::keyExchange($clientSealSecret, $serverSealPublic, false);
        $right = Simple::keyExchange($serverSealSecret, $clientSealPublic, true);
        $this->assertSame($left, $right);

        $left = Simple::keyExchange($clientSealSecret, $serverSealPublic, false, 56);
        $right = Simple::keyExchange($serverSealSecret, $clientSealPublic, true, 56);
        $this->assertSame($left, $right);
        $this->assertSame(56, \ParagonIE_Sodium_Core_Util::strlen($left));
        $this->assertSame(56, \ParagonIE_Sodium_Core_Util::strlen($right));
    }

    /**
     * @covers Simple::seal()
     * @covers Simple::unseal()
     */
    public function testSealUnseal()
    {
        $sealSecret = SealingSecretKey::generate();
        /** @var SealingPublicKey $sealPublic */
        $sealPublic = $sealSecret->getPublickey();

        $messages = [
            '',
            '',
            'Hello, this is a unit test',
            'Paragon Initiative Enterprises, LLC',
            \random_bytes(\random_int(101, 1000))
        ];
        foreach ($messages as $message) {
            $sealed = Simple::seal($message, $sealPublic);
            $this->assertSame(
                48 + \ParagonIE_Sodium_Core_Util::strlen($message),
                \ParagonIE_Sodium_Core_Util::strlen($sealed),
                'Ciphertext output is too short'
            );
            $this->assertSame(
                $message,
                Simple::unseal($sealed, $sealSecret),
                'Incorrect plaintext'
            );
        }
    }
}
