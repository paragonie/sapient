<?php
namespace ParagonIE\Sapient\UnitTests;

use ParagonIE\Sapient\CryptographyKeys\SharedEncryptionKey;
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
}
