<?php
namespace ParagonIE\Sapient\UnitTests;

use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Sapient\Sapient;
use PHPUnit\Framework\TestCase;

/**
 * Class SapientTest
 * @package ParagonIE\Sapient\UnitTests
 */
class KeyExchangeTest extends TestCase
{
    /** @var Sapient */
    protected $sapient;

    /** @var SealingSecretKey */
    protected $clientSealSecret;

    /** @var SealingPublicKey */
    protected $clientSealPublic;

    /** @var SealingSecretKey */
    protected $serverSealSecret;

    /** @var SealingPublicKey */
    protected $serverSealPublic;

    /**
     * Setup the class properties
     */
    public function setUp()
    {
        $this->sapient = new Sapient();

        $this->clientSealSecret = SealingSecretKey::generate();
        $this->clientSealPublic = $this->clientSealSecret->getPublickey();

        $this->serverSealSecret = SealingSecretKey::generate();
        $this->serverSealPublic = $this->serverSealSecret->getPublickey();
    }

    /**
     * @covers SealingSecretKey::deriveSharedEncryptionkey()
     */
    public function testKeyExchange()
    {
        $clientShared = $this->clientSealSecret->deriveSharedEncryptionkey($this->serverSealPublic, false);
        $serverShared = $this->serverSealSecret->deriveSharedEncryptionkey($this->clientSealPublic, true);

        $this->assertSame(
            $clientShared->getString(),
            $serverShared->getString()
        );
    }
}
