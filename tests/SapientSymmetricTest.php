<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle;
use ParagonIE\Sapient\CryptographyKeys\{
    SharedAuthenticationKey,
    SharedEncryptionKey
};
use ParagonIE\Sapient\Sapient;
use PHPUnit\Framework\TestCase;

/**
 * Class SapientTest
 * @package ParagonIE\Sapient\UnitTests
 */
class SapientSymmetricTest extends TestCase
{
    /** @var SharedAuthenticationKey */
    protected $sharedAuthenticationKey;

    /** @var SharedEncryptionKey */
    protected $sharedEncryptionKey;

    private function getSampleObjects(): array
    {
        return [
            [],
            ['test' => 'abcdefg'],
            ['random' => Base64UrlSafe::encode(
                \random_bytes(
                    \random_int(1, 100)
                )
            )
            ],
            ['structued' => [
                'abc' => 'def',
                'o' => null,
                'ghi' => ['j', 'k', 'l'],
                'm' => 1234,
                'n' => 56.78,
                'p' => ['q' => ['r' => []]]
            ]]
        ];
    }

    /**
     * Setup the class properties
     */
    public function setUp()
    {
        $this->sharedEncryptionKey = SharedEncryptionKey::generate();
        $this->sharedAuthenticationKey = SharedAuthenticationKey::generate();
    }

    /**
     * @covers Sapient::createSymmetricEncryptedJsonRequest()
     * @covers Sapient::decryptJsonRequestWithSharedKey()
     */
    public function testEncryptDecryptJsonRequest()
    {
        foreach ($this->getSampleObjects() as $obj) {
            $guzzle = new Guzzle();
            $request = $guzzle->createSymmetricEncryptedJsonRequest(
                'POST',
                '/test/api-endpoint',
                $obj,
                $this->sharedEncryptionKey
            );
            $decrypted = Sapient::decryptJsonRequestWithSharedKey(
                $request,
                $this->sharedEncryptionKey
            );
            $this->assertSame($obj, $decrypted);

            try {
                Sapient::decryptJsonRequestWithSharedKey(
                    $request,
                    SharedEncryptionKey::generate()
                );
                $this->fail('Decryption permitted under invalid key');
            } catch (\Error $ex) {
                // Expected outcome
            }
        }
    }


    /**
     * @covers Sapient::createSymmetricEncryptedJsonRequest()
     * @covers Sapient::decryptJsonRequestWithSharedKey()
     */
    public function testEncryptDecryptRequest()
    {
        $randomMessage = random_bytes(random_int(101, 200));

        $guzzle = new Guzzle();
        $request = $guzzle->createSymmetricEncryptedRequest(
            'POST',
            '/test/api-endpoint',
            $randomMessage,
            $this->sharedEncryptionKey
        );
        $decrypted = Sapient::decryptRequestWithSharedKey(
            $request,
            $this->sharedEncryptionKey
        );
        $this->assertInstanceOf(Request::class, $decrypted);

        $decryptedBody = (string) $decrypted->getBody();
        $this->assertSame($randomMessage, $decryptedBody);

        try {
            Sapient::decryptRequestWithSharedKey(
                $request,
                SharedEncryptionKey::generate()
            );
            $this->fail('Decryption permitted under invalid key');
        } catch (\Error $ex) {
            // Expected outcome
        }
    }

    /**
     * @covers Sapient::createSymmetricEncryptedJsonResponse()
     * @covers Sapient::decryptJsonResponseWithSharedKey()
     */
    public function testEncryptDecryptJsonResponse()
    {
        foreach ($this->getSampleObjects() as $obj) {
            $guzzle = new Guzzle();
            $Response = $guzzle->createSymmetricEncryptedJsonResponse(
                200,
                $obj,
                $this->sharedEncryptionKey
            );
            $decrypted = Sapient::decryptJsonResponseWithSharedKey(
                $Response,
                $this->sharedEncryptionKey
            );
            $this->assertSame($obj, $decrypted);

            try {
                Sapient::decryptJsonResponseWithSharedKey(
                    $Response,
                    SharedEncryptionKey::generate()
                );
                $this->fail('Decryption permitted under invalid key');
            } catch (\Error $ex) {
                // Expected outcome
            }
        }
    }


    /**
     * @covers Sapient::createSymmetricEncryptedJsonResponse()
     * @covers Sapient::decryptJsonResponseWithSharedKey()
     */
    public function testEncryptDecryptResponse()
    {
        $randomMessage = random_bytes(random_int(101, 200));

        $guzzle = new Guzzle();
        $response = $guzzle->createSymmetricEncryptedResponse(
            200,
            $randomMessage,
            $this->sharedEncryptionKey
        );
        $decrypted = Sapient::decryptResponseWithSharedKey(
            $response,
            $this->sharedEncryptionKey
        );
        $this->assertInstanceOf(Response::class, $decrypted);

        $decryptedBody = (string) $decrypted->getBody();
        $this->assertSame($randomMessage, $decryptedBody);

        try {
            Sapient::decryptResponseWithSharedKey(
                $response,
                SharedEncryptionKey::generate()
            );
            $this->fail('Decryption permitted under invalid key');
        } catch (\Error $ex) {
            // Expected outcome
        }
    }
}
