<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle;
use ParagonIE\Sapient\Exception\InvalidMessageException;
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
    /** @var Sapient */
    protected $sapient;

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
     * @before
     */
    public function before()
    {
        $this->sapient = new Sapient(new Guzzle());
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
            $request = $this->sapient->createSymmetricEncryptedJsonRequest(
                'POST',
                '/test/api-endpoint',
                $obj,
                $this->sharedEncryptionKey
            );
            $decrypted = $this->sapient->decryptJsonRequestWithSharedKey(
                $request,
                $this->sharedEncryptionKey
            );
            $this->assertSame($obj, $decrypted);

            try {
                $this->sapient->decryptJsonRequestWithSharedKey(
                    $request,
                    SharedEncryptionKey::generate()
                );
                $this->fail('Decryption permitted under invalid key');
            } catch (InvalidMessageException $ex) {
                // Expected outcome
            } catch (\SodiumException $ex) {
                // Expected outcome
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
        $decrypted = $this->sapient->decryptRequestWithSharedKey(
            $request,
            $this->sharedEncryptionKey
        );
        $this->assertInstanceOf(Request::class, $decrypted);

        $decryptedBody = (string) $decrypted->getBody();
        $this->assertSame($randomMessage, $decryptedBody);

        try {
            $this->sapient->decryptRequestWithSharedKey(
                $request,
                SharedEncryptionKey::generate()
            );
            $this->fail('Decryption permitted under invalid key');
        } catch (InvalidMessageException $ex) {
            // Expected outcome
        } catch (\SodiumException $ex) {
            // Expected outcome
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
            $decrypted = $this->sapient->decryptJsonResponseWithSharedKey(
                $Response,
                $this->sharedEncryptionKey
            );
            $this->assertSame($obj, $decrypted);

            try {
                $this->sapient->decryptJsonResponseWithSharedKey(
                    $Response,
                    SharedEncryptionKey::generate()
                );
                $this->fail('Decryption permitted under invalid key');
            } catch (InvalidMessageException $ex) {
                // Expected outcome
            } catch (\SodiumException $ex) {
                // Expected outcome
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
        $decrypted = $this->sapient->decryptResponseWithSharedKey(
            $response,
            $this->sharedEncryptionKey
        );
        $this->assertInstanceOf(Response::class, $decrypted);

        $decryptedBody = (string) $decrypted->getBody();
        $this->assertSame($randomMessage, $decryptedBody);

        try {
            $this->sapient->decryptResponseWithSharedKey(
                $response,
                SharedEncryptionKey::generate()
            );
            $this->fail('Decryption permitted under invalid key');
        } catch (InvalidMessageException $ex) {
            // Expected outcome
        } catch (\SodiumException $ex) {
            // Expected outcome
        } catch (\Error $ex) {
            // Expected outcome
        }
    }
}
