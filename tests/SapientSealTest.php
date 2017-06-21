<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use function GuzzleHttp\Psr7\stream_for;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\CryptographyKeys\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Sapient\Exception\InvalidMessageException;
use ParagonIE\Sapient\Sapient;
use PHPUnit\Framework\TestCase;

/**
 * Class SapientTest
 * @package ParagonIE\Sapient\UnitTests
 */
class SapientSealTest extends TestCase
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
     * @covers Sapient::createSignedJsonRequest()
     * @covers Sapient::verifySignedRequest()
     */
    public function testSignedJsonRequest()
    {
        $sampleObjects = $this->getSampleObjects();

        foreach ($sampleObjects as $obj) {
            $request = $this->sapient->createSealedJsonRequest(
                'POST',
                '/',
                $obj,
                $this->clientSealPublic
            );
            $decoded = $this->sapient->unsealJsonRequest(
                $request,
                $this->clientSealSecret
            );
            $this->assertSame($obj, $decoded);

            /* We expect an exception: */
            try {
                $this->sapient->unsealJsonRequest(
                    $request,
                    $this->serverSealSecret
                );
                $this->fail('Bad message signature');
            } catch (\Throwable $ex) {
                $this->assertInstanceOf(InvalidMessageException::class, $ex);
            }

            $invalid = $request->withBody(stream_for(
                Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
            ));
            /* We expect an exception: */
            try {
                $this->sapient->unsealJsonRequest(
                    $invalid,
                    $this->clientSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
                $this->assertInstanceOf(InvalidMessageException::class, $ex);
            }
        }
    }

    /**
     * @covers Sapient::createSignedRequest()
     * @covers Sapient::verifySignedRequest()
     */
    public function testSignedRequest()
    {
        $randomMessage = Base64UrlSafe::encode(
            \random_bytes(
                \random_int(101, 200)
            )
        );
        $request = $this->sapient->createSealedRequest(
            'POST',
            '/',
            $randomMessage,
            $this->clientSealPublic
        );
        $decoded = $this->sapient->unsealRequest(
            $request,
            $this->clientSealSecret
        );
        $this->assertInstanceOf(Request::class, $decoded);
        $this->assertSame($randomMessage, (string) $decoded->getBody());

        /* Test bad public key */
        try {
            $this->sapient->unsealRequest(
                $request,
                $this->serverSealSecret
            );
            $this->fail('Bad message signature');
        } catch (\Throwable $ex) {
            $this->assertInstanceOf(InvalidMessageException::class, $ex);
            var_dump($ex->getMessage());
        }

        $invalid = $request->withBody(stream_for(
            Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
        ));

        /* Test bad message */
        try {
            $this->sapient->unsealRequest(
                $invalid,
                $this->serverSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
            $this->assertInstanceOf(InvalidMessageException::class, $ex);
        }
    }
    /**
     * @covers Sapient::createSignedJsonResponse()
     * @covers Sapient::verifySignedResponse()
     */
    public function testSignedJsonResponse()
    {
        $sampleObjects = $this->getSampleObjects();

        foreach ($sampleObjects as $obj) {
            $response = $this->sapient->createSealedJsonResponse(
                200,
                $obj,
                $this->serverSealPublic
            );
            $responseRaw = $this->sapient->unsealResponse(
                $response,
                $this->serverSealSecret
            );
            $this->assertInstanceOf(Response::class, $responseRaw);

            $decoded = $this->sapient->unsealJsonResponse($response, $this->serverSealSecret);
            $this->assertSame($obj, $decoded);

            /* Test bad public key */
            try {
                $this->sapient->unsealResponse(
                    $response,
                    $this->clientSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
                $this->assertInstanceOf(InvalidMessageException::class, $ex);
            }

            $invalid = $response->withBody(stream_for(
                Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
            ));
            /* Test bad message */
            try {
                $this->sapient->unsealResponse(
                    $invalid,
                    $this->serverSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
                $this->assertInstanceOf(InvalidMessageException::class, $ex);
            }
        }
    }

    /**
     * @covers Sapient::createSignedResponse()
     * @covers Sapient::verifySignedResponse()
     */
    public function testSignedResponse()
    {
        $randomMessage = Base64UrlSafe::encode(
            \random_bytes(
                \random_int(101, 200)
            )
        );
        $response = $this->sapient->createSealedResponse(
            200,
            $randomMessage,
            $this->serverSealPublic
        );
        $responseRaw = $this->sapient->unsealResponse(
            $response,
            $this->serverSealSecret
        );
        $this->assertInstanceOf(Response::class, $responseRaw);

        $decoded = $this->sapient->unsealResponse($response, $this->serverSealSecret);
        $this->assertSame($randomMessage, (string) $decoded->getBody());

        /* Test bad public key */
        try {
            $this->sapient->unsealResponse(
                $response,
                $this->clientSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
            $this->assertInstanceOf(InvalidMessageException::class, $ex);
        }

        $invalid = $response->withBody(stream_for(
            Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
        ));
        /* Test bad message */
        try {
            $this->sapient->unsealResponse(
                $invalid,
                $this->serverSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
            $this->assertInstanceOf(InvalidMessageException::class, $ex);
        }
    }
}