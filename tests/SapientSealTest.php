<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use function GuzzleHttp\Psr7\stream_for;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle;
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
            $guzzle = new Guzzle();
            $request = $guzzle->createSealedJsonRequest(
                'POST',
                '/',
                $obj,
                $this->clientSealPublic
            );
            $decoded = Sapient::unsealJsonRequest(
                $request,
                $this->clientSealSecret
            );
            $this->assertSame($obj, $decoded);

            /* We expect an exception: */
            try {
                Sapient::unsealJsonRequest(
                    $request,
                    $this->serverSealSecret
                );
                $this->fail('Bad message signature');
            } catch (\Throwable $ex) {
            }

            $invalid = $request->withBody(stream_for(
                Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
            ));
            /* We expect an exception: */
            try {
                Sapient::unsealJsonRequest(
                    $invalid,
                    $this->clientSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
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
        $guzzle = new Guzzle();
        $request = $guzzle->createSealedRequest(
            'POST',
            '/',
            $randomMessage,
            $this->clientSealPublic
        );
        $decoded = Sapient::unsealRequest(
            $request,
            $this->clientSealSecret
        );
        $this->assertInstanceOf(Request::class, $decoded);
        $this->assertSame($randomMessage, (string) $decoded->getBody());

        /* Test bad public key */
        try {
            Sapient::unsealRequest(
                $request,
                $this->serverSealSecret
            );
            $this->fail('Bad message signature');
        } catch (\Throwable $ex) {
        }

        $invalid = $request->withBody(stream_for(
            Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
        ));

        /* Test bad message */
        try {
            Sapient::unsealRequest(
                $invalid,
                $this->serverSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
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
            $guzzle = new Guzzle();
            $response = $guzzle->createSealedJsonResponse(
                200,
                $obj,
                $this->serverSealPublic
            );
            $responseRaw = Sapient::unsealResponse(
                $response,
                $this->serverSealSecret
            );
            $this->assertInstanceOf(Response::class, $responseRaw);

            $decoded = Sapient::unsealJsonResponse($response, $this->serverSealSecret);
            $this->assertSame($obj, $decoded);

            /* Test bad public key */
            try {
                Sapient::unsealResponse(
                    $response,
                    $this->clientSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
            }

            $invalid = $response->withBody(stream_for(
                Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
            ));
            /* Test bad message */
            try {
                Sapient::unsealResponse(
                    $invalid,
                    $this->serverSealSecret
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
            }
        }
    }

    /**
     * @covers Sapient::createSignedResponse()
     * @covers Sapient::verifySignedResponse()
     */
    public function testSealedResponse()
    {
        $randomMessage = Base64UrlSafe::encode(
            \random_bytes(
                \random_int(101, 200)
            )
        );
        $guzzle = new Guzzle();
        $response = $guzzle->createSealedResponse(
            200,
            $randomMessage,
            $this->serverSealPublic
        );
        $responseRaw = Sapient::unsealResponse(
            $response,
            $this->serverSealSecret
        );
        $this->assertInstanceOf(Response::class, $responseRaw);

        $decoded = Sapient::unsealResponse($response, $this->serverSealSecret);
        $this->assertSame($randomMessage, (string) $decoded->getBody());

        /* Test bad public key */
        try {
            Sapient::unsealResponse(
                $response,
                $this->clientSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
        }

        $invalid = $response->withBody(stream_for(
            Base64UrlSafe::encode('invalid message goes here for verifying the failure of crypto_box_seal')
        ));
        /* Test bad message */
        try {
            Sapient::unsealResponse(
                $invalid,
                $this->serverSealSecret
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
        }
    }

    /**
     * @covers Sapient::signRequest()
     * @covers Sapient::signResponse()
     */
    public function testPsr7()
    {
        $randomMessage = Base64UrlSafe::encode(
            \random_bytes(
                \random_int(101, 200)
            )
        );

        $request = new Request('POST', '/test', [], $randomMessage);
        $signedRequest = Sapient::sealRequest($request, $this->clientSealPublic);
        try {
            $unsealed = Sapient::unsealRequest(
                $signedRequest,
                $this->clientSealSecret
            );
            $this->assertSame(
                $randomMessage,
                (string) $unsealed->getBody()
            );
        } catch (\Throwable $ex) {
            $this->fail('Error decrypting message');
        }

        $response = new Response(200, [], $randomMessage);
        $signedResponse = Sapient::sealResponse($response, $this->clientSealPublic);
        try {
            $unsealed = Sapient::unsealResponse(
                $signedResponse,
                $this->clientSealSecret
            );
            $this->assertSame(
                $randomMessage,
                (string) $unsealed->getBody()
            );
        } catch (\Throwable $ex) {
            $this->fail('Error decrypting message');
        }
    }
}