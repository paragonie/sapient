<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\Adapter\Guzzle;
use ParagonIE\Sapient\CryptographyKeys\{
    SigningPublicKey,
    SigningSecretKey
};
use ParagonIE\Sapient\Exception\HeaderMissingException;
use ParagonIE\Sapient\Exception\InvalidMessageException;
use ParagonIE\Sapient\Sapient;
use PHPUnit\Framework\TestCase;

/**
 * Class SapientTest
 * @package ParagonIE\Sapient\UnitTests
 */
class SapientSignTest extends TestCase
{
    /** @var Sapient */
    protected $sapient;

    /** @var SigningSecretKey */
    protected $clientSignSecret;

    /** @var SigningPublicKey */
    protected $clientSignPublic;

    /** @var SigningSecretKey */
    protected $serverSignSecret;

    /** @var SigningPublicKey */
    protected $serverSignPublic;

    /**
     * Setup the class properties
     * @before
     */
    public function before()
    {
        $this->sapient = new Sapient(new Guzzle());

        $this->clientSignSecret = SigningSecretKey::generate();
        $this->clientSignPublic = $this->clientSignSecret->getPublickey();

        $this->serverSignSecret = SigningSecretKey::generate();
        $this->serverSignPublic = $this->serverSignSecret->getPublickey();
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
            $request = $guzzle->createSignedJsonRequest(
                'POST',
                '/',
                $obj,
                $this->clientSignSecret
            );
            $valid = $this->sapient->verifySignedRequest(
                $request,
                $this->clientSignPublic
            );
            $this->assertInstanceOf(Request::class, $valid);
            $decoded = $this->sapient->decodeSignedJsonRequest($request, $this->clientSignPublic);
            $this->assertSame($obj, $decoded);

            /* We expect an exception: */
            try {
                $this->sapient->verifySignedRequest(
                    $request,
                    $this->serverSignPublic
                );
                $this->fail('Bad message signature');
            } catch (\Throwable $ex) {
            }

            $invalid = $request->withBody($this->sapient->stringToStream(('invalid message')));
            /* We expect an exception: */
            try {
                $this->sapient->verifySignedRequest(
                    $invalid,
                    $this->clientSignPublic
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
        $request = $guzzle->createSignedRequest(
            'POST',
            '/',
            $randomMessage,
            $this->clientSignSecret
        );
        $valid = $this->sapient->verifySignedRequest(
            $request,
            $this->clientSignPublic
        );
        $this->assertInstanceOf(Request::class, $valid);

        $decoded = $this->sapient->verifySignedStringRequest($request, $this->clientSignPublic);
        $this->assertSame($randomMessage, $decoded);

        /* Test bad public key */
        try {
            $this->sapient->verifySignedRequest(
                $request,
                $this->serverSignPublic
            );
            $this->fail('Bad message signature');
        } catch (\Throwable $ex) {
        }

        $invalid = $request->withBody($this->sapient->stringToStream('invalid message'));

        /* Test bad message */
        try {
            $this->sapient->verifySignedRequest(
                $invalid,
                $this->clientSignPublic
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
            $response = $guzzle->createSignedJsonResponse(
                200,
                $obj,
                $this->serverSignSecret
            );
            $valid = $this->sapient->verifySignedResponse($response, $this->serverSignPublic);
            $this->assertInstanceOf(Response::class, $valid);

            $decoded = $this->sapient->decodeSignedJsonResponse($response, $this->serverSignPublic);
            $this->assertSame($obj, $decoded);

            /* Test bad public key */
            try {
                $this->sapient->verifySignedResponse(
                    $valid,
                    $this->clientSignPublic
                );
                $this->fail('Bad message accepted');
            } catch (\Throwable $ex) {
            }

            $invalid = $response->withBody($this->sapient->stringToStream('invalid message'));
            /* Test bad message */
            try {
                $this->sapient->verifySignedResponse(
                    $invalid,
                    $this->serverSignPublic
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
    public function testSignedResponse()
    {
        $randomMessage = Base64UrlSafe::encode(
            \random_bytes(
                \random_int(101, 200)
            )
        );

        $response = $this->sapient->createSignedResponse(
            200,
            $randomMessage,
            $this->serverSignSecret
        );
        $valid = $this->sapient->verifySignedResponse($response, $this->serverSignPublic);
        $this->assertInstanceOf(Response::class, $valid);

        $decoded = $this->sapient->verifySignedStringResponse($response, $this->serverSignPublic);
        $this->assertSame($randomMessage, $decoded);

        /* Test bad public key */
        try {
            $this->sapient->verifySignedResponse(
                $valid,
                $this->clientSignPublic
            );
            $this->fail('Bad message accepted');
        } catch (\Throwable $ex) {
        }

        $invalid = $response->withBody($this->sapient->stringToStream('invalid message'));
        /* Test bad message */
        try {
            $this->sapient->verifySignedResponse(
                $invalid,
                $this->serverSignPublic
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
        $signedRequest = $this->sapient->signRequest($request, $this->clientSignSecret);
        try {
            $verified = $this->sapient->verifySignedRequest(
                $signedRequest,
                $this->clientSignPublic
            );
            $this->assertSame(
                $randomMessage,
                (string) $verified->getBody()
            );
            $this->assertNotEmpty(
                $verified->getHeader(Sapient::HEADER_SIGNATURE_NAME)
            );
        } catch (HeaderMissingException $exception) {
            $this->fail('No header added');
        } catch (InvalidMessageException $exception) {
            $this->fail('Invalid signature');
        }

        $response = new Response(200, [], $randomMessage);
        $signedResponse = $this->sapient->signResponse($response, $this->serverSignSecret);
        try {
            $verified = $this->sapient->verifySignedResponse(
                $signedResponse,
                $this->serverSignPublic
            );
            $this->assertSame(
                $randomMessage,
                (string) $verified->getBody()
            );
            $this->assertNotEmpty(
                $verified->getHeader(Sapient::HEADER_SIGNATURE_NAME)
            );
        } catch (HeaderMissingException $exception) {
            $this->fail('No header added');
        } catch (InvalidMessageException $exception) {
            $this->fail('Invalid signature');
        }
    }
}
