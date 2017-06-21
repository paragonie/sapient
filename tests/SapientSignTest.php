<?php
namespace ParagonIE\Sapient\UnitTests;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use function GuzzleHttp\Psr7\stream_for;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\CryptographyKeys\{
    SigningPublicKey,
    SigningSecretKey
};
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
     */
    public function setUp()
    {
        $this->sapient = new Sapient();

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
            $request = $this->sapient->createSignedJsonRequest(
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

            $invalid = $request->withBody(stream_for('invalid message'));
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
        $request = $this->sapient->createSignedRequest(
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

        $decoded = $this->sapient->decodeSignedRequest($request, $this->clientSignPublic);
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

        $invalid = $request->withBody(stream_for('invalid message'));

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
            $response = $this->sapient->createSignedJsonResponse(
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

            $invalid = $response->withBody(stream_for('invalid message'));
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

        $decoded = $this->sapient->decodeSignedResponse($response, $this->serverSignPublic);
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

        $invalid = $response->withBody(stream_for('invalid message'));
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
