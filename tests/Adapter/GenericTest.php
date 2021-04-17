<?php
namespace ParagonIE\Sapient\UnitTests\Adapter;

use ParagonIE\Sapient\Adapter\Generic\Adapter;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class GenericTest extends TestCase
{
    /** @var Adapter */
    protected $adapter;
    /**
     * Populate the methods.
     * @before
     */
    public function before()
    {
        $this->adapter = new Adapter();
    }

    /**
     * @covers Guzzle::stringToStream()
     */
    public function testStringToStream()
    {
        $this->assertInstanceOf(StreamInterface::class, $this->adapter->stringToStream('test'));
    }
}
