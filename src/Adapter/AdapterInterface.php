<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\Adapter;

use Psr\Http\Message\StreamInterface;


/**
 * Interface AdapterInterface
 * @package ParagonIE\Sapient\Adapter
 */
interface AdapterInterface
{
    /**
     * Adapter-specific way of converting a string into a StreamInterface
     *
     * @param string $input
     * @return StreamInterface
     */
    public function stringToStream(string $input): StreamInterface;
}
