<?php
declare(strict_types=1);
namespace ParagonIE\Sapient\Adapter\Generic;

use Psr\Http\Message\StreamInterface;

/**
 * Class Stream
 * @package ParagonIE\Sapient\Adapter\Generic
 *
 * This was copied from Slim Framework's implementation.
 *
 * Slim Framework (https://slimframework.com)
 *
 * @link      https://github.com/slimphp/Slim
 * @copyright Copyright (c) 2011-2017 Josh Lockhart
 * @license   https://github.com/slimphp/Slim/blob/3.x/LICENSE.md (MIT License)
 */
class Stream implements StreamInterface
{
    /**
     * Bit mask to determine if the stream is a pipe
     *
     * This is octal as per header stat.h
     */
    const FSTAT_MODE_S_IFIFO = 0010000;

    /**
     * Resource modes
     *
     * @var  array
     * @link http://php.net/manual/function.fopen.php
     */
    protected static $modes = [
        'readable' => ['r', 'r+', 'w+', 'a+', 'x+', 'c+'],
        'writable' => ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'],
    ];

    /**
     * The underlying stream resource
     *
     * @var resource|closed-resource|null
     */
    protected $stream;

    /**
     * Stream metadata
     *
     * @var array|null
     */
    protected $meta;

    /**
     * Is this stream readable?
     *
     * @var bool|null
     */
    protected $readable;

    /**
     * Is this stream writable?
     *
     * @var bool|null
     */
    protected $writable;

    /**
     * Is this stream seekable?
     *
     * @var bool|null
     */
    protected $seekable;

    /**
     * The size of the stream if known
     *
     * @var null|int
     */
    protected $size;

    /**
     * Is this stream a pipe?
     *
     * @var bool|null
     */
    protected $isPipe;

    /**
     * Create a new Stream.
     *
     * @param  resource $stream A PHP resource handle.
     *
     * @throws \InvalidArgumentException If argument is not a resource.
     */
    public function __construct($stream)
    {
        $this->stream = null;
        $this->attach($stream);
    }

    /**
     * Get stream metadata as an associative array or retrieve a specific key.
     *
     * The keys returned are identical to the keys returned from PHP's
     * stream_get_meta_data() function.
     *
     * @link http://php.net/manual/en/function.stream-get-meta-data.php
     *
     * @param string $key Specific metadata to retrieve.
     *
     * @return array|mixed|null Returns an associative array if no key is
     *     provided. Returns a specific key value if a key is provided and the
     *     value is found, or null if the key is not found.
     */
    public function getMetadata($key = null)
    {
        if (!\is_resource($this->stream)) {
            return null;
        }
        $this->meta = \stream_get_meta_data($this->stream);
        if (\is_null($key) === true) {
            return $this->meta;
        }

        return isset($this->meta[$key]) ? $this->meta[$key] : null;
    }

    /**
     * Is a resource attached to this stream?
     *
     * Note: This method is not part of the PSR-7 standard.
     *
     * @return bool
     */
    protected function isAttached()
    {
        return is_resource($this->stream);
    }

    /**
     * Attach new resource to this object.
     *
     * Note: This method is not part of the PSR-7 standard.
     *
     * @param resource $newStream A PHP resource handle.
     * @return void
     *
     * @throws \InvalidArgumentException If argument is not a valid PHP resource.
     * @psalm-suppress DocblockTypeContradiction
     */
    protected function attach($newStream)
    {
        if (!\is_resource($newStream)) {
            throw new \InvalidArgumentException(__METHOD__ . ' argument must be a valid PHP resource');
        }

        if ($this->isAttached() === true) {
            $this->detach();
        }

        $this->stream = $newStream;
    }

    /**
     * Separates any underlying resources from the stream.
     *
     * After the stream has been detached, the stream is in an unusable state.
     *
     * @return resource|null Underlying PHP stream, if any
     */
    public function detach()
    {
        if (!\is_resource($this->stream)) {
            return null;
        }
        $oldResource = $this->stream;
        $this->stream = null;
        $this->meta = null;
        $this->readable = null;
        $this->writable = null;
        $this->seekable = null;
        $this->size = null;
        $this->isPipe = null;

        return $oldResource;
    }

    /**
     * Reads all data from the stream into a string, from the beginning to end.
     *
     * This method MUST attempt to seek to the beginning of the stream before
     * reading data and read the stream until the end is reached.
     *
     * Warning: This could attempt to load a large amount of data into memory.
     *
     * This method MUST NOT raise an exception in order to conform with PHP's
     * string casting operations.
     *
     * @see http://php.net/manual/en/language.oop5.magic.php#object.tostring
     * @return string
     */
    public function __toString()
    {
        if (!$this->isAttached()) {
            return '';
        }

        try {
            $this->rewind();
            return $this->getContents();
        } catch (\RuntimeException $e) {
            return '';
        }
    }

    /**
     * Closes the stream and any underlying resources.
     * @throws \TypeError
     * @return void
     */
    public function close()
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if ($this->isAttached() === true) {
            if ($this->isPipe()) {
                \pclose($this->stream);
            } else {
                \fclose($this->stream);
            }
        }

        $this->detach();
    }

    /**
     * Get the size of the stream if known.
     *
     * @return int|null Returns the size in bytes if known, or null if unknown.
     * @throws \TypeError
     */
    public function getSize()
    {
        if (!$this->size && $this->isAttached() === true) {
            if (!\is_resource($this->stream)) {
                throw new \TypeError();
            }
            $stats = \fstat($this->stream);
            /** @var int|null size */
            $this->size = isset($stats['size']) && !$this->isPipe() ? (int) $stats['size'] : null;
        }

        return $this->size;
    }

    /**
     * Returns the current position of the file read/write pointer
     *
     * @return int Position of the file pointer
     *
     * @throws \RuntimeException on error.
     * @throws \TypeError
     */
    public function tell()
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isAttached() || $this->isPipe()) {
            throw new \RuntimeException('Could not get the position of the pointer in stream');
        }
        /** @var int|false $position */
        $position = \ftell($this->stream);
        if (!\is_int($position)) {
            throw new \RuntimeException('Could not get the position of the pointer in stream');
        }
        return (int) $position;
    }

    /**
     * Returns true if the stream is at the end of the stream.
     *
     * @return bool
     * @throws \TypeError
     */
    public function eof()
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        return $this->isAttached() ? \feof($this->stream) : true;
    }

    /**
     * Returns whether or not the stream is readable.
     *
     * @return bool
     */
    public function isReadable()
    {
        if ($this->readable === null) {
            if ($this->isPipe()) {
                $this->readable = true;
            } else {
                $this->readable = false;
                if ($this->isAttached()) {
                    /** @var array<string, string> $meta */
                    $meta = $this->getMetadata();
                    /** @var string $mode */
                    foreach (self::$modes['readable'] as $mode) {
                        if (strpos($meta['mode'], $mode) === 0) {
                            $this->readable = true;
                            break;
                        }
                    }
                }
            }
        }

        return $this->readable;
    }

    /**
     * Returns whether or not the stream is writable.
     *
     * @return bool
     */
    public function isWritable()
    {
        if ($this->writable === null) {
            $this->writable = false;
            if ($this->isAttached()) {
                /** @var array<string, string> $meta */
                $meta = $this->getMetadata();
                /** @var string $mode */
                foreach (self::$modes['writable'] as $mode) {
                    if (\strpos($meta['mode'], $mode) === 0) {
                        $this->writable = true;
                        break;
                    }
                }
            }
        }

        return $this->writable;
    }

    /**
     * Returns whether or not the stream is seekable.
     *
     * @return bool
     */
    public function isSeekable()
    {
        if ($this->seekable === null) {
            $this->seekable = false;
            if ($this->isAttached()) {
                /** @var array<string, bool|int|string> $meta */
                $meta = $this->getMetadata();
                $this->seekable = !$this->isPipe() && $meta['seekable'];
            }
        }

        return $this->seekable;
    }

    /**
     * Seek to a position in the stream.
     *
     * @link http://www.php.net/manual/en/function.fseek.php
     *
     * @param int $offset Stream offset
     * @param int $whence Specifies how the cursor position will be calculated
     *     based on the seek offset. Valid values are identical to the built-in
     *     PHP $whence values for `fseek()`.  SEEK_SET: Set position equal to
     *     offset bytes SEEK_CUR: Set position to current location plus offset
     *     SEEK_END: Set position to end-of-stream plus offset.
     * @return void
     *
     * @throws \RuntimeException on failure.
     * @throws \TypeError
     */
    public function seek($offset, $whence = SEEK_SET)
    {
        // Note that fseek returns 0 on success!
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isSeekable() || \fseek($this->stream, $offset, $whence) === -1) {
            throw new \RuntimeException('Could not seek in stream');
        }
    }

    /**
     * Seek to the beginning of the stream.
     *
     * If the stream is not seekable, this method will raise an exception;
     * otherwise, it will perform a seek(0).
     *
     * @see seek()
     *
     * @link http://www.php.net/manual/en/function.fseek.php
     *
     * @return void
     * @throws \RuntimeException on failure.
     * @throws \TypeError
     */
    public function rewind()
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isSeekable() || \rewind($this->stream) === false) {
            throw new \RuntimeException('Could not rewind stream');
        }
    }

    /**
     * Read data from the stream.
     *
     * @param int $length Read up to $length bytes from the object and return
     *     them. Fewer than $length bytes may be returned if underlying stream
     *     call returns fewer bytes.
     *
     * @return string Returns the data read from the stream, or an empty string
     *     if no bytes are available.
     *
     * @throws \RuntimeException if an error occurs.
     * @throws \TypeError
     */
    public function read($length)
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isReadable() || ($data = \fread($this->stream, $length)) === false) {
            throw new \RuntimeException('Could not read from stream');
        }
        if (!isset($data)) {
            $data = '';
        }

        return (string) $data;
    }

    /**
     * Write data to the stream.
     *
     * @param string $string The string that is to be written.
     *
     * @return int Returns the number of bytes written to the stream.
     *
     * @throws \RuntimeException on failure.
     * @throws \TypeError
     */
    public function write($string)
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isWritable() || ($written = \fwrite($this->stream, $string)) === false) {
            throw new \RuntimeException('Could not write to stream');
        }
        if (!isset($written)) {
            $written = 0;
        }

        // reset size so that it will be recalculated on next call to getSize()
        $this->size = null;

        return (int) $written;
    }

    /**
     * Returns the remaining contents in a string
     *
     * @return string
     *
     * @throws \RuntimeException if unable to read or an error occurs while
     *     reading.
     * @throws \TypeError
     */
    public function getContents()
    {
        if (!\is_resource($this->stream)) {
            throw new \TypeError();
        }
        if (!$this->isReadable() || ($contents = \stream_get_contents($this->stream)) === false) {
            throw new \RuntimeException('Could not get contents of stream');
        }
        if (!isset($contents)) {
            $contents = '';
        }

        return (string) $contents;
    }

    /**
     * Returns whether or not the stream is a pipe.
     *
     * @return bool
     * @throws \TypeError
     */
    public function isPipe()
    {
        if ($this->isPipe === null) {
            $this->isPipe = false;
            if ($this->isAttached()) {
                if (!\is_resource($this->stream)) {
                    throw new \TypeError();
                }
                $mode = (int) \fstat($this->stream)['mode'];
                $this->isPipe = ($mode & self::FSTAT_MODE_S_IFIFO) !== 0;
            }
        }

        return $this->isPipe;
    }

    /**
     * Create a Stream object from a string.
     *
     * @param string $input
     * @return StreamInterface
     * @throws \Error
     */
    public static function fromString(string $input): StreamInterface
    {
        /** @var resource|bool $stream */
        $stream = \fopen('php://temp', 'w+');
        if (!\is_resource($stream)) {
            throw new \Error('Could not create stream');
        }
        \fwrite($stream, $input);
        \rewind($stream);
        return new static($stream);
    }
}
