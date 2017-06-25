# Adapter Interface

All an Adapter needs is the ability to convert a string (containin the data, not a filename)
into an implementation of PSR-7's `StreamInterface` specific to your framework.

Some adapters may also choose to implement the [`ConvenienceInterface`](ConvenienceInterface.md),
which provides methods for converting strings or arrays into framework-specfic `Request` or
`Response` objects.

## `stringToStream()`

Function prototype:

```php
function stringToStream(
    string $input
): StreamInterface;
```

This must return a `Stream` object that implements `StreamInterface` whose contents are populated
by `$input`. Implementations may alter the contents of `$input` to suit their needs. 
