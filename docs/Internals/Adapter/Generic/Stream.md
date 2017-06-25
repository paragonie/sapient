# Generic Adapter Stream Object

Our generic `Stream` implementation was taken almost verbatim from [Slim Framework's `Stream` class](https://www.slimframework.com/docs/objects/request.html#the-request-body).

It implements PSR-7's `StreamInterface` but, aside from being fully type-safe, doesn't do anything special.
