# The Generic Adapter

If you do not specify an adapter for a specific framework, this is what Sapient uses.

The generic adapter only provides `stringToStream()` (and none of the convenience methods),
which is needed to convert a string to an instance of `StreamInterface`.

We adapted our `Stream` implementation almost verbatim from Slim Framework, except we made
our implementation type-safe (verified by Psalm during continuous integration).
