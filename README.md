CL-BEAR-SSL - Binding to BearSSL, providing SSL/TLS streams.

Copyright (C) 2018 Olof-Joachim Frahm

Released under a Simplified BSD license.

Rough first draft, DRAKMA can use the stream, inefficient as it may be.

Uses CFFI/CFFI-GROVEL, trivial-utf-8 and trivial-garbage.

# SUMMARY

I find the OpenSSL API hard to understand and presumably that also
hinders others to work on CL+SSL.  This library should firstly be a
drop-in replacement for CL+SSL for the typical use cases, that being
DRAKMA and whatever other HTTP clients are out there.  That's the MVP.

Secondly it should also expose all the right suites to make it usable
for HTTP 2.0 - the protocol itself isn't in scope though.

Thirdly, this library should also expose a nice API that's not tied to
OpenSSL conventions and allows more atypical use cases.

# TODO

- Sort out the library thing, possibly with a Makefile that compiles it
  from scratch or so.
- Add an ASDF system that can be preloaded so that systems requiring
  CL+SSL will not actually need to load anything else but us.
- Allow disabling of trust handling, which I failed at before, so either
  that, or
- sort out trust anchor handling, load that from the default operating
  stores (that'll be a pain, but presumably just follow whatever OpenSSL
  does for this).
- Make it run on SBCL.
- Make I/O fast, both on the route through Lisp, but also possibly
  implement a C layer that doesn't always have to jump back into Lisp
  for looking at the buffers.
- Make I/O cooperate nicely with IOLIB (aka expose the FD).
- Check that GC works correctly.
