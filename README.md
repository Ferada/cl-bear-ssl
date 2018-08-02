CL-BEAR-SSL - Binding to BearSSL, providing SSL/TLS streams.

Copyright (C) 2018 Olof-Joachim Frahm

Released under a Simplified BSD license.

Rough first draft, DRAKMA/DEXADOR can use the stream, inefficient as it
may be.

Runs on CCL and SBCL.

Uses CFFI/CFFI-GROVEL, trivial-utf-8 and trivial-garbage.

**Don't use this for anything critical!**  Like your online banking,
with important passwords, etc.  Firstly BearSSL itself says
"beta-quality software", so this one here is basically pre-alpha.
Secondly I've not even started to look for logic bugs, memory isn't
being handled carefully at all and in general *here be bugs*.

That said it does support reading Reddit.

# SUMMARY

I find the OpenSSL API hard to understand and presumably that also
hinders others to work on CL+SSL.  This library should firstly be a
drop-in replacement for CL+SSL for the typical use cases, that being
DRAKMA, DEXADOR and whatever other HTTP clients are out there.  That's
the MVP.

Secondly it should also expose all the right suites to make it usable
for HTTP 2.0 - the protocol itself isn't in scope though.

Thirdly, this library should also expose a nice API that's not tied to
OpenSSL conventions and allows more atypical use cases.

# USAGE

Until I find a better way you'll have to add the BearSSL shared library
to a path that CFFI can search; alternatively use something like

    (pushnew #P".../BearSSL/build/" cffi:*foreign-library-directories*)
    (pushnew #P".../cl-bear-ssl/src/" cffi:*foreign-library-directories*)

to add the directory in question to the list of directories to search.
BearSSL needs to be built of course, c.f. https://www.bearssl.org, or
just `git clone https://www.bearssl.org/git/BearSSL` at this time.

Then, load the compatibility layer for now

    (asdf:load-system '#:cl-bear-ssl-compat)

and then *remove* CL+SSL from the ASDF of definitions of DRAKMA/DEXADOR
and then load it (looking for a better way here!) and request something
from an HTTPS page:

    ;; after having removed CL+SSL from DRAKMA/DEXADOR!
    (asdf:load-system '#:drakma)
    (drakma:http-request "https://www.google.com/")

    (asdf:load-system '#:dexador)
    (dex:get "https://www.google.com/")

The system loads `/etc/ssl/certs/ca-certificates.crt` on startup, if
your system doesn't have that file you might need to find a replacement
since, funnily enough, disabling certificate validation isn't
implemented yet.

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
- Make I/O fast, both on the route through Lisp, but also possibly
  implement a C layer that doesn't always have to jump back into Lisp
  for looking at the buffers.
- Make I/O cooperate nicely with IOLIB (aka expose the FD).
- Check that GC works correctly.
- Make it run on more implementations (ECL, ...?).
- Enable client certificates.
