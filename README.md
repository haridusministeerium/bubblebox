# bubblebox
Process sandboxing using bubblewrap

The original version was stolen from [@sloonz's gist](https://gist.github.com/sloonz/ef282a1f53366e1ed6f5cb848de015ba)

Not to be confused with [RalfJung/bubblebox](https://github.com/RalfJung/bubblebox)

# see also

- [landlock](https://github.com/landlock-lsm) - different from
  bubblewrap/firejail -- doesn't use namespaces
  - [island](https://github.com/landlock-lsm/island) - frontend by landlock
    project themselves (WIP as of May '26)
  - [landrun](https://github.com/Zouuup/landrun) - 3rd party go-based frontend
  - [sandlock](https://github.com/multikernel/sandlock) - 3rd party rust-based frontend
  - see also [software using landlock](https://wiki.gnoack.org/SoftwareUsingLandlock)
- [syd](https://gitlab.exherbo.org/sydbox/sydbox)
  - another alternative to bwrap/firejail et al
- [google/nsjail](https://github.com/google/nsjail)
- [google/minijail](https://google.github.io/minijail/)
- [crablock](https://codeberg.org/crabjail/crablock/)
  - more related projects in [crabjail's readme](https://codeberg.org/crabjail/crabjail#related-projects)
- [opensnitch](https://github.com/evilsocket/opensnitch)
- [bubblejail](https://github.com/igo95862/bubblejail)
https://github.com/windtf/wireproxy
https://github.com/capnspacehook/egress-eddie


## TODO

- create config validator. also unknown config keys shouldn't simply be
  ignored, but should result in an exception
- to the validation end, consider pydantic, but past experience suggests it
  adds non-insignificant delay to startup. perhaps `TypedDict`?
- why do we use camel-case in config only having to convert it to kebab
  used by bwrap via bwrap_name()? would make everyone's lives easier by using kebab everywhere.

