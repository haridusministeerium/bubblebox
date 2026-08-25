# bubblebox
Process sandboxing using bubblewrap

The original version was stolen from [@sloonz's gist](https://gist.github.com/sloonz/ef282a1f53366e1ed6f5cb848de015ba)

Not to be confused with [RalfJung/bubblebox](https://github.com/RalfJung/bubblebox)


## Articles/blogs/discussions

- [Let's discuss sandbox isolation](https://www.shayon.dev/post/2026/52/lets-discuss-sandbox-isolation/) - blog post from Feb '26
- [one sandboxing blog post](https://www.standingpad.org/posts/2023/08/sandboxing-time/)
  - discovered form the main gist thread discussing xdg portals starting from
    [here](https://gist.github.com/sloonz/4b7f5f575a96b6fe338534dbc2480a5d?permalink_comment_id=5402392#gistcomment-5402392)
- https://dev.to/uenyioha/37-vulnerabilities-exposed-across-15-ai-ides-the-threat-model-every-agent-builder-must-understand-3f5


# see also

- [gvisor](https://gvisor.dev/)
  - shields container workloads;
  - it implements the linux api and intercepts sandboxed apps' calls to the
    kernel; note it's not a syscall filter (like `seccomp-bpf`); it's an
    application kernel for containers.
  - note [this HN comment](https://news.ycombinator.com/item?id=48690216)
    shows how to use it with bubblewrap: `bwrap args -- gvisor args do args -- /path/sandboxee args`
- [muvm](https://github.com/AsahiLinux/muvm)
  - run programs from your system in a microVM
  - loosely related: https://git.clan.lol/clan/munix
- [fence](https://github.com/fencesandbox/fence)
  - lang: go
  - Network isolation - All outbound blocked by default; allowlist domains via config
  - Filesystem restrictions - Control read/write access paths
  - Command blocking - Deny dangerous commands like rm -rf /, git push
  - SSH Command Filtering - Control which hosts and commands are allowed over SSH
  - Built-in templates - Pre-configured rulesets for common workflows
  - Violation monitoring - Real-time logging of blocked requests (-m)
  - Cross-platform - macOS (sandbox-exec) + Linux (bubblewrap)
- [syd](https://gitlab.exherbo.org/sydbox/sydbox)
  - another alternative to bwrap/firejail et al;
    > intends to provide a simple interface over various intricate Linux sandboxing mechanisms such as LandLock, Namespaces, Ptrace, and Seccomp-{BPF,Notify}
- [crablock](https://codeberg.org/crabjail/crablock/)
  - more related projects in [crabjail's readme](https://codeberg.org/crabjail/crabjail#related-projects)
- [simple-appimage-sandbox](https://github.com/Samueru-sama/simple-appimage-sandbox/)
  - uses bwrap to sandbox appimages
- [jai](https://github.com/stanford-scs/jai)
  - Jail your AI agent
- [sbx](https://github.com/cauldrondevelopmentllc/sbx)
  - another solution deriving from @sloonz's gist
- [docker-based sbx](https://github.com/dockersamples/sbx-quickstart)
  - also does secrets injection
  - demonstrates opinionated claude workflow
- [docker's own sbx](https://docs.docker.com/ai/sandboxes/)
  - `sbx run claude`
- [landlock](https://github.com/landlock-lsm) - different from
  bubblewrap/firejail -- doesn't use namespaces
  - [island](https://github.com/landlock-lsm/island) - frontend by landlock
    project themselves (WIP as of May '26)
  - [landrun](https://github.com/Zouuup/landrun) - 3rd party go-based frontend
  - [sandlock](https://github.com/multikernel/sandlock) - 3rd party rust-based frontend
  - see also [software using landlock](https://wiki.gnoack.org/SoftwareUsingLandlock)
- [google/nsjail](https://github.com/google/nsjail)
- [google/minijail](https://google.github.io/minijail/)
- [opensnitch](https://github.com/evilsocket/opensnitch)
- [bubblejail](https://github.com/igo95862/bubblejail)
- [matchlock](https://github.com/jingkaihe/matchlock)
  - isolates AI workloads using firecracker
  - one interesting feature is the secrets injection:
    > When your agent calls an API the real credentials are injected in-flight by the host.
      The sandbox only ever sees a placeholder. Even if the agent is tricked into running
      something malicious your keys don't leak and there's nowhere for data to go
- [gondolin](https://github.com/earendil-works/gondolin)
  - another agent isolation using micro-VMs (qemu by default)
- [opensandbox](https://github.com/opensandbox-group/OpenSandbox)
- [amika](https://github.com/gofixpoint/amika) - Infra for computer agents and software factories
  - spawn/manage local or remote sandboxes
  - see also their [roadmap](https://github.com/gofixpoint/amika/blob/main/ROADMAP.md)
- [microsandbox](https://github.com/superradcompany/microsandbox?tab=readme-ov-file#getting-started)
  - easy, fast and local-first microVM runtime
  - cli, sdk...
  - looks cool!
- https://github.com/windtf/wireproxy
- https://github.com/capnspacehook/egress-eddie
- https://github.com/danthegoodman1/netfence
- https://github.com/arjan/awesome-agent-sandboxes
- https://engine.build/lab/agent-sandboxes
  - compares 30 hosted, platform-native, open-source, self-hosted, and local sandbox
    options across isolation model, startup time, persistence, pricing, SDKs, and deployment style
- https://github.com/kubernetes-sigs/agent-sandbox
  - spawn sandboxed workloads on k8s
- https://shellbox.dev/
  - manage linux vms via ssh, pay only for what you use
  - cheaper, no subscription is needed, supports nested virt, docker, custom images,
    duplication of boxes, gives an ipv6, auto-stop on optional auto stop on disconnect,
    wakeup on web endpoint hit, email endpoint, exposed ipv6, and more
- https://github.com/lima-vm/lima
  - for MacOS
- [sandboxd](https://github.com/tastyeffectco/sandboxd/)
  - Open-source, self-hosted AI app builder — an agent builds real apps in isolated
    sandboxes on your own server, each live at a preview URL. Self-host in one command
  - [basically](https://github.com/tastyeffectco/sandboxd/#what-is-sandboxd)
    starts a sandbox with GUI and live-preview to vibe-code... "apps"; note
    this GUI is still an api client, i.e. you can opt out of GUI and use
    directly the api yourself
  - odd one, think it's more for providing interface for clients/your grandma
- [smolvm](https://github.com/smol-machines/smolvm)
  - portable, lightweight, self-contained virtual machine.

# other resources

- another [instruction](https://github.com/hemashushu/docker-archlinux-gui#sound-related-parameters)
  demonstrating running GUI apps via docker/namespaces


## TODO

- create config validator. also unknown config keys shouldn't simply be
  ignored, but should result in an exception
- to the validation end, consider pydantic, but past experience suggests it
  adds non-insignificant delay to startup. perhaps `TypedDict`? even better, try
  TypedDict [with pydantic](https://pydantic.dev/docs/validation/latest/concepts/performance/#use-typeddict-over-nested-models),
  using its `TypeAdapter`;
- why do we use camel-case in config only having to convert it to kebab
  used by bwrap via bwrap_name()? would make everyone's lives easier by using kebab everywhere.
- do we want to add `--json-status-fd FD` (e.g. replace or add in addition to
  existing `--info-fd FD`) to bwrap?
- how to make `xdg-dbus-proxy` work if it's _not_ sandboxed?
- more of a config/taste question, but is there any point in binding separate
  `~/.cache`, given we already have private HOME?
- verify seccomp & add rules
- to enter already-created ns w/ another process, do
  `nsenter --preserve-credentials --user --env --mount --pid --net -t 3487436`
  where 3487436 is --info-fd file's `child-pid` + 1; i.e. child-pid points
  to the bwrap process, but we want the first process started _from_ it; to see
  whether to pass --mount, --net, --ipc et al, check the same file and which
  namespace IDs it contains (but we won't need the IDs themselves)

