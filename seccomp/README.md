# Seccomp profiles

## `moby-default.json`

Docker's default seccomp profile, **vendored unmodified** from
[`moby/moby` @ `v27.3.1`](https://github.com/moby/moby/blob/v27.3.1/profiles/seccomp/default.json)
(`profiles/seccomp/default.json`).

It is here so that the profile Watson's containers actually run under is a small,
reviewable *delta* from Docker's own default, rather than 13KB of JSON somebody
has to read from scratch — or, worse, `seccomp=unconfined`.

## The derived profile

`tools/seccomp-profile.mjs` reads the file above and applies **two changes**,
both required for Chromium's layer-1 (namespace) sandbox to start:

1. `unshare` is allowed without `CAP_SYS_ADMIN`.
2. The `clone` argument mask no longer forbids the four namespace flags Chromium
   needs (`CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
   Creating new cgroup, UTS and IPC namespaces stays forbidden.

Nothing else changes: `defaultAction` remains `SCMP_ACT_ERRNO`, so the profile is
still an allow-list, and every other syscall rule is Docker's.

`test/seccomp.test.mjs` asserts exactly that — that the delta is these two
changes and no others — so a future edit that quietly widens the profile fails
the build instead of passing review.

## Why this is needed

Measured, not assumed. On GitHub's `ubuntu-latest` runners:

```text
host: apparmor_restrict_unprivileged_userns = 1
default                                  unshare: Operation not permitted
apparmor=unconfined                      unshare: Operation not permitted
seccomp=unconfined                       CREATED
no no-new-privileges                     unshare: Operation not permitted
cap SYS_ADMIN                            CREATED
```

So the blocker is **Docker's seccomp profile**, not AppArmor and not
`no-new-privileges`. The two configurations that work are dropping seccomp
entirely or granting `CAP_SYS_ADMIN`; both are far larger than what Chromium
needs. This profile is the small version.

## The trade, stated

Permitting unprivileged user-namespace creation widens the kernel surface
reachable from inside the container — user namespaces are a well-known local
privilege-escalation vector, which is why the host restricts them by default.

It is taken deliberately, because the process that handles attacker-controlled
content is the browser renderer, and the namespace sandbox is what isolates it.
The container that gets this profile runs **no product code**: it holds the
engine, the browser and the evidence, and the product runs in a different
container that keeps the unmodified default.
