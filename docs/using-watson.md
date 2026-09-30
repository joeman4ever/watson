# Using Watson — a plain-English guide

This is the doorway. If you are deciding whether to use Watson on a project, or
you have inherited one that already uses it, start here. The
[README](../README.md) is the reference manual and assumes you already know the
vocabulary; this page doesn't.

---

## What Watson is

Watson is a robot tester. It opens a real browser, signs in as a test user, and
clicks through the journeys you tell it matter — "can a coach see the report
they're allowed to see, and not the ones they aren't" — against a real database
and a real running copy of your application.

It then writes down what actually happened and posts the result.

**What makes it different from your existing tests:** unit tests check that
functions return the right values. Watson checks that the assembled, running
product behaves correctly when a person uses it. Those are different questions,
and a codebase can pass every unit test while the actual screen is broken.

**What Watson deliberately does not do:** it never reviews your code, never
comments on your design, never suggests changes, and never modifies the product
it tests. It answers one question — *did the running application behave
correctly?* — and stays out of everything else.

---

## Should you use it?

Honest answer: **it is not free, and the cost is mostly yours, not the
machine's.**

Watson is generic. What makes it useful on your project is a description *you*
write: which journeys matter, what a correct outcome looks like, what world to
seed the database with. Nobody can write that for you, because it is a statement
about your product's intended behaviour.

Budget roughly **a few days** to describe a meaningful set of journeys for a
medium-sized application, and expect to revise them as you learn what you got
wrong. The first project to use Watson took considerably longer than that, but
much of it was building Watson itself.

**It is worth it when:**

- the damage from a broken screen is high — permissions, money, anything
  involving people's data
- the behaviour you care about only emerges when several pieces run together
- you have had bugs that every test suite passed

**It is probably not worth it when:**

- your app is small enough that you'd notice breakage immediately
- nobody will maintain the journey descriptions as the product changes

That last one is the real risk. A journey description that has drifted away from
the product is worse than none: it either fails constantly and gets ignored, or
passes over behaviour it no longer actually checks.

---

## How it keeps itself honest

You don't need this section to use Watson, but you should read it before
trusting it, because it is the reason the results mean anything.

**Watson runs in two halves that don't trust each other.**

The first half runs *your pull request's code*. That is inherently risky — it is
executing code someone proposed — so it is given **no ability to write anything
back to GitHub at all**. It produces a report and stops.

The second half reads that report, checks it is internally honest, and posts the
result. It runs code from your main branch only. The checks it makes are things
like: did this report describe the commit it claims? Was the working copy clean?
Does the engine it says it used match the one we pinned?

**The same idea applies to Watson's instructions.** The list of journeys, and
the pointer to which version of Watson to use, are read from your **main
branch** — never from the pull request being tested.

That one is worth dwelling on. If a pull request could edit the rules that judge
it, it could simply delete the journey that catches its bug, or point at a
version of Watson that agrees with it. The whole exercise would be theatre.

**A consequence that surprises people:** a pull request that changes Watson's
own settings is *not* tested under its own changes. The run uses the settings
from main. So if you change a journey, the pull request making that change can't
confirm it works — the first real confirmation comes from the *next* pull
request, after yours merges.

---

## What you have to write

Everything lives in a `.watson/` folder at the root of your project, versioned
alongside your code and reviewed in the same pull requests. Five files there,
plus two CI workflow files:

| File | What it is |
| --- | --- |
| `.watson/config.yaml` | How to install, build, launch and reach your app; which version of Watson to use |
| `.watson/features/*.md` | One file per journey — the steps to take and what must be true |
| `.watson/fixtures/profiles.yaml` | What world to seed the database with, and checks that the seeding worked |
| `.watson/identities.yaml` | The test users and what each is meant to be able to do |
| `.watson/invariants.yaml` | The rules that must never break |
| Two CI workflow files | One runs the test; one checks the report and posts the result |

The project already using Watson has eleven journeys. That is a reasonable
target — enough to cover what actually matters, few enough that someone will
keep them current.

### A journey, in practice

A journey file is mostly readable prose with a list of steps. Roughly:

> Go to the report page. Confirm the grade this user *is* allowed to see does
> load — otherwise every denial below proves nothing, because a user with no
> access at all would also be denied. Then confirm the grade they were never
> granted is refused. Then the one that was granted and revoked. Then the one
> that expired.

That "otherwise every denial proves nothing" instinct is most of the skill.
A test that only checks things fail can pass against a completely broken login.

### The part people underestimate

`fixtures/profiles.yaml` also holds **preconditions** — checks that run *before*
any journey, confirming the world you asked for actually got built. Writing rows
into a database is not proof that they mean anything. A real example from the
first project: every insert succeeded, and the feature still didn't work,
because a missing route meant the data resolved to nothing. A journey passed
over a world that was never really there.

If preconditions fail, Watson reports an *environment* problem, not a product
failure. That distinction matters — it stops Watson blaming your code for its
own setup going wrong.

---

## Setting it up, in order

Don't try to write all of this at once. Each step is checkable on its own, and
the order exists so that when something breaks you know which step broke it.

**1. Get your app to start on a clean machine.** Write `config.yaml` — the
commands to install dependencies, build, and launch, and the address to reach
the app at. Run `watson doctor` locally: it starts everything up, pokes it, and
tears it down. Nothing else will work until this does, and this is where most
of the early time goes.

**2. Describe your test users.** `identities.yaml` lists who they are and what
each is supposed to be able to do. Keep it small — a handful of clearly
different roles beats twenty near-identical ones.

**3. Describe the world.** `fixtures/profiles.yaml` says what to put in the
database before anything runs, and — importantly — the checks that confirm the
setup actually worked. Read "the part people underestimate" above before
writing this one.

**4. Write one journey.** Just one, the most important one. Get it running and
get it passing.

**5. Break it on purpose.** Change the product so the journey *should* fail, and
confirm Watson notices. A journey you have never seen fail is a journey you have
no reason to trust. Then undo the break.

**6. Repeat steps 4 and 5** for the rest of the journeys that matter.

**7. Turn on CI.** Copy the two workflow files, and run in watch-only mode.
Leave it there until you have seen enough results to know how often it's right.

Use real files from the project already running Watson as your templates —
copying a working example is far faster than writing from the reference manual.

### One thing to know before you start step 7

Watson's settings are read from your main branch, not from the pull request
being tested. So while you are still setting things up, changes to `.watson/`
only take effect once they are merged. Expect the loop to feel slower than
normal development — that is the price of the safety described above, and it
is deliberate.

---

## Where the results show up

Three places, listed in order of how much you should trust them.

**1. The check on the pull request** — the quick answer. It shows the outcome
and links to the other two.

Treat it as a signpost, not the truth. It is the least trustworthy of the three,
and Watson says so on the check itself: a pull request can publish a check with
the same name and any result it likes, and can overwrite the real one. This has
been demonstrated, not theorised.

**2. The summary of the checking job** — *this is the record.* It is produced by
the half of Watson that runs your main branch's code, so a pull request cannot
influence it. The check links to it directly.

**If the check and the summary disagree, the summary is right. If you can't find
the summary, you have no evidence — which is not the same as a pass.**

**3. The evidence bundle** — attached to the run. Step-by-step logs, the final
web address, network failures, and on failure a screenshot, a snapshot of the
page, and a full trace. This is where you look when you want to know *why*,
rather than *whether*.

### Reading a result

Watson reports two things, and they answer different questions.

The first is **what it learned** — the product passed, the product failed, or it
couldn't tell. The second is **whether it managed to do its job at all** — the
check ran properly, or something stopped it.

They are kept separate on purpose. "The product is broken" and "Watson couldn't
check" are very different situations, and collapsing them into one signal means
either you can't trust a pass, or you can't act on a failure.

The outcomes you'll see most:

| What it says | What it means |
| --- | --- |
| Passed | The journeys ran and behaved correctly |
| Passed, with notes | Same, plus something worth a glance that isn't a failure |
| Product failure | Watson believes your application is genuinely broken |
| Not applicable | Nothing in this change touched anything Watson covers |
| Blocked | Watson couldn't set up a working environment — its problem, not yours |
| Can't tell | Something prevented a trustworthy answer. **Not a pass.** |

---

## What Watson will not tell you

Be clear-eyed about this, especially if you are considering letting Watson block
merges.

**It only checks the journeys you wrote.** If your description covers nine
journeys and a change touches forty files, Watson has an opinion about the nine.
A green result means *"the nine things I check still work"* — not *"this change
is safe."*

**It can be wrong.** On the first project it twice reported the product broken
when it was fine, because a check for "this text must not appear" matched "Grade
1" inside a legitimate "Grade 10". Both were false alarms, both are on the
permanent record, and the fix is in — but the lesson stands: a robot tester's
accusations need the same scepticism as anyone else's.

**It does not prove the code that ran was the code you committed.** It proves
the *source files* matched the commit. What gets built from that source, the
libraries it loads, and the machine it runs on are outside what it measures.
That limitation is written down deliberately rather than glossed over, in an
architecture decision record kept in this repository, rather than left for
someone to discover.

---

## Current maturity

Watson is **in use on one project, in watch-only mode.** It reports; it blocks
nothing; you are free to ignore it.

Before it is considered trustworthy enough to matter, there is a written list of
ten conditions. One of them was settled long ago as a nice-to-have rather than a
requirement. Of the nine that are real, **seven are met and two are not** — and
both of those two trace back to the single false-alarm bug described above.

That bug is fixed, and the fix is live. What is still owed is evidence: enough
further runs to bring the false-alarm rate back under its limit, and at least
one real run observed working under the corrected version. Neither can be
rushed, because the only observations that count are ones produced by genuine
product work. Manufacturing changes to make the numbers move faster is
explicitly not allowed — it would make the evidence worthless.

**Do not make Watson a required check on a new project.** Run it in watch-only
mode first, long enough to see how often it is right, and decide from evidence
rather than hope.
