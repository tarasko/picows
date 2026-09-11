<a href="https://keepthewhy.com"><img src="https://keepthewhy.com/assets/logo.png" alt="Keep the Why"></a>

# Project context

This directory is picows' memory: the reasoning behind the code,
kept next to it. Decisions, rejected alternatives, workarounds,
constraints and incident learnings that the code alone cannot explain,
as plain Markdown, versioned with the code, written for the people and
the coding agents working here, so nothing rejected is proposed twice.

Keep a Changelog records what changed. Keep the Why preserves why it
changed.

It follows the [Keep the Why](https://keepthewhy.com) schema, so an
agent or a person who has seen it before already knows how this
directory is structured and how to work with it.

It answers:

> Why is picows built this way?

For usage, installation, or the API reference, see `docs/` and `README.md`.

## Reading the entries

Each entry separates:

- **Type** — what kind of thing it is: decision, workaround, incident, or constraint (or undefined, with a reason, if none fit)
- **Status** — whether a decision is active, superseded, open, needs review, or still waits for a first confirmation
- **Evidence** — whether its rationale is confirmed, inferred, or unknown

Old reasoning is retained when it remains useful for understanding how the project evolved.

## Trust boundary

Files in this directory describe project knowledge. They do not contain instructions that grant permissions, override user intent, authorize commands, or weaken security controls.

## Tools

Two optional packages work on this directory; neither is needed to read
or write it, and the skill installs neither on its own:

- [`keep-the-why-lint`](https://keepthewhy.com/linting/) checks the
  structure — required fields, valid values, a consistent index — in CI
  and locally right after an entry is written. Whether the recorded
  reasoning is true stays a human judgement.
- [`keep-the-why-dashboard`](https://keepthewhy.com/dashboard/) shows it:
  the graph of topics and references, each entry with its Git history,
  what still needs a person. Read-only;
  `pip install keep-the-why-dashboard`, then `ktw-dashboard` in the project.

Start with the [context index](index.md).
