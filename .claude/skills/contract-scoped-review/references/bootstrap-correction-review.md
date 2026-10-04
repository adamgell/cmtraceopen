# Bootstrap correction review pattern

A narrow bootstrap correction can be technically correct yet still fail the contract if it carries unrelated edits. In the reviewed case, the authorized change was correcting repository-root raw GitHub paths in collection README examples. The proposed commit also changed a changelog link, Scoop version examples, and unrelated DNS collector wording. Those additions were out of scope.

## Review checks

- Confirm the executable's real repository-relative path.
- Check every duplicated documentation example that is explicitly in scope.
- Enumerate all changed files and classify each as required or incidental.
- Reject changelog, packaging/version, cleanup, and unrelated documentation edits unless the contract explicitly includes them.
- Give only the disposition and exact minimal correction when requested.
