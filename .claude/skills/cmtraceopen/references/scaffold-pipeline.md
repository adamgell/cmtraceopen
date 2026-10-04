# Scaffold-tier delegation

How to hand fixture matrices, test boilerplate, and doc skeletons to a low-cost
scaffold-tier model (tiers are in `soul.md`) without letting it invent log formats.
Two pilot runs in August 2026 set the bar: scaffold output without real anchors was
grammar-unsafe (graded B+); the same work anchored to real exemplars was repo-correct
(graded A-).

## Hard rules

A violation invalidates the pull request.

1. **Never synthesize log lines from nothing.** Every fixture brief embeds two or three
   real exemplar lines from the repo corpus or a lab capture. The model may transform
   or extend real captures only.
2. **Conservative parse stance.** Malformed timestamps and values parse without a
   fabricated offset; never assert rejection. (#406, #410, #414)
3. **Evidence bar.** Findings cite exact artifacts, severity and confidence, and the
   smallest missing evidence bundle. No timestamp-proximity root causes.
4. **Mark guesses.** Put `// GUESSED` on every assumption about the parser API surface.

## Take the grammar from the target family

The CCM wrapper and attribute order are fixed:

```text
<![LOG[message]LOG]!><time="..." date="..." component="..." context="" type="N" thread="N" file="">
```

The `time`, `date`, and `type` values are not. The parser fixtures contain
milliseconds with a signed minute offset (`time="00:00:00.000+000"`), seven fractional
digits with no offset (`time="09:00:01.0000000"`), and seven digits with an offset
(`time="10:15:22.0000000+060"`). Dates appear both unpadded (`date="3-12-2026"`) and
zero-padded (`date="07-31-2026"`). The meaning of `type` differs by family. That
fractional-and-offset tail is ambiguous and positional heuristics have mis-split it
(#406), so a single grammar copied into every brief is wrong for most families.

Before writing a brief, pull exemplars from the target family and copy their exact
shape. To see the shapes currently in the corpus:

```bash
git grep -hoE 'time="[^"]*" date="[^"]*"' -- 'crates/cmtraceopen-parser/tests/fixtures/**' \
  | sed -E 's/[0-9]/9/g' | sort | uniq -c | sort -rn
```

## Anchor sourcing

Fixtures live under `crates/cmtraceopen-parser/tests/fixtures/`, grouped by family
(`intune/`, `sccm/`, and so on). Find a family's logs and read their first lines:

```bash
git ls-files 'crates/cmtraceopen-parser/tests/fixtures/sccm/**/*.log' | head
head -5 <path-from-the-list>
```

Without a checkout, `gh api` reads the same files:

```bash
gh api 'repos/adamgell/cmtraceopen/git/trees/main?recursive=1' \
  --jq '.tree[] | select(.path | test("(?i)FAMILY.*(log|txt)$")) | .path'
gh api 'repos/adamgell/cmtraceopen/contents/PATH' --jq '.content' | base64 -d | head -5
```

## Grading rubric

Grade every run before it becomes a pull request.

- **Grammar:** wrappers, attribute order, date padding, time precision, and offset all
  match the target family's exemplars.
- **Stance:** malformed input parses conservatively with no fabricated offsets.
- **Spec fidelity:** byte and line budgets hold. Check with `wc -c`; one pilot model
  turned a 10 KB spec into 71 KB.
- **Realism:** rotation headers and error lines match the real family, not plausible
  inventions.
- **Review:** CodeRabbit findings are triaged. Use the reasoning tier only for
  escalations and contract design.

## Pitfalls

- Scaffold models reproduce a wrong brief faithfully. A wrong date format in the brief
  comes back in every line. Verify the brief before the run, not only the output.
- A new model, including a locally hosted one, joins the scaffold pool only after it
  passes this rubric on a pilot task.
