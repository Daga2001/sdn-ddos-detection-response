# Archive: superseded documents

Copies of documents whose figures were later corrected. They are kept unchanged so that
earlier versions of the thesis and of the repository can be audited. Cite the current
documents, not these copies.

| Copy | Replaced on | What changed in the current document |
| --- | --- | --- |
| `detection-modes-2026-11-19.md` | 22 Nov 2026 | Development figures recomputed from the run records, with the run identifier of each (first 8 characters of the identifier in the laboratory database). |

Changes in `docs/detection-modes.md` on 22 Nov 2026:

- Verdict cache: the 97 s run (36 s without the cache, 2 s with it, 723 cached answers and
  127 real calls) could not be matched to a recorded run. It was replaced by the figures of
  the 40 held-out LLM runs: a median of 235 ms per model call, about 98 % of the judgments
  answered from the cache.
- Asynchronous judging: recovery 81-90 % became 85-95 % (runs `188dacab`, `e70ed097`).
- ICMP flood: "in 135 s" and "no false positive" were not recomputed and were removed.
- Polling table, 5 s row: +11 s / +14 s / 100 / 26-37 / 80 % became +8.9 to +11.2 s /
  +14.3 to +14.8 s / 100 / 25-45 / 89-100 % (runs `d05fb1c0`, `7e030f9f`, `9c7f0b08`).
- 8 attackers, LLM at 5 s polling: 100 / 3 / 50 % became 100 / 3 / 53 % (run `29b0d160`).
- Never naming the victim: "13 university runs, web server blocked in 2" could be matched
  to only one run (`c15d163d`); the text now describes that run.
