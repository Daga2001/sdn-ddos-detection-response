# Systematic review (PRISMA 2020): search and screening record

The state of the art of the final report (section 2.3) was updated with
a review that follows the PRISMA 2020 statement (Page et al., BMJ 2021;372:n71). This
folder keeps what is needed to check or repeat it.

## Question and criteria

How are language models used in the detection of, and response to, network DoS/DDoS
attacks; where are they evaluated; against which baselines; at what cost per decision;
and do they act on the network?

* PICOS: networks under DoS/DDoS; a language model in the detection or response
  decision; any comparison; detection quality, time, cost or service; primary studies
  with an experiment.
* Inclusion: 2021-01-01 to 2026-11-17; English; peer-reviewed journal or conference
  paper, or an arXiv preprint; primary study meeting PICOS.
* Exclusion: **EC1** no language model in the decision (it only selects features,
  translates explanations, or is the protected workload); **EC2** not network DoS/DDoS
  (e.g. DoS *against* LLM services); **EC3** review, survey or overview without its own
  experiment; **EC4** not peer reviewed and not in arXiv (Zenodo, SSRN, Research Square,
  Figshare, theses).
* Eligibility: a report whose abstract and full text could not be obtained is excluded,
  because no data can be extracted from it (`EL:no-abstract-or-full-text`).

## Sources (searched 2026-11-17)

| Source | Query | Records | File |
|---|---|---|---|
| OpenAlex API | `filter=title.search:DDoS,title_and_abstract.search:language model,from_publication_date:2021-01-01` | 64 | `openalex_q1_2026-11-17.csv` |
| arXiv API | `(abs:"language model" OR abs:"language models" OR abs:LLM OR abs:LLMs) AND (abs:DDoS OR abs:"denial of service") AND submittedDate:[202101010000 TO 202611172359]`, `max_results=200` | 95 | `arxiv_2026-11-17.xml` (raw), `arxiv_2026-11-17.csv` |
| Citation searching | bibliography of the approved proposal | 3 | Houssel 2024, Mehavilla 2026, Lodh 2025 |

The OpenAlex query requires "DDoS" in the title because the API's title filter could
not combine synonyms; the arXiv query adds "denial of service" in the abstract.

## Counts

| Stage | n |
|---|---|
| Records identified (databases) | 159 (OpenAlex 64, arXiv 95) |
| Duplicates removed | 10 (3 inside OpenAlex, 7 arXiv records already in OpenAlex) |
| Records screened on title and abstract | 149 |
| Excluded | 115: EC1 27, EC2 74, EC3 10, EC4 4 |
| Reports assessed for eligibility (databases) | 34 (OpenAlex 24, arXiv 10) |
| Reports from citation searching | 3 |
| Excluded at eligibility | 4 (no abstract or full text available) |
| Included in the synthesis | 33 |

The `decision` column of each CSV is `INC`, `DUP:<n>` (duplicate of record n; `OA<n>`
is OpenAlex record n), the exclusion criterion, or `EL:no-abstract-or-full-text` for a
report excluded at eligibility. Decisions were made on titles and
abstracts by one reviewer. Eligibility was decided on the same title and abstract, and
on the full text where it was openly available. The extracted data come from the
abstracts; values read in the full text are marked with an asterisk in Table 2.2 of
the report. The review used these two databases and citation searching only.

## Change of 24 November 2026

Four OpenAlex records first included without data (marked FT in the report: OpenAlex
records 3, 28, 41 and 61, DOIs 10.1117/12.3112369, 10.1007/978-3-032-15404-0_2,
10.1007/978-3-032-04312-2_7 and 10.1007/s11334-026-00660-6) have no abstract in OpenAlex
and no openly available full text, so no data could be extracted from them. They are now
excluded at eligibility, and the synthesis has 33 reports (7 of them in an SDN). The
version before this change is kept in `docs/archive/prisma-2026-11-17/`.
