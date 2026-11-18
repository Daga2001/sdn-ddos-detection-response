# Systematic review (PRISMA 2020): search and screening record

The state of the art of the final report (section 2.3 and Appendix D) was updated with
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

## Sources (searched 2026-11-17)

| Source | Query | Records | File |
|---|---|---|---|
| OpenAlex API | `filter=title.search:DDoS,title_and_abstract.search:language model,from_publication_date:2021-01-01` | 64 | `openalex_q1_2026-11-17.csv` |
| arXiv API | `(abs:"language model" OR abs:"language models" OR abs:LLM OR abs:LLMs) AND (abs:DDoS OR abs:"denial of service") AND submittedDate:[202101010000 TO 202611172359]`, `max_results=200` | 95 | `arxiv_2026-11-17.xml` (raw), `arxiv_2026-11-17.csv` |
| Citation searching | bibliography of the approved proposal | 3 | Houssel 2024, Mehavilla 2026, Lodh 2025 |
| IEEE Xplore, Scopus | `("language model*" OR LLM*) AND (DDoS OR "denial of service")` in title/abstract/keywords, 2021–2026 | pending | to be run through the university library |

The OpenAlex query requires "DDoS" in the title because the API's title filter could
not combine synonyms; the arXiv query adds "denial of service" in the abstract.

## Counts

| Stage | n |
|---|---|
| Records identified (databases) | 159 (OpenAlex 64, arXiv 95) |
| Duplicates removed | 10 (3 inside OpenAlex, 7 arXiv records already in OpenAlex) |
| Records screened on title and abstract | 149 |
| Excluded | 115: EC1 27, EC2 74, EC3 10, EC4 4 |
| Reports sought (databases) | 34 (OpenAlex 24, arXiv 10) |
| Reports from citation searching | 3 |
| Included in the synthesis (abstract-level extraction) | 37 |
| Full-text check | pending |

The `decision` column of each CSV is `INC`, `DUP:<n>` (duplicate of record n; `OA<n>`
is OpenAlex record n), or the exclusion criterion. Decisions were made on titles and
abstracts by one reviewer; the author must check every exclusion and record
disagreements before the report is submitted.
