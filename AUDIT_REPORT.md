# Publication audit and validation

## Scope and preservation

Audited every byte of all 60 original publication candidates recursively: Python,
Markdown, CSV, JSON, raw flow/attack captures and logs. Included text was checked
for personal paths/names, account/contact data, credentials, private keys and
non-project IPv4 addresses. JSON metadata and benchmark consistency were examined
separately. No credentials, personal contact/student identifiers or unrelated
network addresses were detected. Automated pattern checks cannot guarantee the
absence of every possible secret; review the manifest before publication.

Retained all 14 Python source/test files, four original Markdown documents,
`block_response.csv`, and all 41 files in `benchmark-results.GHxubQ/`. This
includes all six identical comparison exports and historical logs useful as
experimental evidence. Simulated addresses, ports, measurement timestamps,
flow cookies and iperf session cookies are technical evidence and retained.
No Python source was edited; retained numerical experimental data is unchanged.

Excluded `.venv/` (including installed packages and machine-specific launchers),
all `__pycache__/` and bytecode, and local `.git/`, `.agents/`, `.aws/`, `.codex/`
directories. The four hidden local directories were empty at audit time.
No runtime database was present among original publication candidates.
The `.git` directory had no repository metadata; Git reported no repository,
so no tracked files, remotes or commit history were available to inspect.
No existing history was changed or copied. No repository or commits were created
in this deliverable, and nothing was pushed or published.

## Sanitization and documentation

- Two benchmark `settings.json` files: replaced original personal absolute
  response paths with project-relative paths. Static response metadata names a
  file absent from the supplied snapshot; static mode creates no BLOCK samples.
- Nine `*-iperf.json` files: replaced the original machine hostname in
  `start.system_info` with `benchmark-host`; retained OS/kernel context and all
  other JSON fields and numerical values.
- `IMPLEMENTATION_GUIDE.md`: corrected references to absent DOCX/PDF originals
  and directed fresh checkouts to virtual-environment setup.
- `PROJECT_COMPATIBILITY.md`: added a historical-context notice to distinguish
  the early integration contract from completed behavior.
- Added `README.md`, `.gitignore`, controller-only `requirements.txt`, this
  report, `GITHUB_SETUP.md` and `PUBLICATION_MANIFEST.sha256`.

The installed controller dependency and actual imports support the single direct
pip requirement `os-ken==3.1.1`. Mininet, Open vSwitch and iperf3 are Linux system
packages. The application and security modules use the standard library.

## Validation performed

- All 14 Python files parsed successfully and are byte-identical to originals.
- All 14 existing unit tests passed: 10 policy and 4 TCP/SQLite logger tests.
  Socket tests initially hit sandbox restrictions; they passed after execution
  with the required permission to create an ephemeral loopback listener.
- Clean topology, benchmark, application and security module imports passed
  using system Python. Clean controller imports passed using the original
  installed OS-Ken environment; no service or switch was launched.
- Recomputed all saved summaries using the supplied benchmark summarizer.
  Each of static, dynamic and recovered has 90 successful RTT samples and three
  throughput trials. All statuses match PASS. All nine raw iperf receiver rates
  agree with measurement rows; three dynamic response times match their cookies
  in `dynamic-response.csv`. Six attack batches contain three timeouts each;
  saved source-block flow evidence agrees with each condition.
- Verified all six comparison exports against per-run summaries. Compared every
  raw JSON field with the original, allowing only the documented metadata edits.
  Every other original benchmark file is byte-identical.
- Scanned all retained/added text for personal paths, known original identifiers,
  emails, credential/private-key patterns and non-project IPv4 addresses.
- Reviewed exact publication candidates with Git's ignore engine using a
  temporary external Git directory. No clean-copy repository was initialized,
  no files staged, and no author identity selected. Confirmed runtime databases,
  virtual environments, caches, private local configuration and new experiment
  folders are ignored while every retained evidence file, including logs, is
  eligible for publication.
- ZIP checked for integrity, exact file list and byte equality with the clean
  directory. ZIP stores ordinary portable file permissions and no original user
  ownership, Git directory, virtual environment or runtime database.
- Verified original publication file hashes remained unchanged after preparation.

## Verification limits and manual review

No fresh package installation, full Mininet/controller live integration, new
performance benchmark, or cross-machine test was performed. Full controller
imports use the existing dependency environment, not a newly installed one.
OS-Ken's installed Eventlet dependency emits a deprecation warning; architecture
and dependencies were intentionally preserved. Earlier integration claims remain
attributed to supplied evidence, not a new live test.

The benchmark helper resolves new output paths, and iperf embeds a hostname in
new results. Audit newly generated evidence before publishing. `.gitignore`
preserves the supplied root `block_response.csv`; use a fresh demo output path
to avoid appending new measurements to that historical file.

Before committing, review this directory and choose each contributor's own Git
name, email (GitHub noreply if desired), repository URL and licensing terms.
No license was invented. See `GITHUB_SETUP.md` for independent repository commands.
The SHA-256 manifest lists all deliverable files except itself; paths are relative
to this directory and contain no original absolute machine paths.

## Modified original files

- `IMPLEMENTATION_GUIDE.md`
- `PROJECT_COMPATIBILITY.md`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/dynamic-1-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/dynamic-2-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/dynamic-3-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/recovered-1-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/recovered-2-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/recovered-3-iperf.json`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/settings.json`
- `benchmark-results.GHxubQ/static-ea16e937ce/settings.json`
- `benchmark-results.GHxubQ/static-ea16e937ce/static-1-iperf.json`
- `benchmark-results.GHxubQ/static-ea16e937ce/static-2-iperf.json`
- `benchmark-results.GHxubQ/static-ea16e937ce/static-3-iperf.json`
