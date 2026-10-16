# ci-canary-tokens

**Honeytokens for CI/CD pipelines — a burglar alarm for your builds.**

The October 2026 GhostAction campaign (~1,900 compromised GitHub accounts, 30,000+ repos) worked by exfiltrating repo and org secrets through poisoned workflows. If a canary credential is sitting among your real secrets, the thief steals it too — and the moment it surfaces anywhere outside its vault, the tripwire fires and your build fails with an alert naming exactly which canary leaked.

Built by [Ingenious AI](https://github.com/Iceman2050). Zero dependencies — Python stdlib only.

## The play

1. **Generate** canary credentials and plant them as repo/org secrets — the exact place a workflow exfiltrator harvests.
2. **Commit the registry** (it holds only prefixes + SHA-256 hashes, never plaintext — safe for git).
3. **Add the tripwire** to your workflows. It scans captured logs/outputs for any registered canary prefix.
4. If a GhostAction-style exfiltration ever steals your secrets, the canary goes with them — and the **build fails loudly**, telling you which canary fired and where it was seen.

Canaries are fake: the AWS keys are shaped like real `AKIA…` key IDs (with a `CANARY` marker) so naive exfiltrators grab them, and the tokens look like ordinary API tokens.

## Install

```bash
git clone https://github.com/Iceman2050/ci-canary-tokens.git
cd ci-canary-tokens
# nothing to install — stdlib only, Python 3.9+
```

## Usage

### 1. Generate a canary

```bash
python3 src/canary.py generate --name ci-aws-canary-1 --kind aws --registry canaries.json
```

Output (shown **once** — plant it immediately as a repo/org secret, never commit it):

```
============================================================
CANARY CREDENTIAL — shown ONCE. Plant it as a repo/org secret NOW,
then never store or commit this value anywhere.
============================================================
AKIACANARYX7Q2M9Z4P1
============================================================
Registered 'ci-aws-canary-1' (aws) in canaries.json
Registry holds prefix + sha256 only — safe to commit.
```

Kinds: `aws` (fake `AKIA…` access key ID with `CANARY` marker), `token` (fake `ing_canary_…` API token).

### 2. Scan with the tripwire

```bash
python3 src/canary.py check --registry canaries.json --blob captured-workflow.log
```

### 3. Use the GitHub Action

Reference this repo's composite action from your workflow and scan anything the workflow produced (logs, artifacts, issue comments):

```yaml
- name: Capture suspicious output
  run: some-command-that-might-leak > /tmp/output.log

- name: Canary tripwire
  uses: Iceman2050/ci-canary-tokens/action@master
  with:
    registry: .github/canaries.json   # committed registry (hashes only)
    scan-path: /tmp/output.log
```

Or pass raw text:

```yaml
- name: Canary tripwire
  uses: Iceman2050/ci-canary-tokens/action@master
  with:
    registry: .github/canaries.json
    scan-text: ${{ steps.something.outputs.text }}
```

When a canary fires, the step fails with an annotation like:

```
::error::CANARY TRIPWIRE FIRED — canary 'ci-aws-canary-1' (aws) detected in /tmp/output.log. A planted CI secret was exfiltrated — investigate NOW.
```

## Example output

Clean run:

```
$ python3 src/canary.py check --registry canaries.json --blob build.log
Canary check clean — no registered canary prefixes found.
```

Fired run (exit code 1):

```
$ python3 src/canary.py check --registry canaries.json --blob exfil-dump.txt
::error::CANARY TRIPWIRE FIRED — 'ci-aws-canary-1' (aws) detected in exfil-dump.txt (prefix 'AKIACANARY'). A planted secret leaked!
```

## Security notes

- The registry contains **no plaintext** — only canary names, prefixes, and SHA-256 hashes. Commit it freely.
- Canaries are **not** real credentials; they can't grant access to anything. Their only job is to be stolen and then scream.
- Rotate canaries periodically (`generate` a fresh one, remove the old entry) so a fired-then-silenced canary can't be reused against you.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 10 tests: generator format validity,
                                            # uniqueness, registry holds no plaintext,
                                            # exfil blob fires (names the canary),
                                            # clean blob stays clean, CLI exit codes
```

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

This project is part of the **Ingenious AI** platform suite — defensive security tooling for the AI era. Our platforms are currently in early access (full launch Nov 1) — request access to any of them on WhatsApp:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)
