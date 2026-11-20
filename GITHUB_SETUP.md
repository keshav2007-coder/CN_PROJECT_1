# Create independent GitHub repositories

Run these commands yourself after approving the cleaned files and selecting your
own Git author identity. Replace the quoted placeholders before use. Create an
empty GitHub repository in your own account first, without an initial README,
license or `.gitignore`. No GitHub CLI is required.

## Your copy

Open a terminal inside `CN_git_clean`, then run:

```bash
git init -b main
git config --local user.name "YOUR_APPROVED_GIT_NAME"
git config --local user.email "YOUR_APPROVED_GIT_EMAIL"
git add .
git diff --cached --name-status
git -c core.whitespace=cr-at-eol,-blank-at-eol diff --cached --check
git diff --cached
```

Only after reviewing the staged files and confirming that identity:

```bash
git commit -m "Initial project release"
git remote add origin https://github.com/YOUR_ACCOUNT/YOUR_REPOSITORY.git
git push -u origin main
```

## Teammate's independent copy

In a directory that does not already contain `CN_git_clean`, extract the ZIP:

```bash
unzip CN_git_clean.zip
cd CN_git_clean
sha256sum -c PUBLICATION_MANIFEST.sha256
git init -b main
git config --local user.name "TEAMMATE_APPROVED_GIT_NAME"
git config --local user.email "TEAMMATE_APPROVED_GIT_EMAIL"
git add .
git diff --cached --name-status
git -c core.whitespace=cr-at-eol,-blank-at-eol diff --cached --check
git diff --cached
```

After reviewing the staged files and confirming the teammate's identity:

```bash
git commit -m "Initial project release"
git remote add origin https://github.com/TEAMMATE_ACCOUNT/TEAMMATE_REPOSITORY.git
git push -u origin main
```

The published Python files retain their original mixed line endings, and saved
iperf server logs contain padding spaces. The per-command Git whitespace option
above suppresses those known, harmless formatting warnings without modifying
source code, changing benchmark evidence or weakening checks for other types
of whitespace problems. You can still review the complete staged diff normally.

Each `git init` creates a new history. The ZIP contains no `.git` directory,
author configuration or commit metadata. Do not share a copy after adding `.git`;
share the supplied clean ZIP. Authenticate through your normal GitHub method;
do not put access tokens or passwords into files or remote URLs.
