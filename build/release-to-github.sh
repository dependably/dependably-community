#!/usr/bin/env bash
# Mirror the current GitLab release tag to GitHub as a single squash commit
# plus a matching annotated tag, and emit SLSA-L2-style provenance.json.
# Invoked by the `release-to-github` job in .gitlab-ci.yml on every `vX.Y.Z`
# tag push. CI owns tag identity (validate-release-tag); this script owns
# publishing only.
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set (masked CI/CD variable)}"
: "${CI_COMMIT_TAG:?CI_COMMIT_TAG must be set (job only fires on tag pipelines)}"
: "${CI_COMMIT_SHA:?CI_COMMIT_SHA must be set}"

EXPECTED_REPO="dependably/dependably-community"
TAG="$CI_COMMIT_TAG"
VERSION="${TAG#v}"

echo "Mirroring release $TAG (version $VERSION) to GitHub"

git config user.email "ci@dependably"
git config user.name  "Dependably Release Bot"

# Configure the GitHub remote without embedding the token in the URL (which would
# appear in process listings and git's own remote-tracking ref storage). The token
# is passed as an HTTP Authorization header via git's extraHeader config instead.
git remote remove github 2>/dev/null || true
git remote add github "https://github.com/${EXPECTED_REPO}.git"
AUTH_HEADER="AUTHORIZATION: basic $(printf 'oauth2:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')"

# Paranoia: confirm the remote URL still matches the expected repo slug.
# This guards against a misconfigured CI variable swapping the destination
# repo — something validate-release-tag (which runs before auth) can't see.
ACTUAL_URL=$(git remote get-url github)
case "$ACTUAL_URL" in
  *"${EXPECTED_REPO}.git") ;;
  *) echo "ERROR: github remote does not point at ${EXPECTED_REPO}" >&2; exit 1 ;;
esac

# Pull all vX.Y.Z tag refs so the best-effort BASELINE_TAG lookup below
# can resolve a known SHA to a release tag (used only in provenance.json).
# GitLab Runner's default fetch only brings the tag being built.
git fetch origin --tags --force --quiet

# Fetch GitHub main; absence means a true first-ever release into an empty
# repository. The GH HEAD's GitLab-Source trailer is the deterministic
# baseline anchor — see baseline resolution below.
GH_HEAD=""
if git -c "http.extraHeader=$AUTH_HEADER" fetch --no-tags github main 2>/dev/null; then
  GH_HEAD=$(git rev-parse FETCH_HEAD)
  echo "GitHub main HEAD: $GH_HEAD"
else
  echo "GitHub main does not exist (bootstrap target)"
fi

# Resolve the squash baseline.
#
# GitHub's history is the source of truth for "what was previously
# published" — each prior mirror commit carries a GitLab-Source trailer
# pointing at the GitLab commit it was built from. That trailer chain is
# the deterministic anchor across release runs.
#
# `git describe` is NOT used: this repo places release tags on feature
# branches that are squash/merge-folded into main, so prior vX.Y.Z tags
# are not ancestors of the current tag and `git describe` cannot reach
# them. See plan §4.
#
# Bootstrap fallback: if GH HEAD has no trailer (pre-mirror state seeded
# by an out-of-band manual push), accept GH HEAD's own SHA as baseline iff
# it identifies a real commit in this GitLab repo.
FIRST_RELEASE=0
BASELINE_SHA=""
BASELINE_TAG=""
if [ -z "$GH_HEAD" ]; then
  FIRST_RELEASE=1
  echo "First-ever release: no prior GitHub history"
else
  BASELINE_SHA=$(git show -s --format='%(trailers:key=GitLab-Source,valueonly,separator=)' "$GH_HEAD" \
    | tr -d '\n')
  if [ -n "$BASELINE_SHA" ]; then
    echo "Baseline from GH HEAD trailer: $BASELINE_SHA"
  else
    BASELINE_SHA="$GH_HEAD"
    echo "Bootstrap: GH HEAD has no trailer, using its SHA as baseline ($BASELINE_SHA)"
  fi
  git cat-file -e "${BASELINE_SHA}^{commit}" 2>/dev/null \
    || { echo "ERROR: baseline $BASELINE_SHA is not a known commit in this GitLab repo" >&2; exit 1; }
  # Best-effort tag lookup for provenance.json; empty when baseline is a
  # squashed mirror commit or an untagged manual-sync commit.
  BASELINE_TAG=$(git tag --points-at "$BASELINE_SHA" 2>/dev/null \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
fi

# Replayability anchor for provenance: SHAs of the commits this release
# introduces vs the prior baseline, sorted before hashing so the digest
# depends only on the commit set — independent of git rev-list traversal
# order. --first-parent matches the squash model on a push-to-main history
# (no-op when no merges exist; if a merge commit is present, side-branch
# commits are already folded into the merge's tree).
#
# When BASELINE_SHA is on a divergent lineage (e.g. an orphan release-tag
# commit), `git rev-list A..B` still emits everything reachable from B but
# not A — deterministic, and faithfully captures "what this release adds
# on top of what's currently published."
FINAL_TREE=$(git rev-parse "${CI_COMMIT_SHA}^{tree}")
if [ "$FIRST_RELEASE" = "1" ]; then
  COMMIT_SET_DIGEST=$(git rev-list --first-parent "$CI_COMMIT_SHA"                    | sort | sha256sum | awk '{print $1}')
else
  COMMIT_SET_DIGEST=$(git rev-list --first-parent "${BASELINE_SHA}..${CI_COMMIT_SHA}" | sort | sha256sum | awk '{print $1}')
fi

# Build the squash commit out-of-tree against the tagged commit's tree.
MSG_FILE=$(mktemp)
trap 'rm -f "$MSG_FILE"' EXIT
{
  printf 'chore(release): %s\n\n' "$VERSION"
  printf 'GitLab-Source: %s\n' "$CI_COMMIT_SHA"
} > "$MSG_FILE"

if [ -n "$GH_HEAD" ]; then
  SQUASH_SHA=$(git commit-tree "$FINAL_TREE" -p "$GH_HEAD" -F "$MSG_FILE")
else
  SQUASH_SHA=$(git commit-tree "$FINAL_TREE" -F "$MSG_FILE")
fi
echo "Squash commit: $SQUASH_SHA"

# Defence-in-depth: the squash tree MUST equal the tagged tree. commit-tree
# above builds off $FINAL_TREE, so inequality means the script was tampered
# with mid-flight.
SQUASH_TREE=$(git rev-parse "${SQUASH_SHA}^{tree}")
if [ "$SQUASH_TREE" != "$FINAL_TREE" ]; then
  echo "ERROR: squash tree $SQUASH_TREE != tagged tree $FINAL_TREE" >&2
  exit 1
fi

# Annotated tag (not lightweight) for clean GitHub Releases UX.
# -f overwrites the local tag that the runner's checkout brought in for
# $CI_COMMIT_TAG; we're repointing it from the GitLab commit to the GH
# squash commit so the subsequent push targets the right object. Safe in
# CI: the runner is ephemeral and validate-release-tag has already
# validated the original tag's identity in a prior stage.
git tag -af "$TAG" "$SQUASH_SHA" -m "$TAG"

# Atomic push of branch + tag together. Atomic is the protocol-level guard
# against a split-state outcome; the ls-remote below is the verification
# that catches any residual partial-push / auth-failure case.
git -c "http.extraHeader=$AUTH_HEADER" push --atomic github "$SQUASH_SHA:refs/heads/main" "refs/tags/$TAG"

# Post-push verification — identity is asserted by provenance.json (below);
# this only catches silent partial-push / auth failures.
git -c "http.extraHeader=$AUTH_HEADER" ls-remote --exit-code github "refs/tags/${TAG}" >/dev/null \
  || { echo "ERROR: post-push: tag ${TAG} not visible on GitHub" >&2; exit 1; }

echo "Mirror complete: $TAG -> github/main"

# SLSA-L2-style provenance. Written only after both push and ls-remote
# succeed. source.final_tree and artifact.squash_tree MUST be equal (asserted
# above); inequality means the script was tampered with mid-flight.
CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > provenance.json <<EOF
{
  "version": "SLSA-L2-style",
  "source": {
    "gitlab_sha":        "${CI_COMMIT_SHA}",
    "tag":               "${TAG}",
    "commit_set_digest": "${COMMIT_SET_DIGEST}",
    "final_tree":        "${FINAL_TREE}",
    "baseline_tag":      "${BASELINE_TAG}",
    "baseline_sha":      "${BASELINE_SHA}"
  },
  "artifact": {
    "squash_sha":  "${SQUASH_SHA}",
    "squash_tree": "${FINAL_TREE}",
    "github_repo": "${EXPECTED_REPO}",
    "github_tag":  "${TAG}"
  },
  "builder": {
    "id":           "gitlab://${CI_PROJECT_PATH:-unknown}",
    "system":       "gitlab",
    "pipeline_id":  "${CI_PIPELINE_ID:-}",
    "pipeline_url": "${CI_PIPELINE_URL:-}",
    "job_id":       "${CI_JOB_ID:-}",
    "job_url":      "${CI_JOB_URL:-}",
    "runner":       "${CI_RUNNER_DESCRIPTION:-unknown}",
    "runner_id":    "${CI_RUNNER_ID:-}"
  },
  "created_at": "${CREATED_AT}"
}
EOF

echo "Provenance written: provenance.json"
