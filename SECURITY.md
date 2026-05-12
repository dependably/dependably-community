# Security Policy

To report a security vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/dependably/dependably-community/security/advisories/new).

Do not open a public issue for security vulnerabilities.

## Leaked credentials

If the secret-scan CI job fails, or a credential is otherwise found in this repository's source or history, treat it as compromised regardless of where it was committed from. Run the response below in order — do not stop at "remove from repo".

1. **Revoke at the provider.** Disable or delete the credential in the issuing system (cloud console, package registry, identity provider, etc.) before doing anything else. A scrubbed git history does not invalidate a leaked token.
2. **Remove from the repo.** Delete the secret from the working tree. If it landed on a long-lived branch or in history, rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push, then have collaborators re-clone.
3. **Rotate and redeploy.** Issue a replacement, update every consumer (deployments, CI variables, local `.env` files), and roll any dependent services that cached the old value.
4. **Notify affected systems and people.** Anything that authenticated with the old credential, plus the maintainer team and — for production credentials — downstream operators.
5. **Owner.** The repo maintainer drives steps 1–4. Page them via the channel listed at the top of this document.

