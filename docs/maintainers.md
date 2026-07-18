# Maintainer checklist

## Repository settings

Protect `main` in GitHub with these minimum rules:

- require a pull request before merging;
- require the **CI / test** status check;
- require at least one approving review for external contributions;
- require branches to be up to date before merge; and
- restrict direct pushes and force pushes.

Enable GitHub's private vulnerability reporting and Actions **Read and write**
workflow permissions. Review third-party Actions before allowing them in the
organization or repository.

## Pull requests

Verify that the PR template is complete, CI passes, tests cover safety
boundaries, public documentation is correct, and scope/policy/audit changes
received a security-focused review. Do not merge secrets or raw production
diagnostics.

## Publishing a release

1. Update `VERSION` to the next semantic version in the release pull request.
2. Merge the intended work into `main`.
3. Confirm the generated release contains both architecture packages, `SHA256SUMS`,
   all Minisign signatures, and provenance attestations.
4. Test the one-line installer on a disposable CloudPanel VM before announcing
   it.

The workflow rejects non-`main` refs and existing version tags. A release is
an explicit version bump, not an automatic side effect of every merge.
