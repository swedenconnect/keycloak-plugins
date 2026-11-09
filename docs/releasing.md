![Sweden Connect](images/sweden-connect.png)

# Keycloak Plugins - Releasing

Maintainer documentation. Contributors do not need this; see
[CONTRIBUTING.md](../CONTRIBUTING.md) instead, which covers issues, pull requests and the
versioning policy.

Creating release tags is restricted to the maintainers.

---

## Tagging rules

Four rules, all of which exist because the tag history drifted without them:

1. **Prefix with `v`.** The tag for version `0.6.0` is `v0.6.0`. Tags without the prefix are
   historical and are not created any more.

2. **Make the tag annotated**, never lightweight, so it records who tagged it, when and why:

   ```bash
   git tag -a v0.6.0 -m "Version 0.6.0"
   ```

   A lightweight tag (`git tag v0.6.0`) is only a pointer and carries none of that.

3. **Tag a commit on `main`.** If the release is prepared on a branch, merge it first and tag the
   merged commit. A tag on a commit that never reaches `main` leaves the released artifacts with
   no reachable source, which is what happened to `v0.4.10`.

4. **Land the version bump on `main` before tagging.** The `<version>` in the POM at the tagged
   commit must equal the version being released, and `main` must not be left behind at the
   previous number.

## Never re-point or delete a release tag

Once a tag has been pushed and artifacts have been built from it, it is a permanent record of
where those artifacts came from. Do not move it to a tidier commit and do not delete it, even if
its commit is not on `main`. Reproducibility matters more than a neat history. If a tag is wrong,
release a new version.

## Release steps

The version bump, the tests and the tag are done by hand. Publishing is done by a workflow that
starts when the tag is pushed.

1. Set the release version on `main`:

   ```bash
   mvn versions:set -DnewVersion=<version> -DprocessAllModules=true -DgenerateBackupPoms=false
   ```

   Run it with `-Pparked` as well if the parked modules need to move with it.

2. Update [release-notes.md](release-notes.md): give the version its `**Date:**` and describe the
   changes. Call out anything a consumer must act on under a bold **Upgrade action required.**

3. Verify both build paths, including the integration tests, which need a running Docker daemon:

   ```bash
   mvn clean install
   mvn -Pparked verify
   ```

4. Commit, then tag the commit on `main` per the rules above, and push both:

   ```bash
   git push origin main && git push origin v<version>
   ```

   Pushing the tag triggers two workflows, which do not depend on each other:

   - [github-release.yml](../.github/workflows/github-release.yml) creates the GitHub release
     pointing at the release notes. It attaches no assets and builds nothing.
   - [maven-github-deploy.yml](../.github/workflows/maven-github-deploy.yml) builds the tagged
     commit and publishes it to GitHub Packages. See
     [Publishing to GitHub Packages](#publishing-to-github-packages).

5. Open the next development version as `<next>-SNAPSHOT` on `main`.

<a name="publishing-to-github-packages"></a>
## Publishing to GitHub Packages

Releases are published to the GitHub Packages Maven registry of this repository:

```
https://maven.pkg.github.com/swedenconnect/keycloak-plugins
```

Versions 0.7.0 and 0.7.1 were published to Maven Central and stay there. 0.7.2 is the first
version in GitHub Packages. Downloading from GitHub Packages always needs a token, also for public
packages. How consumers set that up is described in
[Using the Artifacts from GitHub Packages](github-packages.md).

### What the workflow does

1. Checks out the tag and sets up Java 21 from Temurin.
2. Checks the version, before anything is built, so that a mismatch publishes nothing. Every module
   that is published must be at the version the tag names, and that version must not be a snapshot.
3. Builds with `mvn -Prelease clean deploy -DskipTests`. The tests are not run, since they were run
   in step 3 of the release steps. A failing build or Javadoc stops the release.
4. Signs every file and deploys it with the Maven deploy plugin to the repository with the id
   `github`.

The workflow publishes with the token GitHub gives every workflow, `GITHUB_TOKEN`. The deploy job
has the permissions `contents: read` and `packages: write`, which lets that token publish packages
for this repository.

The workflow can also be started by hand from the Actions page, with a tag such as `v0.7.2` as
input. It then checks out that tag and does exactly what a pushed tag does. Use this to run a
failed publish again once the cause is fixed. A version that is already published is refused by
GitHub Packages, so delete it on the package page first if the run got that far.

### What is published

Every module of the default reactor, except `tools`, which holds example clients, and
`integration-tests`, which produces an empty jar. Both set the `skipPublishing` property to `true`.
The parked modules do the same, so that a `-Pparked -Prelease deploy` cannot push them by mistake.
The root `pom.xml` sets `maven.deploy.skip` to the value of `skipPublishing`, so the Maven deploy
plugin skips those modules. The version check in the workflow reads `skipPublishing` too.

Each published module comes with its POM, its source and javadoc jars, and a signature for every
file.

### Signing and secrets

The workflow signs with the Bouncy Castle signer of the Maven GPG plugin, chosen on the command
line with `-Dgpg.signer=bc`. It reads the key and its password from the environment, so the runner
needs no `gpg` program and no imported key. Signing from your own machine still uses `gpg`.

These are organisation secrets:

| Secret | What it holds |
|--------|---------------|
| `BOT_GPG_PRIVATE_KEY` | the private key, in ASCII armour |
| `BOT_GPG_PASSWORD` | the password for that key |

### Trying it out first

To build every file a release would upload, without signing or uploading anything:

```bash
mvn -Prelease -Dgpg.skip=true clean verify
```

### Publishing by hand

Only if the workflow cannot be used. You need:

- A classic personal access token with the `write:packages` scope, from a GitHub account that can
  write to this repository. Fine-grained tokens are not accepted by the Maven registry.
- A server with the id `github` in your `~/.m2/settings.xml`, with your GitHub user name and that
  token:

  ```xml
  <server>
    <id>github</id>
    <username>YOUR_GITHUB_USERNAME</username>
    <password>${env.GITHUB_PACKAGES_TOKEN}</password>
  </server>
  ```

- A GPG key that `gpg` can find on your machine.

Run it from the tagged commit:

```bash
git checkout v<version>
mvn -Prelease clean deploy
```

### Publishing to Maven Central again

Kept possible in case it is needed again, but not part of a normal release. The
`maven-central-release` profile in the parent POM holds the Sonatype Central publishing plugin.
Selected together with `release`, it replaces the deploy to GitHub Packages with an upload to
Central, as the server with the id `central` in `settings.xml`, and leaves out modules that set
`skipPublishing`. `autoPublish` is on, so an upload that passes validation goes live without a
manual step in the Central portal:

```bash
mvn -Prelease,maven-central-release clean deploy
```

Central is immutable. A version that has been published there cannot be altered or withdrawn.

## Versioning

The project is pre-1.0, so the minor number carries breaking changes:

- **Minor** (`0.5.0` to `0.6.0`) for anything a consumer must react to: requiring a new Keycloak
  version, removing or parking a module, or removing a provider ID.
- **Patch** (`0.6.0` to `0.6.1`) for fixes and additions that are drop-in.

**Never reuse a version number that has already been published**, even if the artifact set has
since changed. Versions on Maven Central cannot be altered or withdrawn, and a version replaced in
GitHub Packages leaves consumers with cached copies that differ from what is published.

## Parked modules

`idp-hint-oidc-provider` and `saml-session-note-mapper` are not built by the default reactor and
are not released. They live behind the `parked` profile, which keeps them compiling and keeps their
unit tests running against the targeted Keycloak version:

```bash
mvn -Pparked verify
```

Release them only once they have a new home. Until then, do not add them back to the default
`<modules>` list, and remember that a release built from the default reactor does not ship their
provider IDs.

<a name="future-work"></a>
## Future work

- **Enforcing the tagging rules.** A GitHub tag ruleset restricting who may create refs matching
  `v*` would make rule 1 and the maintainer restriction real rather than advisory.

---

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
