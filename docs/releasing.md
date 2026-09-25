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

Releases are currently cut by hand. Publishing automatically from a tag, once the build and tests
pass, is planned; see [Future work](#future-work).

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

   Pushing the tag triggers
   [github-release.yml](../.github/workflows/github-release.yml), which creates the GitHub release
   pointing at the release notes. It attaches no assets and builds nothing.

5. Publish to Maven Central from the tagged commit:

   ```bash
   mvn -Prelease clean deploy
   ```

   See [Publishing to Maven Central](#publishing-to-maven-central) for what the profile does and
   what has to be in place first.

6. Open the next development version as `<next>-SNAPSHOT` on `main`.

<a name="publishing-to-maven-central"></a>
## Publishing to Maven Central

The `release` profile in the parent POM attaches the sources and javadoc jars Central requires,
signs every artifact with GPG, and uploads the bundle through the Sonatype Central publishing
plugin. `autoPublish` is on, so a bundle that passes validation goes live without a manual step in
the Central portal.

Two things must be set up on the machine doing the release:

1. **A Central portal token**, as a server with id `central` in `~/.m2/settings.xml`:

   ```xml
   <server>
     <id>central</id>
     <username><!-- token username --></username>
     <password><!-- token password --></password>
   </server>
   ```

2. **A published GPG key.** The key must be available to `gpg` on the machine and its public half
   uploaded to a keyserver Central checks, otherwise validation rejects the bundle.

Not everything in the reactor is published. `tools` holds example clients and `integration-tests`
produces an empty jar, so both set `maven.deploy.skip`. The parked modules do the same, so that a
`-Pparked -Prelease deploy` cannot push them by mistake.

Central is immutable. A version that has been published cannot be altered or withdrawn, so verify
the build before running `deploy`:

```bash
mvn -Prelease -Dgpg.skip=true clean verify
```

## Versioning

The project is pre-1.0, so the minor number carries breaking changes:

- **Minor** (`0.5.0` to `0.6.0`) for anything a consumer must react to: requiring a new Keycloak
  version, removing or parking a module, or removing a provider ID.
- **Patch** (`0.6.0` to `0.6.1`) for fixes and additions that are drop-in.

**Never reuse a version number that has already been published**, even if the artifact set has
since changed. Maven Central is immutable: a version cannot be altered or withdrawn once it is up,
so two different artifact sets sharing one set of coordinates is a permanent inconsistency.

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

- **Publishing to Central from a tag.** The `v*` tag already creates the GitHub release. A second
  workflow on the same trigger could run the build and tests and publish to Central only on
  success, replacing the manual `deploy` step above. It needs the Central token and the signing
  key as repository secrets.

- **Enforcing the tagging rules.** A GitHub tag ruleset restricting who may create refs matching
  `v*` would make rule 1 and the maintainer restriction real rather than advisory.

---

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for
Digital Government (DIGG)](https://www.digg.se). Licensed under version 2.0 of the
[Apache License](https://www.apache.org/licenses/LICENSE-2.0).
