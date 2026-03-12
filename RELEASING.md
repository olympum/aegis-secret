# Releasing Aegis Secret

This document covers first-party binary releases for macOS outside the Mac App
Store.

## Release Goal

The release artifact should let users download a signed Aegis Secret app from
GitHub, install it locally, and get the same biometric-only Keychain behavior as
source installs.

## Distribution Model

Recommended v1 release format:

- notarized `Aegis Secret.app` bundled as a `.zip`
- detached checksum file such as `SHA256SUMS`
- optional helper install script for copying the app into `~/Applications` and
  registering the user-scoped MCP server

GitHub Releases is an appropriate place to host these assets. Apple is still
required for code signing and notarization.

## Manual Prerequisites

Before the first binary release, set up the following in Apple Developer:

1. A paid Apple Developer Program membership.
2. A `Developer ID Application` certificate on the release machine.
3. Notarization credentials for `notarytool`.

Optional:

4. A `Developer ID Installer` certificate if you later decide to distribute a
   signed `.pkg`.

## Manual One-Time Setup

### 1. Create a Developer ID Application certificate

Create a `Developer ID Application` certificate in Apple Developer / Xcode and
install it in the login keychain of the release machine.

### 2. Set up notarization credentials

Create a `notarytool` keychain profile or equivalent notarization credentials on
the release machine.

Suggested local config file:

```bash
mkdir -p ~/.config/aegis-secret
cat > ~/.config/aegis-secret/release.env <<'EOF'
AEGIS_SECRET_NOTARY_PROFILE="AegisSecretRelease"
EOF
```

### 3. Verify local signing

Confirm the signing identity exists:

```bash
security find-identity -v -p codesigning
```

You should see a `Developer ID Application: ...` identity for the release user.

## Release Build Steps

At release time:

1. Build the Release app:

```bash
./scripts/build-release.sh v0.1.0
```

2. Notarize and staple it:

```bash
./scripts/notarize-release.sh v0.1.0
```

3. Package release assets:

```bash
./scripts/package-release-assets.sh v0.1.0
```

4. Create a draft GitHub release:

```bash
./scripts/create-github-release.sh v0.1.0
```

Or run the full local release pipeline:

```bash
./scripts/release-binary.sh v0.1.0
```

## Verification Checklist

Before publishing a release:

- `swift test` passes.
- The app builds in Release mode.
- `aegis-secret list` works from the installed app wrapper.
- A policy-backed request completes with exactly one Touch ID prompt.
- `spctl --assess --type execute` accepts the stapled app.
- The GitHub release notes include install steps and the checksum file.

## Future Automation

Recommended follow-up automation:

- a macOS GitHub Actions workflow that runs tests on push
- a tag-driven release workflow that builds, signs, notarizes, checksums, and
  uploads release assets
- release notes generated from tags or a changelog

The repository includes:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

The release workflow expects these GitHub secrets:

- `APPLE_TEAM_ID`
- `DEVELOPER_ID_APPLICATION_P12_BASE64`
- `DEVELOPER_ID_APPLICATION_P12_PASSWORD`
- `APP_STORE_CONNECT_API_KEY_P8`
- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_API_ISSUER_ID`
- `NOTARY_APPLE_ID`
- `NOTARY_APP_SPECIFIC_PASSWORD`
