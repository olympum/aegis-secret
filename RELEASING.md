# Releasing Aegis Secret

This document covers first-party binary releases for macOS outside the Mac App
Store.

## Release Goal

The release artifact should let users download a signed Aegis Secret app from
GitHub, install it locally, and get the same biometric-only Keychain behavior as
source installs.

## Distribution Model

Recommended v1 release format:

- notarized `Aegis Secret-<version>-installer.pkg`
- detached checksum file such as `SHA256SUMS`
- signed installer that places the app in `/Applications` and PATH shims in
  `/usr/local/bin`

GitHub Releases is an appropriate place to host these assets. Apple is still
required for code signing and notarization.

## Manual Prerequisites

Before the first binary release, set up the following in Apple Developer:

1. A paid Apple Developer Program membership.
2. A `Developer ID Application` certificate on the release machine.
3. A `Developer ID Installer` certificate on the release machine.
4. Notarization credentials for `notarytool`.
5. A `Developer ID` provisioning profile for `com.olympum.aegis-secret`.

Optional:

6. A custom installer background / resources bundle if you later decide to
   brand the package UI.

## Manual One-Time Setup

### 1. Create a Developer ID Application certificate

Create a `Developer ID Application` certificate in Apple Developer / Xcode and
install it in the login keychain of the release machine.

### 2. Create a Developer ID Installer certificate

Create a `Developer ID Installer` certificate in Apple Developer / Xcode and
install it in the login keychain of the release machine.

### 3. Set up notarization credentials

Create a `notarytool` keychain profile or equivalent notarization credentials on
the release machine.

Suggested local config file:

```bash
mkdir -p ~/.config/aegis-secret
cat > ~/.config/aegis-secret/release.env <<'EOF'
AEGIS_SECRET_NOTARY_PROFILE="AegisSecretRelease"
EOF
```

### 4. Verify local signing

Confirm the signing identity exists:

```bash
security find-identity -v -p codesigning
```

You should see a `Developer ID Application: ...` identity for the release user.

### 5. Create a Developer ID provisioning profile

Because Aegis Secret uses Keychain sharing, the release build needs a
Developer ID provisioning profile in addition to the certificate.

Create an explicit App ID for `com.olympum.aegis-secret`, enable Keychain
Sharing for that App ID, and create a `Developer ID` provisioning profile that
uses your `Developer ID Application` certificate.

For GitHub Actions, add that profile as a repository secret:

- `DEVELOPER_ID_PROVISIONING_PROFILE_BASE64`

Populate it with:

```bash
base64 -i /absolute/path/to/AegisSecretDeveloperID.provisionprofile \
  | gh secret set DEVELOPER_ID_PROVISIONING_PROFILE_BASE64 --repo olympum/aegis-secret
```

## Release Build Steps

At release time:

1. Build the Release app:

```bash
./scripts/build-release.sh v0.1.0
```

2. Notarize and staple the app bundle:

```bash
./scripts/notarize-release.sh v0.1.0
```

3. Package the signed installer:

```bash
./scripts/package-release-assets.sh v0.1.0
```

4. Notarize and staple the installer package:

```bash
./scripts/notarize-pkg.sh v0.1.0
```

5. Create a draft GitHub release:

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
- `spctl --assess --type install` accepts the stapled package.
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
- `DEVELOPER_ID_INSTALLER_P12_BASE64`
- `DEVELOPER_ID_INSTALLER_P12_PASSWORD`
- `DEVELOPER_ID_PROVISIONING_PROFILE_BASE64`
- `APP_STORE_CONNECT_API_KEY_P8`
- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_API_ISSUER_ID`
- `NOTARY_APPLE_ID`
- `NOTARY_APP_SPECIFIC_PASSWORD`
