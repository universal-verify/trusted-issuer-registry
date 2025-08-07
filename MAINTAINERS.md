# Maintainers Guide

This document outlines the processes for releasing patches and minor versions of the Trusted Issuer Registry, including handling the deprecation lifecycle.

## Release Process Overview

The Trusted Issuer Registry follows semantic versioning with the following release types:

- **Patches** (0.0.x): Bug fixes and issuer updates within the same minor version
- **Minor versions** (0.x.0): Schema changes, breaking updates, and new signing keys

## Patch Releases

Patch releases are for issuer updates and bug fixes within the same minor version.

### Steps for Patch Release

1. **Update issuer files** (if applicable)
   - Add, remove, or modify issuer entries in the `issuers/` directory
   - Ensure all issuer files follow the schema in `trusted-issuer.schema.json`

2. **Sign issuer files** (skip if no updates to issuer files were made)
   - Go to GitHub Actions → "Sign issuer files" workflow
   - Click "Run workflow" and select the appropriate branch:
     - For current minor version: use `dev` branch
     - For previous minor versions: use `release/{major}.{minor}` branch
   - Wait for the automated PR to be created
   - Review and merge the PR

3. **Update version**
   - Update the version in `package.json`
   - Example: `"version": "0.0.7"`

4. **Update build files**
   ```bash
   npm run build
   ```

6. **Commit changes**
   ```bash
   git add ./
   git commit 0.0.7
   ```

7. **Publish**
   ```bash
   npm publish
   ```

## Minor Version Releases

Minor version releases involve schema changes, breaking updates, and new cryptographic keys. This process includes creating a deprecation notice for the old version.

### Steps for Minor Version Release

#### 1. Create New Cryptographic Keys

Generate new public and private keys for the new minor version:

```bash
# Go to home directory to ensure you don't accidentally store keys in any git repo
cd ~

# Generate private key (prime256v1/P-256 curve)
openssl ecparam -genkey -name prime256v1 -noout -out gh_private_key.pem

# Generate public cert from private key
openssl req -new -x509 -key gh_private_key.pem -out public_signing_cert.pem -days 3650 -subj "/CN=Universal Verify Root CA"
```

#### 2. Add Private Key to Repository Secrets

- Go to GitHub repository → Settings → Secrets and variables → Actions
- Add new repository secret with name `PRIVATE_KEY_{major}_{minor}` (e.g., `PRIVATE_KEY_0_1`)
- Paste the private key content from `~/gh_private_key.pem`
- Delete the private key with `rm ~/gh_private_key.pem`

#### 3. Create Release Branch for Old Minor Version

```bash
# Create branch for old minor version
git checkout -b release/0.0

# Push the branch
git push origin release/0.0
```

#### 4. Create Deprecation Notice

Run `npm run deprecate` in our old minor version branch. You will be prompted to provide an end-of-life date, under ordinary conditions you should use the provided sample date which is 90 days from the current date.

This will create a `deprecation_notice.json` file.

#### 5. Update and Publish Patch for Old Version

```bash
# Update patch version in package.json (e.g., 0.0.7)
# Publish the patch
npm publish
```

#### 6. Update Dev Branch with breaking changes
_Make sure that there is no deprecation_notice.json in the dev branch!_
```bash
# Checkout dev branch
git checkout dev

# Replace the public signing cert file
mv ~/public_signing_cert.pem public_signing_cert.pem

# Replace value of PUBLIC_SIGNING_CERT in `./scripts/constants.js` with
# content of new public_signing_cert.pem
vim scripts/constants.js

# Merge/commit schema changes and breaking updates
git add .
git commit -m "Update public signing cert for upcoming minor version {major}.{minor}"
```

#### 7. Update Version and Workflow files

- **Update package.json version** (e.g., `"version": "0.1.0"`)
- **Update minor version in constants.js**:
  ```javascript
  export const MINOR_VERSION = '0.1';
  ```
- **Update build files**
  ```bash
  npm run build
  ```
- **Update to new major-minor version in sign_issuer_files.yml**:
  - `PRIVATE_KEY_{major}_{minor}`
  - `sign-issuers-files-{major}-{minor}`
- **Create new workflow for old version** (stay in dev branch!):
  ```bash
  # Copy the dev workflow for the old minor version, not the new one!
  cp .github/workflows/update_issuers_dev.yml .github/workflows/update_issuers_{old_major}_{old_minor}.yml
  ```

  Edit `.github/workflows/update_issuers_{old_major}_{old_minor}.yml`:
  - Change the last part of the title from "Dev" to "{old_major}.{old_minor}
  - Change `ref: dev` to `ref: release/{old_major}.{old_minor}`
  - Change `base: dev` to `base: release/{old_major}.{old_minor}`
- **Commit changes**
  ```bash
  git add ./
  git commit -m "0.1"
  git push
  ```

#### 8. Create Issue for Workflow Cleanup

Create a GitHub issue to delete the old workflow file once the end-of-life date is reached:

**Title**: "Delete update_issuers_#_#.yml workflow after YYYY-MM-DD"

**Body**:
```
The workflow `.github/workflows/update_issuers_#_#.yml` should be deleted in dev after the end-of-life date in release/#.# is reached.

End-of-life date: [DATE]
Workflow file: `.github/workflows/update_issuers_#_#.yml`
```

#### 9. Sign Files and Publish New Minor Version

- Manually trigger "Sign issuer files" workflow on dev branch (wait for PR to be created and merge it)
- Publish to npm
  ```bash
  # Pull latest changes
  git pull origin dev

  # Publish the new minor version
  npm publish
  ```

## Deprecation Lifecycle

### Timeline

- **Day 0**: New minor version released and deprecation notice created for old version
- **Day 90**: Old version reaches end-of-life and old version workflow is deleted
