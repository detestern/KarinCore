#!/usr/bin/env bash
# ***************************************
# KarinCore — permanent Android release key
# ***************************************
# Creates the signing key OUTSIDE the repository and (optionally) uploads it to
# GitHub Actions secrets. Run it once; keep the backup safe forever.
#
#   scripts/android-keystore.sh            create the key and print the next steps
#   scripts/android-keystore.sh --upload   also store it as repository secrets (needs `gh auth login`)
#
set -euo pipefail

REPO="${KARINCORE_REPO:-detestern/KarinCore}"
DIR="${KARINCORE_SIGNING_DIR:-$HOME/.karincore-signing}"
KEYSTORE="$DIR/karincore-release.p12"
ALIAS="karincore"
PASS_FILE="$DIR/password.txt"

for tool in keytool openssl base64; do
  command -v "$tool" >/dev/null || { echo "Required tool is missing: $tool (keytool comes with a JDK)"; exit 1; }
done

if [ -e "$KEYSTORE" ]; then
  echo "A key already exists at $KEYSTORE and will not be overwritten."
else
  umask 077
  mkdir -p "$DIR"
  PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
  printf '%s' "$PASSWORD" > "$PASS_FILE"
  keytool -genkeypair -storetype PKCS12 -keystore "$KEYSTORE" \
    -alias "$ALIAS" -keyalg RSA -keysize 4096 -validity 36500 \
    -storepass "$PASSWORD" -keypass "$PASSWORD" \
    -dname "CN=KarinCore, O=KarinCore"
  echo "Key created: $KEYSTORE"
fi

echo
echo "Certificate fingerprint (SHA-256):"
keytool -list -keystore "$KEYSTORE" -storepass "$(cat "$PASS_FILE")" -alias "$ALIAS" | grep -i 'SHA-256' || true

if [ "${1:-}" = "--upload" ]; then
  command -v gh >/dev/null || { echo "gh is not installed"; exit 1; }
  base64 -w0 "$KEYSTORE" | gh secret set ANDROID_KEYSTORE_BASE64 -R "$REPO"
  gh secret set ANDROID_KEYSTORE_PASSWORD -R "$REPO" < "$PASS_FILE"
  gh secret set ANDROID_KEY_PASSWORD -R "$REPO" < "$PASS_FILE"
  gh secret set ANDROID_KEY_ALIAS -R "$REPO" --body "$ALIAS"
  echo "Secrets uploaded to $REPO."
else
  cat <<MSG

Next: upload the key to GitHub Actions secrets. Either rerun with --upload or run:
  base64 -w0 "$KEYSTORE" | gh secret set ANDROID_KEYSTORE_BASE64 -R $REPO
  gh secret set ANDROID_KEYSTORE_PASSWORD -R $REPO < "$PASS_FILE"
  gh secret set ANDROID_KEY_PASSWORD -R $REPO < "$PASS_FILE"
  gh secret set ANDROID_KEY_ALIAS -R $REPO --body "$ALIAS"
MSG
fi

cat <<MSG

IMPORTANT: back up the whole folder $DIR (password manager, encrypted drive).
If this key is lost, installed copies of the app can no longer be updated in place.
Never commit it to the repository.
MSG
