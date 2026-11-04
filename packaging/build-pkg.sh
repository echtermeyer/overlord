#!/bin/sh
# Builds a signed, notarized installer. Needs: Developer ID Application + Installer certificates
# in the keychain, and a notarytool keychain profile named "overlord".
#   DEVELOPER_ID_APP="Developer ID Application: Name (TEAMID)" \
#   DEVELOPER_ID_INSTALLER="Developer ID Installer: Name (TEAMID)" ./packaging/build-pkg.sh v0.1.0
set -eu
version=${1:?version}
root=$(mktemp -d)
mkdir -p "$root/Library/Overlord/bin" "$root/Library/Overlord/rules"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/echtermeyer/overlord.Version=$version" -o "$root/Library/Overlord/bin/overlord" ./cmd/overlord
cp rules/*.yaml "$root/Library/Overlord/rules/"
cp policy.yaml packaging/pf.anchor packaging/com.overlord.daemon.plist packaging/com.overlord.notify.plist "$root/Library/Overlord/"
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APP" "$root/Library/Overlord/bin/overlord"
mkdir -p dist
pkgbuild --root "$root" --identifier com.overlord.pkg --version "${version#v}" --scripts packaging/scripts --install-location / "dist/overlord-unsigned.pkg"
productsign --sign "$DEVELOPER_ID_INSTALLER" dist/overlord-unsigned.pkg "dist/overlord-$version.pkg"
rm dist/overlord-unsigned.pkg
xcrun notarytool submit "dist/overlord-$version.pkg" --keychain-profile overlord --wait
xcrun stapler staple "dist/overlord-$version.pkg"
shasum -a 256 "dist/overlord-$version.pkg" > "dist/overlord-$version.pkg.sha256"
echo "built dist/overlord-$version.pkg"
