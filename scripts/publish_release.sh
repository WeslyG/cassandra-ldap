#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tag=${RELEASE_TAG:?Set RELEASE_TAG}
repository=${GH_REPO:?Set GH_REPO}
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'Invalid release tag' >&2
  exit 1
fi
directory="$root/dist/$tag"
commit=$(git -C "$root" rev-parse HEAD)
test "$(git -C "$root" rev-parse "refs/tags/$tag^{commit}")" = "$commit"
jq -e --arg tag "$tag" --arg commit "$commit" --arg repository "$repository" \
  '.tag == $tag and .commit == $commit and .repository == $repository' "$directory/release-manifest.json" >/dev/null
cd "$directory"
sha256sum --check SHA256SUMS
assets=("$directory/SHA256SUMS")
while read -r hash filename; do
  if [[ ! "$hash" =~ ^[a-f0-9]{64}$ || ! "$filename" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    printf '%s\n' 'Invalid asset filename' >&2
    exit 1
  fi
  assets+=("$directory/$filename")
done < SHA256SUMS
test "${#assets[@]}" -eq 9

if draft=$(gh release view "$tag" --repo "$repository" --json isDraft --jq .isDraft 2>/dev/null); then
  if [[ "$draft" != true ]]; then
    printf '%s\n' 'A published release exists; refusing to replace its assets' >&2
    exit 1
  fi
  existing=$(gh release view "$tag" --repo "$repository" --json assets --jq '.assets[].name')
  missing=()
  for asset in "${assets[@]}"; do
    if ! grep -Fxq "$(basename "$asset")" <<< "$existing"; then
      missing+=("$asset")
    fi
  done
  if [[ "${#missing[@]}" -gt 0 ]]; then
    gh release upload "$tag" "${missing[@]}" --repo "$repository"
  fi
  gh release edit "$tag" --repo "$repository" --notes-file "$directory/RELEASE_NOTES.md"
else
  gh release create "$tag" "${assets[@]}" --repo "$repository" --verify-tag \
    --target "$commit" --title "Cassandra LDAP Authenticator $tag" \
    --notes-file "$directory/RELEASE_NOTES.md" --draft
fi

# Verify the exact uploaded file set and bytes before making the draft public.
verification=$(mktemp -d)
trap 'rm -rf "$verification"' EXIT
for asset in "${assets[@]}"; do basename "$asset"; done | sort > "$verification/expected"
gh release view "$tag" --repo "$repository" --json assets --jq '.assets[].name' | sort > "$verification/actual"
diff -u "$verification/expected" "$verification/actual"
gh release download "$tag" --repo "$repository" --dir "$verification/downloads"
cmp "$directory/SHA256SUMS" "$verification/downloads/SHA256SUMS"
cd "$verification/downloads"
sha256sum --check SHA256SUMS
gh release edit "$tag" --repo "$repository" --draft=false --latest
gh release view "$tag" --repo "$repository" --json url --jq .url
