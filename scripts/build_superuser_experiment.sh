#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
state="$root/molecule/integration/.state/superuser-experiment"
source="$state/source"
source_ref=${EXPERIMENT_SOURCE_REF:-9a12806cd87fd1a9ace03a2487a87f819dfd3e72}
mkdir -p "$state"
if [ -e "$source" ]; then
  printf 'Refusing to overwrite experiment source: %s\n' "$source" >&2
  exit 1
fi
mkdir "$source"
git -C "$root" rev-parse "$source_ref^{commit}" > "$state/source-commit.txt"
git -C "$root" archive --output="$state/source.tar" "$source_ref"
tar -xf "$state/source.tar" -C "$source"
git -C "$source" init -q
for variant in baseline unprivileged absent; do
  if [ "$variant" != baseline ]; then
    git -C "$source" apply "$root/molecule/integration/superuser-$variant.patch"
  fi
  docker run --rm -v "$root:/work" -w /work/molecule/integration/.state/superuser-experiment/source \
    maven:3.9.9-eclipse-temurin-17 mvn -B -s .mvn/matrix-settings.xml \
    -Dmaven.repo.local=/work/.m2/repository -DskipTests -Dmaven.javadoc.skip=true clean package
  mkdir -p "$state/artifacts/$variant"
  for module in 2.2 3.0 3.11 4.0 4.1 5.0; do
    for jar in "$source/cassandra-$module/target/"cassandra-ldap-*.jar; do
      case "$jar" in *-sources.jar) continue ;; esac
      cp "$jar" "$state/artifacts/$variant/cassandra-$module.jar"
    done
  done
done
