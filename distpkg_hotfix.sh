#!/bin/zsh

OPENJKDF2_ROOT=$(pwd)

python3 scripts/increment_version_commits.py "$1" $(git log -1 --format="%H")

cp packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml $OPENJKDF2_ROOT/../org.openjkdf2.OpenJKDF2/org.openjkdf2.OpenJKDF2.yml

cd $OPENJKDF2_ROOT/../org.openjkdf2.OpenJKDF2/
git stash
git checkout master
git pull
git checkout "$1"
git add org.openjkdf2.OpenJKDF2.yml
git commit -m "hotfix"
git push origin "$1"

cd $OPENJKDF2_ROOT

./distpkg_all.sh
