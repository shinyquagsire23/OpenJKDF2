#!/bin/sh

OPENJKDF2_ROOT=$(pwd)

python3 scripts/increment_version.py "$1" $(git log -1 --format="%H")

git add packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml
git add src/version.c src/version.h
git commit -m "$1"
git push origin master

python3 scripts/increment_version_commits.py "$1" $(git log -1 --format="%H")

cd $OPENJKDF2_ROOT/../org.openjkdf2.OpenJKDF2/
git stash
git checkout master
git pull
git checkout -b "$1"

cp $OPENJKDF2_ROOT/packaging/flatpak/org.openjkdf2.OpenJKDF2.yml $OPENJKDF2_ROOT/../org.openjkdf2.OpenJKDF2/org.openjkdf2.OpenJKDF2.yml

git add org.openjkdf2.OpenJKDF2.yml
git commit -m "$1"
git push origin "$1"

cd $OPENJKDF2_ROOT

./distpkg_all.sh
