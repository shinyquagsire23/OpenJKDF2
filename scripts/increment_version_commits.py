import sys
from datetime import date

today = date.today()

def handle_flatpak_repo(version, commit):
    f = open("packaging/flatpak/org.openjkdf2.OpenJKDF2.template.yml", "r")
    contents = f.read()
    f.close()

    if version[0] == 'v':
        version = version[1:]

    contents = contents.replace("REPLACE_COMMIT_HASH", commit)

    f = open("packaging/flatpak/org.openjkdf2.OpenJKDF2.yml", "w")
    f.write(contents)
    f.close()

if __name__ == "__main__":
    handle_flatpak_repo(sys.argv[1], sys.argv[2])