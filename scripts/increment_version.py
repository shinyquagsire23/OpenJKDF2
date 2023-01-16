import sys
from datetime import date

today = date.today()

def handle_flatpak(version):
    f = open("packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml", "r")
    contents = f.read()
    f.close()

    if version[0] == 'v':
        version = version[1:]

    dt = today.strftime("%Y-%m-%d")

    contents = contents.replace("<!--NEXT_RELEASE_HERE-->", "<!--NEXT_RELEASE_HERE-->\n    <release version=\"" + version + "\" date=\"" + dt + "\" />")

    f = open("packaging/flatpak/org.openjkdf2.OpenJKDF2.metainfo.xml", "w")
    f.write(contents)
    f.close()

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

def handle_version_c(version):
    if version[0] == 'v':
        version = version[1:]

    version_parts = version.split(".")
    major = version_parts[0]
    minor = version_parts[1]
    patch = version_parts[2]

    f = open("src/version.c", "w")
    f.write("#include \"types.h\"\n")
    f.write("#include \"version.h\"\n\n")
    f.write("const char* openjkdf2_aReleaseVersion = \"v" + version + "\";\n");
    f.write("const wchar_t* openjkdf2_waReleaseVersion = L\"v" + version + "\";\n");
    f.write("const char* openjkdf2_aReleaseCommit = OPENJKDF2_RELEASE_COMMIT;\n");
    f.write("const wchar_t* openjkdf2_waReleaseCommit = OPENJKDF2_RELEASE_COMMIT_W;\n");
    f.write("const char* openjkdf2_aReleaseCommitShort = OPENJKDF2_RELEASE_COMMIT_SHORT;\n");
    f.write("const wchar_t* openjkdf2_waReleaseCommitShort = OPENJKDF2_RELEASE_COMMIT_SHORT_W;\n");
    f.write("const int openjkdf2_releaseVersionMajor = " + major + ";\n");
    f.write("const int openjkdf2_releaseVersionMinor = " + minor + ";\n");
    f.write("const int openjkdf2_releaseVersionPatch = " + patch + ";\n");
    f.close()

if __name__ == "__main__":
    handle_flatpak(sys.argv[1])
    handle_flatpak_repo(sys.argv[1], sys.argv[2])
    handle_version_c(sys.argv[1])