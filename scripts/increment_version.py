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

def handle_cmake(version):
    if version[0] == 'v':
        version = version[1:]

    version_parts = version.split(".")
    major = version_parts[0]
    minor = version_parts[1]
    patch = version_parts[2]

    cmake_version = ".".join([major, minor, patch, "0"])

    f = open("cmake_modules/version.cmake", "w")
    f.write("set(OPENJKDF2_PROJECT_VERSION " + cmake_version + ")\n"
            "find_package(Git)\n"
            "execute_process(\n"
            "    COMMAND git log -1 --format=%H\n"
            "    OUTPUT_VARIABLE OPENJKDF2_RELEASE_COMMIT\n"
            "    OUTPUT_STRIP_TRAILING_WHITESPACE\n"
            ")\n"
            "execute_process(\n"
            "    COMMAND git rev-parse --short=8 HEAD\n"
            "    OUTPUT_VARIABLE OPENJKDF2_RELEASE_COMMIT_SHORT\n"
            "    OUTPUT_STRIP_TRAILING_WHITESPACE\n"
            ")");
    f.close()

if __name__ == "__main__":
    handle_flatpak(sys.argv[1])
    handle_flatpak_repo(sys.argv[1], sys.argv[2])
    handle_cmake(sys.argv[1])
