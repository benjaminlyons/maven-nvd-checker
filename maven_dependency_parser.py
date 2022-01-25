import sys
import xml.etree.ElementTree as xml
import sqlite3
import re

def extract_dependencies(pom_file):
    dep_list = []
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    pom = xml.parse(pom_file)
    dependencies = pom.find('m:dependencies', ns)
    for dependency in dependencies.findall('m:dependency', ns):
        groupid = dependency.find('m:groupId', ns).text
        artifactid = dependency.find('m:artifactId', ns).text
        version = dependency.find('m:version', ns).text
        dep_list.append((groupid, artifactid, version))
    return dep_list

def match(groupid, artifactid, vendor, product):
    artifactid = artifactid.replace('-', '_') # most product names use _ instead of -
    if re.match(product, artifactid):
        return True

    if re.match(artifactid, product):
        return True

    # compare with group id, but ignore the first part because its usually com., net., gov.
    group_parts = groupid.split('.')
    if len(group_parts) > 1:
        for index, part in enumerate(group_parts):
            if index > 0 and re.match(product, part):
                print(product, groupid)
                return True

    return False

def find_vulns(dep_list, db):
    print("Found vulnerabilities:")
    cur = db.cursor()

    for (groupid, artifactid, version) in dep_list:
        res = cur.execute("SELECT distinct cpes.vendor, cpes.product, cpes.cve_id from cpes, cve_match where cve_match.version = ? and cve_match.cve_id = cpes.cve_id and cpes.product = cve_match.product and cpes.part = 'a'", (version,)).fetchall()

        if not res:
            continue

        cve_list = []
        for vendor, product, cve_id in res:
            if match(groupid, artifactid, vendor, product):
                cve_list.append(cve_id)

        if not cve_list:
            continue

        print()
        print("Dependency:", artifactid)
        print("Version:", version)
        print("Vulnerabilities:")

        for cve_id in cve_list:
            print("- " + cve_id)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pom.xml")
        sys.exit(1)

    pom_file = sys.argv[1]
    dep_list = extract_dependencies(pom_file)
    db = sqlite3.connect("nvd.db")
    find_vulns(dep_list, db)

if __name__ == "__main__":
    main()
