import xml.etree.ElementTree as xml
import sqlite3

def extract_dependencies(pom_file):
    dep_list = []
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    pom = xml.parse(pom_file)
    dependencies = pom.find('m:dependencies', ns)
    for dependency in dependencies.findall('m:dependency', ns):
        product = dependency.find('m:artifactId', ns).text
        version = dependency.find('m:version', ns).text
        dep_list.append((product, version))
    return dep_list

def find_vulns(dep_list, db):
    print("Found vulnerabilities:")
    cur = db.cursor()

    for (product, version) in dep_list:
        res = cur.execute("SELECT distinct cve_match.cve_id FROM cve_match where cve_match.product = ? and cve_match.version = ?", (product, version)).fetchall()

        if not res:
            continue

        print()
        print("Dependency:", product)
        print("Version:", version)
        print("Vulnerabilities:")

        for cve_id in res:
            print("- " + cve_id[0])


def main():
    dep_list = extract_dependencies("pom.xml")
    db = sqlite3.connect("nvd.db")
    find_vulns(dep_list, db)

if __name__ == "__main__":
    main()
