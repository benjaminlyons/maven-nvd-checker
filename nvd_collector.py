import json
import sqlite3
from cpe import CPE

import zipfile
import urllib.request
from progress.bar import Bar


def initialize_db(db_filename):
    db = sqlite3.connect(db_filename)

    cpes_create_command = "create table cpes ( uri text, part text, vendor text, product text, version text, update_number text, edition text, language text, sw_edition text, target_sw text, target_hw text, other text, cve_id text, start_version text, end_version text, end_comp text);"
    db.execute(cpes_create_command)

    matches_create_command = "create table matches ( uri text, start_version text, end_version text, end_comp text, version text )"
    db.execute(matches_create_command)
    return db

def extract_version_comps(cpe):
    start_version = "NULL"
    end_version = "NULL"
    end_comparison_symbol = "="

    if "versionStartIncluding" in cpe:
        start_version = cpe["versionStartIncluding"]

    if "versionEndIncluding" in cpe:
        end_version = cpe["versionEndIncluding"]
        end_comparison_symbol = "<="

    if "versionEndExcluding" in cpe:
        end_version = cpe["versionEndExcluding"]
        end_comparison_symbol = "<"

    return start_version, end_version, end_comparison_symbol

def process_cpe(cpe, cve, db):
    uri = cpe["cpe23Uri"]

    # check if its vulnerable
    if not cpe["vulnerable"]:
        return

    # check start/end versions
    start_version, end_version, end_comparison_symbol = extract_version_comps(cpe)

    # parse cpe 
    cpe = CPE(uri)
    part = cpe.get_part()[0]
    vendor = cpe.get_vendor()[0]
    product = cpe.get_product()[0]
    version = cpe.get_version()[0]
    update = cpe.get_update()[0]
    edition = cpe.get_edition()[0]
    language = cpe.get_language()[0]
    sw_edition = cpe.get_software_edition()[0]
    target_sw = cpe.get_target_software()[0]
    target_hw = cpe.get_target_hardware()[0]
    other = cpe.get_other()[0]

    # add to table
    row_tuple = (uri, part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other, cve, start_version, end_version, end_comparison_symbol)
    insertion_command = "INSERT INTO cpes VALUES " + str(row_tuple)
    db.execute(insertion_command)

def process_node(config_node, cve, db):

    # process node children
    for child in config_node["children"]:
        process_node(child, cve, db)

    for cpe in config_node["cpe_match"]:
        process_cpe(cpe, cve, db)

def download_year_data(year, db):
    url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(year) + ".json.zip"
    f, _ = urllib.request.urlretrieve(url)
    year_zip = zipfile.ZipFile(f, 'r')
    json_file = year_zip.open(year_zip.namelist()[0])
    nvd_feed = json.load(json_file)
    cves = nvd_feed["CVE_Items"]

    bar = Bar("Downloading year " + str(year), max=len(cves))
    for cve in cves:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]
        config_nodes = cve["configurations"]["nodes"]
        for node in config_nodes:
            process_node(node, cve_id, db)
        bar.next()

    db.commit()
    print("Done!")

def download_cpe_match_data(db):
    url = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip"
    f, _ = urllib.request.urlretrieve(url)
    match_zip = zipfile.ZipFile(f, 'r')
    json_file = match_zip.open(match_zip.namelist()[0])
    nvd_feed = json.load(json_file)
    cpe_matches = nvd_feed["matches"]

    bar = Bar("Downloading cpe match data", max=len(cpe_matches))
    for index, match in enumerate(cpe_matches):
        original_uri = match["cpe23Uri"]
        start_version, end_version, end_comparison_symbol = extract_version_comps(match)

        for name in match["cpe_name"]:
            cpe = CPE(name["cpe23Uri"])
            version = cpe.get_version()[0]
            match_row = (original_uri, start_version, end_version, end_comparison_symbol, version)

            insertion_command = "INSERT INTO matches VALUES " + str(match_row)
            db.execute(insertion_command)
        bar.next()
        if not index % 10000:
            db.commit()
    db.commit()


def main():
    db_filename = "nvd.db"
    db = initialize_db(db_filename)

    download_cpe_match_data(db)

    for year in range(2002, 2022):
        download_year_data(year, db)

    # now join these two tables together
    print("Creating cve match table...", end='', flush=True)
    db.execute("create table cve_match as select distinct cpes.product, matches.version, cpes.cve_id from cpes join matches on cpes.uri=matches.uri and cpes.start_version=matches.start_version and cpes.end_version=matches.end_version and cpes.end_comp=matches.end_comp;")
    db.commit()
    print("Done!")

if __name__=="__main__":
    main()

