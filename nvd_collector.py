import json
import sqlite3
from cpe import CPE

import zipfile
import urllib.request


def initialize_db(db_filename):
    db = sqlite3.connect(db_filename)
    create_command = "create table cpes ( part text, vendor text, product text, version text, update_number text, edition text, language text, sw_edition text, target_sw text, target_hw text, other text, cve_id text);"
    db.execute(create_command)
    return db

def process_cpe(cpe, cve, db):
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

    row_tuple = (part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other, cve)

    insertion_command = "INSERT INTO cpes VALUES " + str(row_tuple)
    db.execute(insertion_command)


def process_cve_item(item, db):
    cve = item["cve"]["CVE_data_meta"]["ID"]

    config_nodes = item["configurations"]["nodes"]
    
    cpes = []
    for node in config_nodes:
        cpes_info = node["cpe_match"]
        for cpe_uri in cpes_info:
            if cpe_uri["vulnerable"]:
                cpe = CPE(cpe_uri["cpe23Uri"])
                process_cpe(cpe, cve, db)

def download_year_data(year, db):
    url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + str(year) + ".json.zip"
    print("Downloading year", str(year) + "...", end="", flush=True)
    f, _ = urllib.request.urlretrieve(url)
    year_zip = zipfile.ZipFile(f, 'r')
    json_file = year_zip.open(year_zip.namelist()[0])
    nvd_feed = json.load(json_file)
    cves = nvd_feed["CVE_Items"]
    for cve in cves:
        process_cve_item(cve, db)
    db.commit()
    print("Done!")



def main():
    db_filename = "nvd.db"
    db = initialize_db(db_filename)

    for year in range(2002, 2022):
        download_year_data(year, db)

if __name__=="__main__":
    main()

