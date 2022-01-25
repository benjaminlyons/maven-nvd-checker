# maven-nvd-checker
Simple heuristic for identifying maven dependencies with vulnerabilities.

## Getting Started
1. download the repository
2. install the packages with `pip3 install -r requirements.txt`
3. access the database at https://drive.google.com/file/d/1g8xJtbGtScokopd7IHK0kxcwF_icpWfH/view?usp=sharing
- another option is to regenerate the database by running 
```
sqlite3 nvd.db
.quit
python3 nvd_collector.py
```
4. Finally, you can analyze a pom file with `python3 maven_dependency_parser.py pom.xml`

## Design Decisions
First, I created the `nvd_collector.py` file which downloads the NVD json feeds and puts them into an sqlite database.
There are two main tables that I create: cpes and cve_match. The cpes table connects individual cpes with a cve. The cve_match
table is used to match specific product versions with a  cve. It was necessary to have both these tables because the json
vulnerability feeds did not contain all of the vulnerable versions of each product.

Then I created `maven_dependency_parser.py` which parses the dependencies in the pom.xml file and runs a heuristic to 
check if they are included in the database. One significant challenge is that the groupId and artifactId do not
directly corresond to any part of the CPE. This means that its not easy to find matches. My solution was to first search the
table for all cpes with the same version as the maven dependency. Then, I would run a regex match to check if the cpe product
name is found in the artifact id or vice versa. Additionally, I would replace all instances of the '-' character in the artifactId 
with an '_ ', because I noticed that dependencies like commons-beanutils could be found as commons_beanutils in json feeds.
Additionally, I split up the groupId based on '.' and check if the product has a regex match to any of the split parts of the
groupId. Overall, this heuristic seems to work pretty well, but it is still imperfect. Sometimes the product/vendor listed in the JSON 
feeds are substantially different from groupId/artifactId. I'm honestly not sure what to do in these cases.

A great example of the program  working can be found by running it on the pom.xml file that is included in this repository. It
identifies serious vulnerabilities in log4j and apache struts, which have been the root cause of data breaches in past.
