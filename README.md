# maven-nvd-checker
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


