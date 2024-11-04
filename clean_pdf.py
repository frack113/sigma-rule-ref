# Remove PDF when fix cookies
#

import pathlib
import json

remove = "https://app.any.run/"

with open("References.json", "r", encoding="UTF-8") as file:
    data = json.load(file)

for k, v in data.items():
    for ref in v["reference"]:
        if ref["url"].startswith(remove):
            if pathlib.Path(ref["pdf"]).exists():
                print(f"Remove : {ref['pdf']}")
                pathlib.Path(ref["pdf"]).unlink()
