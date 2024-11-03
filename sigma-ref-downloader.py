# Download sigma rule reference as PDF
#
# thank https://www.checklyhq.com/learn/playwright/generating-pdfs/

import asyncio
from playwright.async_api import async_playwright

from sigma.collection import SigmaCollection

import pathlib
import hashlib
import click
import json
import string
import re

sigmahq_folder = [
    "rules",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
    "rules-compliance",
]


header = """
<html>
  <head>
    <style type="text/css">
      #header {
        padding: 0;
      }
      .content {
        width: 100%;
        background-color: #777;
        color: white;
        padding: 5px;
        -webkit-print-color-adjust: exact;
        vertical-align: middle;
        font-size: 15px;
        margin-top: 0;
        display: inline-block;
      }
      .title {
        font-weight: bold;
      }
      .date {
        text-align:right;
      }
    </style>
  </head>
  <body>
    <div class="content">
        <span class="title"></span> -
        <span class="date"></span>
        <span class="url"></div>
    </div>
  </body>
</html>
"""

footer = """
<html>
  <head>
    <style type="text/css">
      #footer {
        padding: 0;
      }
      .content-footer {
        width: 100%;
        background-color: #777;
        color: white;
        padding: 5px;
        -webkit-print-color-adjust: exact;
        vertical-align: middle;
        font-size: 15px;
        margin-top: 0;
        display: inline-block;
        text-align: center;
      }
    </style>
  </head>
  <body>
    <div class="content-footer">
      Page <span class="pageNumber"></span> of <span class="totalPages"></span>
    </div>
  </body>
</html>
"""

def get_site(reference:str)->str:
    match = re.search(r'https?://([^/]*)',reference)
    return match.group()


async def url_to_pdf(url, output_path):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        try:        
            await page.goto(url=url,timeout=0, wait_until="load")

            # General Data Protection Regulation Click "Accept" button
            if await page.locator("#hs-eu-confirmation-button").is_visible():
                await page.locator("#hs-eu-confirmation-button").click(timeout=2000)

            await page.emulate_media(media="screen")
            await page.pdf(
                path=output_path,
                display_header_footer=True,
                header_template=header,
                footer_template=footer,
                margin={"top": "100px", "bottom": "40px"},
                print_background=True,
                landscape =True,
                format="Ledger",
            )
        except Exception as err:
            print("Open error :") 
            print(err)
            
        await browser.close()

def create_json(data:dict,name:str):
    with open(name,"w",encoding="UTF-8",newline='') as file:
        json.dump(data,file,indent=4,sort_keys=True)

def create_md(data:dict,name:str):
    revert = {v['yaml']:k for k,v in data.items()}
    sorted_revert =  {k:revert[k] for k in sorted(revert)}

    #create all the md
    for letter in list(string.ascii_lowercase):
        filename = f"{name}_{letter}.md"
        with open(filename,"w",encoding="UTF-8",newline='') as file:
            file.write("# Sigma rule references as PDF\n\n") 

    for k,v in sorted_revert.items():
        filename = f"{name}_{k[0]}.md"
        with open(filename,"a",encoding="UTF-8",newline='') as file:
            file.write(f"## {k}\n")
            file.write(f"Title : {data[v]['title']}\n\n")
            file.write(f"Rule id : {v}\n\n")
            file.write("| Url | Pdf |\n")
            file.write("| --- | --- |\n")
            for ref in data[v]['reference']:
                file.write(f"| {ref['url']} | [{ref['pdf']}]({ref['pdf']}) |\n")
            file.write("\n\n")

@click.command()
@click.argument("path")
def check(path):
    json_data = {}
    url_data = {}
    path_to_rules = [f"{path}/{folder}" for folder in sigmahq_folder]
    rule_paths = SigmaCollection.resolve_paths(path_to_rules)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    with click.progressbar(rule_collection) as bar:
        for sigmaHQrule in bar:
            rule_id = str(sigmaHQrule.id)

            json_data[rule_id] = {
                "yaml": sigmaHQrule.source.path.stem,
                "title": sigmaHQrule.title,
                "reference": []
            }

            for reference in sigmaHQrule.references:
                if reference.startswith("http"):

                    url_uri = get_site(reference)
                    url_data.update({url_uri:'0'})

                    if reference.lower().endswith(".pdf"):
                        continue

                    sha_name = hashlib.sha256(reference.encode()).hexdigest()
                    output_path = f"pdf/{sha_name}.pdf"
                    if not pathlib.Path(output_path).exists():
                        asyncio.run(url_to_pdf(reference, output_path))
                    
                    json_data[rule_id]["reference"].append({
                        "url": reference,
                        "pdf": output_path}
                        )

    create_json(json_data,"references.json")
    create_json(url_data,"site.json")
    create_md(json_data,"references")

if __name__ == "__main__":
    if not pathlib.Path("pdf").exists():
        pathlib.Path("pdf").mkdir()
    check()
