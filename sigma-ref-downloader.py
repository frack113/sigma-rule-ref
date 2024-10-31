# Download sigma rule reference as PDF
#
# thank https://www.checklyhq.com/learn/playwright/generating-pdfs/

import asyncio
from playwright.async_api import async_playwright

from sigma.collection import SigmaCollection

import pathlib
import hashlib

import click

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

async def url_to_pdf(url, output_path):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto(url)
        await page.emulate_media(media='screen')
        await page.pdf(
            path=output_path,
            display_header_footer=True,
            header_template=header,
            footer_template=footer,
            margin={ 'top': '100px','bottom': '40px'},
            print_background=True
            )
        await browser.close()




@click.command()
@click.argument("path")
def check(path):
  path_to_rules = [f"{path}/{folder}" for folder in sigmahq_folder]
  rule_paths = SigmaCollection.resolve_paths(path_to_rules)
  rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
  for sigmaHQrule in rule_collection:
      rule_id = str(sigmaHQrule.id)
      for reference in sigmaHQrule.references:
          if reference.startswith("http"):
              if not pathlib.Path(rule_id).exists():
                  pathlib.Path(rule_id).mkdir()
              print(f" --> {reference}")
              sha_name = hashlib.sha256(reference.encode()).hexdigest()           
              print(f"   |--> {sha_name}")
              output_path = f"pdf/{rule_id}/{sha_name}.pdf"
              if not pathlib.Path(output_path).exists():
                  asyncio.run(url_to_pdf(reference, output_path))
              else:
                  print(f"   |--> pass")


if __name__ == "__main__":
    check()