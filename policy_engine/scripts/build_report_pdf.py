"""Renders docs/Implementation_Review2.html to PDF with headless Chrome / Edge.

Usage (from the project root, after `aspe all` and `plot_results.py`):
    python scripts/build_report_pdf.py
"""
import os
import pathlib
import shutil
import subprocess
import sys

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser():
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        path = shutil.which(name)
        if path:
            return path
    return next((c for c in CANDIDATES if os.path.exists(c)), None)


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    source = root / "docs" / "Implementation_Review2.html"
    target = root / "docs" / "Implementation_Review2.pdf"
    browser = find_browser()
    if browser is None:
        sys.exit("Chrome or Edge not found - open the HTML file and use Print > Save as PDF")
    subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                    "--print-to-pdf=" + str(target), source.as_uri()], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("wrote", target)


if __name__ == "__main__":
    main()
