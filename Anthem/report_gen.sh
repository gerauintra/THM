#!/bin/bash

# ArchLinux: pacman -S p7zip haskell-pandoc texlive-basic texlive-fontsextra texlive-fontsrecommended texlive-latexextra
# openSUSE: zypper in texlive-scheme-medium pandoc p7zip-full
# Ubuntu: apt install texlive-latex-recommended texlive-fonts-extra texlive-latex-extra pandoc p7zip-full

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'

/opt/THM/Anthem="/opt/THM/Anthem"
box_name="Anthem"
screenshots_dir="${/opt/THM/Anthem}/8-screenshots"

printf "${YELLOW}[-] Generating report...\n"

pandoc ${/opt/THM/Anthem}/Anthem_report.md \
-o ${/opt/THM/Anthem}/Anthem_report.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style breezedark \
--resource-path .:${screenshots_dir}

printf "${GREEN}[+] Report generated\n"

printf "\n\n   ${GREEN}DONE !!!   \n"