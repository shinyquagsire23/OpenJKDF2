#!/bin/bash
python3 analyze.py > tmp.txt
cat README.md.template tmp.txt README.md.template-foot > README.md
