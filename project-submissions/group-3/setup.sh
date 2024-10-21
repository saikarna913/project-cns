#!/bin/bash

# curl -sSL https://install.python-poetry.org | python3 -
poetry lock
poetry install

# python3 -m pip install -r ./requirements.txt

chmod +x ./atm
chmod +x ./atm_cleaner.sh