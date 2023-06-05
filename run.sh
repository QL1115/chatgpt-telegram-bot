#!/bin/sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app_test/modify_api.py #python app_test/env_setting.py
python bot/main.py
