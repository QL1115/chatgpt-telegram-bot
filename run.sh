#!/bin/sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app_test/env_setting.py #python app_test/modify_api.py
python bot/main.py &

# 等待一分鐘
sleep 60

# 停止Python腳本
kill $(pgrep -f "python bot/main.py")
