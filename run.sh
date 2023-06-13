#!/bin/sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app_test/modify_api.py #app_test/env_setting.py
python bot/main.py &

# 執行一百分鐘
sleep 6000

# 停止Python腳本
kill $(pgrep -f "python bot/main.py")
