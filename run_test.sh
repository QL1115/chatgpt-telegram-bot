#!/bin/sh
python -m venv venv
source venv/bin/activate
#pip install -r requirements.txt
#pip install -r othertest_requirements.txt

bandit bot/main.py
bandit bot/openai_helper.py
bandit bot/telegram_bot.py
bandit bot/usage_trackey.py
bandit bot/utils.py

pylint bot/main.py
pylint bot/openai_helper.py
pylint bot/telegram_bot.py
pylint bot/usage_trackey.py
pylint bot/utils.py

flake8 bot/main.py
flake8 bot/openai_helper.py
flake8 bot/telegram_bot.py
flake8 bot/usage_trackey.py
flake8 bot/utils.py