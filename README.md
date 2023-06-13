# chatGPTbot_Testing
## Application Test 

### Unittest
* test for each functions in bot folder
```
cd unittest
python3 -m unittest
```

### Envrroment Setup
```
python -m venv venv
source venv/bin/activate
pip install -r othertest_requirements.txt
```

### Selenium
* test for chat_ai
```
cd app_test
python app_test.py
```


* test for chat_ai group
```
cd app_test
python app_test_group.py
```
* you should enter your telegram phonenumber & the verification code for login.

## Atheris fuzz test

```
cd fuzz_test
python main_fuzz.py
python openai_helper_fuzz.py
python telegram_bot_fuzz.py
python usage_tracker_fuzz.py
```

## AFL fuzz test
in venv

```
py-afl-fuzz -m 200 -t 5000+ -o fuzz_test/results/ -i fuzz_test/in -- python fuzz_test/afl_test.py
```


## Execute the chatGPT telegram bot project 
```
bash run.sh
```

### modify_api & env_setting
* modify_api: modify api by directly input
* env_setting:modify api by parameter(default by the api_config file)
you can choose the method you want (by input or by api_config file) by modify run.sh 
* by input: `python app_test/modify_api.py`  (default)
* by api_config file or os environment variable: `python app_test/env_setting.py`   

### api_config file
modify `app_test/api_config` file to
```
{{your_open_api_key}}
{{your_telegram_bot_key}}
```


## Run Security Test & Code Quality Test
```
bash run_test.sh
```
### Security Test
* bandit
```
cd bot
bandit main.py
bandit openai_helper.py
bandit telegram_bot.py
bandit usage_trackey.py
bandit utils.py
```

### Code Quality Test
* pylint
```
cd bot
pylint main.py
pylint openai_helper.py
pylint telegram_bot.py
pylint usage_trackey.py
pylint utils.py
```

* Flake8
```
cd bot
flake8 main.py
flake8 openai_helper.py
flake8 telegram_bot.py
flake8 usage_trackey.py
flake8 utils.py
```
