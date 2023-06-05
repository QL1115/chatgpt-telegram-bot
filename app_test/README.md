# chatGPTbot_Testing
## selenium
test for chat_ai
```
python app_test.py
```


test for chat_ai group
```
python app_test_group.py
```

## fuzz test

```
python main_fuzz.py
python openai_helper_fuzz.py
python telegram_bot_fuzz.py
python usage_tracker_fuzz.py
```

## AFL_test
in venv
```
py-afl-fuzz -m 200 -t 5000+ -o results/ -i bot/ -- python bot/afl_test.py
```
*note: you need to comment out the `telegram_bot.run()` in main.py line83 or you will get timeout error for AFL test.

```
 py-afl-fuzz -m 200 -t 5000+ -o results/ -i bot/ -- python fuzz_test/afl_test.py
```


## run.sh
```
bash run.sh
```

## modify_api & env_setting
* modify_api: modify api by directly input
* env_setting:modify api by parameter(dafult by the api_config file)
you can choose the method you want (by input or by dby api_config file) by modify run.sh 
* by input: `python app_test/modify_api.py`   (default)
* by api_config file: `python app_test/env_setting.py`

## api_config file
modify `app_test/api_config` file to
```
${your_open_api key} 
${your_telegram_bot_key}
````