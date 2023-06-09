import os
import argparse


lines = []
try:
    with open("app_test/api_config", 'r') as file:
        for line in file:
            # 去除行尾的换行符
            line = line.rstrip('\n')
            # 将每一行内容存入列表
            lines.append(line)
except FileNotFoundError:
    print("api_config文件未找到")
except IOError:
    print("讀取文件發生錯誤")

parser = argparse.ArgumentParser(description='ArgparseTry')
parser.add_argument(
    "--openai_key",
    type=str,
    default=lines[0]
)
parser.add_argument(
    "--telegram_token",
    type=str,
    default=lines[1]
)
parser.add_argument(
    "--admin_uid",
    type=str,
    default='-'
)
parser.add_argument(
    "--allowed_uid",
    type=str,
    default='*' 
)

args = parser.parse_args()
print(args)



openai_api_key = args.openai_key
telegram_bot_token = args.telegram_token
admin_user_ids = args.admin_uid
allowed_telegram_user_ids = args.allowed_uid



if os.environ.get('your_open_api_key'):
    openai_api_key = os.environ.get('your_open_api_key')
if os.environ.get('your_telegram_bot_key'):
    telegram_bot_token = os.environ.get('your_telegram_bot_key')

    
    
file_path = '.env.example'  # 替换为你要读取的文件路径

try:
    with open(file_path, 'r') as file:
        content = file.read()  # 读取整个文件内容
        #print(content)
except FileNotFoundError:
    print("文件未找到")
except IOError:
    print("读取文件时发生错误")



# print("please access https://platform.openai.com/account/api-keys to get your openAI api key")
# # Prompt user for input
# openai_api_key = input("Your OpenAI API key: ")

# print("please access https://t.me/botfather to get your Telegram Bot api key")

# telegram_bot_token = input("Your Telegram bot token: ")
# admin_user_ids = input("Comma-separated list of Telegram user ID of admins: (or - to assign no admin)")
# allowed_telegram_user_ids = input("Comma-separated list of allowed Telegram user IDs: (or * to allow all)")
# if (admin_user_ids == ''):
#     admin_user_ids = '-'
# if (allowed_telegram_user_ids == ''):
#     allowed_telegram_user_ids = '*' 
# Replace XXX with user input
content = content.replace('XXX', openai_api_key, 1)
content = content.replace('XXX', telegram_bot_token, 1)
content = content.replace('ADMIN_1_USER_ID,ADMIN_2_USER_ID', admin_user_ids, 1)
content = content.replace('USER_ID_1,USER_ID_2', allowed_telegram_user_ids, 1)


output_file_path = '.env'
# Write the updated content to a new file
with open('.env', 'w') as output_file:
    output_file.write(content)

print("Content has been written to the output file:", output_file_path)
print(content)
