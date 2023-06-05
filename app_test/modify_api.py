file_path = '.env.example'  # 替换为你要读取的文件路径

try:
    with open(file_path, 'r') as file:
        content = file.read()  # 读取整个文件内容
        #print(content)
except FileNotFoundError:
    print("文件未找到")
except IOError:
    print("读取文件时发生错误")



print("please access https://platform.openai.com/account/api-keys to get your openAI api key")
# Prompt user for input
openai_api_key = input("Your OpenAI API key: ")

print("please access https://t.me/botfather to get your Telegram Bot api key")

telegram_bot_token = input("Your Telegram bot token: ")
admin_user_ids = input("Comma-separated list of Telegram user ID of admins: (or - to assign no admin)")
allowed_telegram_user_ids = input("Comma-separated list of allowed Telegram user IDs: (or * to allow all)")
if (admin_user_ids == ''):
    admin_user_ids = '-'
if (allowed_telegram_user_ids == ''):
    allowed_telegram_user_ids = '*' 
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
