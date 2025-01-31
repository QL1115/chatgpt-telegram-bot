import sys
import atheris
#import telegram_bot
from telegram_bot import ChatGPTTelegramBot
import telegram
import os
from openai_helper import OpenAIHelper, default_max_tokens
import datetime
from telegram import Message, MessageEntity, Update, InputTextMessageContent, BotCommand, ChatMember
import telegram.ext  # 新增這行
from functools import partial
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, \
    filters, InlineQueryHandler, CallbackQueryHandler, Application, CallbackContext

# Setup configurations
model = os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo')
max_tokens_default = default_max_tokens(model=model)
openai_config = {
    'api_key': 'XXX',
    'show_usage': os.environ.get('SHOW_USAGE', 'false').lower() == 'true',
    'stream': os.environ.get('STREAM', 'true').lower() == 'true',
    'proxy': os.environ.get('PROXY', None),
    'max_history_size': int(os.environ.get('MAX_HISTORY_SIZE', 15)),
    'max_conversation_age_minutes': int(os.environ.get('MAX_CONVERSATION_AGE_MINUTES', 180)),
    'assistant_prompt': os.environ.get('ASSISTANT_PROMPT', 'You are a helpful assistant.'),
    'max_tokens': int(os.environ.get('MAX_TOKENS', max_tokens_default)),
    'n_choices': int(os.environ.get('N_CHOICES', 1)),
    'temperature': float(os.environ.get('TEMPERATURE', 1.0)),
    'image_size': os.environ.get('IMAGE_SIZE', '512x512'),
    'model': model,
    'presence_penalty': float(os.environ.get('PRESENCE_PENALTY', 0.0)),
    'frequency_penalty': float(os.environ.get('FREQUENCY_PENALTY', 0.0)),
    'bot_language': os.environ.get('BOT_LANGUAGE', 'en'),
}

telegram_config = {
    'token': 'XXX',
    'admin_user_ids': os.environ.get('ADMIN_USER_IDS', '-'),
    'enable_quoting': os.environ.get('ENABLE_QUOTING', 'true').lower() == 'true',
    'enable_image_generation': os.environ.get('ENABLE_IMAGE_GENERATION', 'true').lower() == 'true',
    'enable_transcription': os.environ.get('ENABLE_TRANSCRIPTION', 'true').lower() == 'true',
    'budget_period': os.environ.get('BUDGET_PERIOD', 'monthly').lower(),
    'user_budgets': os.environ.get('USER_BUDGETS', os.environ.get('MONTHLY_USER_BUDGETS', '*')),
    'guest_budget': float(os.environ.get('GUEST_BUDGET', os.environ.get('MONTHLY_GUEST_BUDGET', '100.0'))),
    'stream': os.environ.get('STREAM', 'true').lower() == 'true',
    'proxy': os.environ.get('PROXY', None),
    'voice_reply_transcript': os.environ.get('VOICE_REPLY_WITH_TRANSCRIPT_ONLY', 'false').lower() == 'true',
    'ignore_group_transcriptions': os.environ.get('IGNORE_GROUP_TRANSCRIPTIONS', 'true').lower() == 'true',
    'group_trigger_keyword': os.environ.get('GROUP_TRIGGER_KEYWORD', ''),
    'token_price': float(os.environ.get('TOKEN_PRICE', 0.002)),
    'image_prices': [float(i) for i in os.environ.get('IMAGE_PRICES', "0.016,0.018,0.02").split(",")],
    'transcription_price': float(os.environ.get('TOKEN_PRICE', 0.006)),
    'bot_language': os.environ.get('BOT_LANGUAGE', 'en'),
}

def TestOneInput(data):
    # 創建一個空的 Bot 對象
    bot = telegram.Bot('XXX')
    bot_chat = telegram.Chat(1, type=telegram.Chat.PRIVATE)
    #application = telegram.ext.AppContext()
    
    # 創建一個空的 Update 對象
    update = telegram.Update(
        update_id=1,
        message=telegram.Message(
            message_id=1,
            date=datetime.datetime.utcnow(),
            chat=bot_chat,
            text=data,
        ),
    )

    # 創建一個空的 context 對象
    context = telegram.ext.CallbackContext(None)

    # 將 Bot 對象作為參數傳遞給 message 處理函式
   # 將 Bot 對象作為參數傳遞給 handle_message 函式
    # message_handler = partial(ChatGPTTelegramBot.prompt, bot=bot)
    # update=update, context=context

    # 調用消息處理函式
    ChatGPTTelegramBot.prompt(bot,update=update, context=context)


def main():
    # 设置模糊测试超时时间为 10 秒
    openai_helper = OpenAIHelper(config=openai_config)
    atheris.Setup(["telegram_bot_fuzz.py"], TestOneInput, enable_python_coverage=False)

    # 启动模糊测试循环
    atheris.Fuzz()

if __name__ == "__main__":
    main()




