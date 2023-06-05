import afl
import sys
from openai_helper import OpenAIHelper, default_max_tokens, localized_text
from telegram_bot import ChatGPTTelegramBot
from usage_tracker import UsageTracker
import logging
import os
import telegram
from dotenv import load_dotenv
from openai_helper import OpenAIHelper, default_max_tokens
from telegram_bot import ChatGPTTelegramBot
from main import main as chat_main
import utils
# Import your project modules or functions here
# For example:
# from myproject import myfunction

#afl.init()
# Create a configuration dictionary with your OpenAI API key and other settings
config = {
    'api_key': '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',
    'proxy': None,  # Set the proxy if needed
    'model': 'gpt-3.5-turbo',  # Set the desired GPT model
    'temperature': 0.8,
    'n_choices': 1,
    'max_tokens': 50,
    'presence_penalty': 0.0,
    'frequency_penalty': 0.0,
    'max_history_size': 3,
    'max_conversation_age_minutes': 60,
    'show_usage': True,
    'assistant_prompt': 'How can I assist you today?',
    'bot_language': 'en',
    'enable_image_generation': True,
    'image_prices': {
        'small': 0.1,
        'medium': 0.2,
        'large': 0.3
    },
    'enable_transcription': True,
    'transcription_price': 0.05,
    'voice_reply_transcript': False,
    'token_price': 0.01,
    'ignore_group_transcriptions': True,
    'budget_period': 'monthly',
    'allowed_user_ids': '5805709223,1,2,3',  # Replace with your own allowed user IDs
    'admin_user_ids': '-',
    'user_budgets': '*',
    'enable_quoting': True,
    'token':'5703123553:AAEoV-GEjK2Y904jwkn5NX6e39n9AE_-dI0'
    
}
class DummyOpenAIHelper:
    async def generate_image(self, prompt):
        return 'https://dummy-image-url.com', 'large'

    async def transcribe(self, audio_file):
        return 'This is a dummy transcript.'

    async def get_chat_response(self, chat_id, query):
        return 'This is a dummy response.', 10

class DummyUpdate:
    def __init__(self):
        self.effective_chat = DummyChat()
        #self.message = DummyChat()
        #self.effective_message = DummyChat()

class DummyChat:
    def __init__(self):
        self.id = 1
        #self.type = 'private'
        #self.is_topic_meassage = False
        #self.reply_price = 0


if __name__ == '__main__':
    afl.init()
    
    try:
        #pass
        # Create an instance of OpenAIHelper
            # Setup and run ChatGPT and Telegram bot
        openai_helper = OpenAIHelper(config)
        telegram_bot = ChatGPTTelegramBot(config, openai=openai_helper)
        #telegram_bot.run()
        #telegram_bot.run()
        # Test conversation stats
        chat_id = 1
        num_messages, num_tokens = openai_helper.get_conversation_stats(chat_id)
        print(f"Number of messages: {num_messages}")
        print(f"Number of tokens: {num_tokens}")

        # Test chat response
        # query = "Hello, how are you?"
        # answer, tokens_used = openai_helper.get_chat_response(chat_id, query)
        # print(f"Answer: {answer}")
        # print(f"Tokens used: {tokens_used}")

        # Test image generation
        # prompt = "Generate an image of a cat"
        # image_url, image_size = openai_helper.generate_image(prompt)
        # print(f"Image URL: {image_url}")
        # print(f"Image size: {image_size}")
        tracker = UsageTracker(user_id="5805709223", user_name="amy890202", logs_dir="usage_logs")

        # Example usage
        tracker.add_chat_tokens(100)
        #tracker.add_image_request("256x256")
        tracker.add_transcription_seconds(120)

        current_token_usage = tracker.get_current_token_usage()
        current_image_count = tracker.get_current_image_count()
        current_transcription_duration = tracker.get_current_transcription_duration()
        current_cost = tracker.get_current_cost()

        print("Current Token Usage:", current_token_usage)
        print("Current Image Count:", current_image_count)
        print("Current Transcription Duration:", current_transcription_duration)
        print("Current Cost:", current_cost)

        # Test audio transcription
        audio_filename = "audio.wav"
        transcription = openai_helper.transcribe(audio_filename)
        print(f"Transcription: {transcription}")
        
        bot = ChatGPTTelegramBot(config, DummyOpenAIHelper())
        # Create a dummy update object
        input_data = sys.stdin.buffer.read()
        update = input_data.decode('utf-8')  # Convert bytes to string
        update = update.strip()  # Remove trailing newline character

        update = DummyUpdate()
         # Read input from AFL queue
        
        # Test the 'help' command
        bot.help(update, None)

        # Test the 'stats' command
        bot.stats(update, None)

        # Test the 'resend' command
        bot.resend(update, None)

        # Test the 'reset' command
        bot.reset(update, None)

        # Test the 'image' command
        bot.image(update, None)

        # Test the 'transcribe' command
        bot.transcribe(update, None)
        bot.prompt(update, None)
        bot.inline_query(update, None)
        bot.send_inline_query_result(update, None,"hi")
        bot.handle_callback_inline_query(update, None)
        bot.edit_message_with_retry(update, None,1,"hi")
        #bot.wrap_with_indicator(update, None)
        bot.send_disallowed_message(update, None)
        bot.send_budget_reached_message(update, None)
        bot.error_handler(update, None)
        #bot.get_thread_id(update)
        #bot.get_stream_cutoff_values(update, None)
        #bot.is_group_chat(update)
        bot.is_user_in_group(update, None,1)
        bot.is_allowed(update, None)
        bot.is_admin(update, None)
        bot.get_user_budget(update)
        #bot.get_remaining_budget(update, None)
        #bot.is_within_budget(update, None)
        bot.check_allowed_and_within_budget(update, None)
        bot.add_chat_request_to_usage_tracker(update, None)
        #bot.get_reply_to_message_id(update)
        #bot.split_into_chunks(update, None)
        bot.post_init(update)
        # utils.message_text(telegram.Message(text="data"))
        # utils.is_user_in_group(update, telegram.ext.CallbackContext(), 123)
        # utils.get_thread_id(update, telegram.ext.CallbackContext())
        # utils.get_stream_cutoff_values(update, telegram.ext.CallbackContext())
        # utils.is_group_chat(update, telegram.ext.CallbackContext())
        # utils.split_into_chunks(update, telegram.ext.CallbackContext())
        # utils.error_handler(update, telegram.ext.CallbackContext())
        # utils.is_allowed(update, telegram.ext.CallbackContext())
        # utils.is_admin(update, telegram.ext.CallbackContext())
        # utils.get_user_budget(update)
        # utils.get_remaining_budget(update, telegram.ext.CallbackContext())
        # utils.is_within_budget(update, telegram.ext.CallbackContext())
        # utils.add_chat_request_to_usage_tracker(update, telegram.ext.CallbackContext())
        # utils.get_reply_to_message_id(update)
        # utils.edit_message_with_retry(update, telegram.ext.CallbackContext(), 1, "hi")
        # utils.wrap_with_indicator(update, telegram.ext.CallbackContext())

        # # Read input from AFL queue
        # input_data = sys.stdin.buffer.read()
        # update = input_data.decode('utf-8')  # Convert bytes to string
        # update = update.strip()  # Remove trailing newline character

        # # Fuzz the Telegram bot methods
        # telegram_bot.help(update, None)
        # telegram_bot.stats(update, None)
        # telegram_bot.resend(update, None)
        # telegram_bot.reset(update, None)
        # telegram_bot.image(update, None)
        # telegram_bot.transcribe(update, None)
        # telegram_bot.prompt(update, None)
        # telegram_bot.inline_query(update, None)
        # telegram_bot.send_inline_query_result(update, None, "hi")
        # telegram_bot.handle_callback_inline_query(update, None)
        # telegram_bot.edit_message_with_retry(update, None, 1, "hi")
        # telegram_bot.send_disallowed_message(update, None)
        # telegram_bot.send_budget_reached_message(update, None)
        # telegram_bot.error_handler(update, None)
        # telegram_bot.is_user_in_group(update, None, 1)
        # telegram_bot.is_allowed(update, None)
        # telegram_bot.is_admin(update, None)
        # telegram_bot.get_user_budget(update)
        # telegram_bot.check_allowed_and_within_budget(update, None)
        # telegram_bot.add_chat_request_to_usage_tracker(update, None)
        # telegram_bot.post_init(update)
        # #bot.run()
        chat_main()

        
        
    except Exception as e:
        logging.exception("An error occurred during execution.")