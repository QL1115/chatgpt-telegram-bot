import atheris
import logging
import os
import sys
from dotenv import load_dotenv

from openai_helper import OpenAIHelper, default_max_tokens
from telegram_bot import ChatGPTTelegramBot

def fuzz_test(data):
    # Place the fuzzing logic here
    # This function will be called with various inputs by Atheris
    
    # Read .env file
    load_dotenv()

    # Setup logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )

    # Check if the required environment variables are set
    required_values = ['TELEGRAM_BOT_TOKEN', 'OPENAI_API_KEY']
    missing_values = [value for value in required_values if os.environ.get(value) is None]
    if len(missing_values) > 0:
        logging.error(f'The following environment values are missing in your .env: {", ".join(missing_values)}')
        exit(1)

    # Setup configurations
    model = os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo')
    max_tokens_default = default_max_tokens(model=model)
    openai_config = {
        'api_key': os.environ['OPENAI_API_KEY'],
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

    # ... Rest of the code ...


def main():
    # Fuzz the main function
    atheris.Setup(sys.argv, fuzz_test)
    atheris.Fuzz()

if __name__ == '__main__':
    main()
