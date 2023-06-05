import atheris
import sys
from openai_helper import OpenAIHelper

def test_openai_helper(data):
    # Initialize OpenAIHelper
    config = {
        'api_key': 'YOUR_API_KEY',
        'proxy': None,  # Optional proxy configuration
        # Add other configuration options as needed
    }
    openai_helper = OpenAIHelper(config)

    # Run your test code
    try:
        # Call the OpenAIHelper methods you want to test
        # For example:
        chat_id = 1
        query = "Hello, how are you?"
        response = openai_helper.get_chat_response(chat_id, query)
        print(response)
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # Fuzzing entry point
    atheris.Setup(sys.argv, test_openai_helper)
    atheris.Fuzz()

if __name__ == '__main__':
    main()
