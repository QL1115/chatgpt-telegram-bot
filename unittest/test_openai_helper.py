import asyncio
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from openai import ChatCompletion, Image, Audio
from bot.openai_helper import OpenAIHelper
from bot.openai_helper import default_max_tokens, localized_text, GPT_3_MODELS, GPT_4_MODELS, GPT_4_32K_MODELS

class TestOpenAIHelper(unittest.TestCase):
    def setUp(self):
        # 模擬一個有效的配置
        self.config = {
            'api_key': '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',
            'proxy': None,  # 可根據需要設置代理
            'assistant_prompt': 'Assistant prompt text',  # 添加 assistant_prompt
            'model': 'gpt-3.5-turbo'  # 添加 model
        }
        self.openai_helper = OpenAIHelper(self.config)

    def tearDown(self):
        self.openai_helper = None

    def test_default_max_tokens(self):
        for model in GPT_3_MODELS:
            self.assertEqual(default_max_tokens(model), 1200)
        for model in GPT_4_MODELS + GPT_4_32K_MODELS:
            self.assertEqual(default_max_tokens(model), 2400)

    # 模擬translations.json中的內容
    @patch('bot.openai_helper.translations', { 
        'en': {
            'hello': 'Hello',
            'world': 'World'
        },
        'zh': {
            'hello': '你好',
            'world': '世界'
        }
    })
    def test_localized_text(self):
        
        # # 將模擬的translations賦值給OpenAIHelper的translations
        # self.openai_helper.translations = translations

        # 測試已翻譯的文本
        self.assertEqual(localized_text('hello', 'zh'), '你好')
        self.assertEqual(localized_text('world', 'zh'), '世界')

        # 測試翻譯未找到時的回退到英文
        self.assertEqual(localized_text('hello', 'fr'), 'Hello')
        self.assertEqual(localized_text('world', 'fr'), 'World')

        # 測試翻譯和英文回退都未找到時的返回鍵本身
        self.assertEqual(localized_text('foo', 'zh'), 'foo')
        self.assertEqual(localized_text('bar', 'fr'), 'bar')

    async def test_get_conversation_stats(self):
        chat_id = 1
        # 測試未初始化對話的情況
        messages, tokens = self.openai_helper.get_conversation_stats(chat_id)
        self.assertEqual(messages, 0)
        self.assertEqual(tokens, 0)

        # 模擬對話
        self.openai_helper.conversations[chat_id] = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ]
        messages, tokens = await self.openai_helper.get_conversation_stats(chat_id)
        self.assertEqual(messages, 2)
        self.assertEqual(tokens, 8)  # 每個消息4個token

    async def test_get_chat_response(self):  # 添加 async
        chat_id = 1
        query = "What's the weather today?"

        # 模擬ChatCompletion.acreate的回應
        response_mock = MagicMock(spec=ChatCompletion.acreate)
        response_mock.choices = [
            {"message": {"content": "The weather is sunny."}},
            {"message": {"content": "It's raining today."}}
        ]
        response_mock.usage = {
            "total_tokens": 20,
            "prompt_tokens": 2,
            "completion_tokens": 18
        }
        self.openai_helper.__common_get_chat_response = MagicMock(return_value=response_mock)

        answer, tokens = await self.openai_helper.get_chat_response(chat_id, query)  # 使用 await

        # 驗證回應和token數量
        self.assertEqual(answer, "The weather is sunny.")
        self.assertEqual(tokens, 20)

        # 驗證對話記錄
        self.assertEqual(len(self.openai_helper.conversations[chat_id]), 3)  # 包括系統提示
        self.assertEqual(self.openai_helper.conversations[chat_id][2]["role"], "assistant")
        self.assertEqual(self.openai_helper.conversations[chat_id][2]["content"], "The weather is sunny.")

    def test_config(self):
        self.assertEqual(self.openai_helper.config['api_key'], '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')
        self.assertEqual(self.openai_helper.config['model'], 'gpt-3.5-turbo')

    async def test_reset_conversation(self):
        chat_id = 1
        self.openai_helper.conversations[chat_id] = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ]
        await self.openai_helper.reset_conversation(chat_id)
        self.assertEqual(len(self.openai_helper.conversations[chat_id]), 0)

    async def test_get_max_tokens(self):
        self.assertEqual(self.openai_helper.get_max_tokens('gpt-3.5-turbo'), 1200)
        self.assertEqual(self.openai_helper.get_max_tokens('gpt-4'), 2400)

    async def test_should_stop(self):
        self.assertTrue(self.openai_helper.should_stop('You: stop'))
        self.assertFalse(self.openai_helper.should_stop('You: continue'))

    async def test_update_conversation_stats(self):
        chat_id = 1
        self.openai_helper.update_conversation_stats(chat_id, 2, 8)
        self.assertEqual(self.openai_helper.conversation_stats[chat_id]['messages'], 2)
        self.assertEqual(self.openai_helper.conversation_stats[chat_id]['tokens'], 8)

    async def test_strip_assistant_prompt(self):
        self.assertEqual(self.openai_helper.strip_assistant_prompt('Assistant prompt text: Hello'), 'Hello')

    async def test_filter_response(self):
        self.assertEqual(self.openai_helper.filter_response('Hello\n- OpenAI GPT-3.5-turbo'), 'Hello')

    async def test_get_default_model(self):
        self.assertEqual(self.openai_helper.get_default_model(), 'gpt-3.5-turbo')

    async def test_get_assistant_prompt(self):
        self.assertEqual(self.openai_helper.get_assistant_prompt(), 'Assistant prompt text')

    async def test_get_model(self):
        self.assertEqual(self.openai_helper.get_model(), 'gpt-3.5-turbo')

if __name__ == '__main__':  # pragma: no cover
    asyncio.run(unittest.main())

