import asyncio
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import os
import sys
import pathlib
current_path = str(pathlib.Path().resolve())
splits = current_path.split("\\")
current_path = splits[:-1]

sys.path.append("\\".join(current_path) + "\\bot")

from telegram import Update
from telegram._message import Message

from openai_helper import OpenAIHelper
from telegram_bot import ChatGPTTelegramBot

class TelegramBotResetMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    def test_reset_is_not_allowed(self):
        async def fake_send_disallowed_message(update, context):
            return

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = False
            with patch("telegram_bot.logging.warning") as mock_warning:
                mock_warning.return_value = None

                self.bot.send_disallowed_message = Mock(side_effect=fake_send_disallowed_message)
                mock_update = Mock(spec=Update)

                asyncio.run(self.bot.reset(update=mock_update, context=None))
                self.assertTrue(mock_warning.called)
                self.assertTrue(self.bot.send_disallowed_message.called)

    def test_reset_is_allowed(self):
        async def fake_reply_text(message_thread_id, text):
            return
        
        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = True
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.message_text") as mock_message_text:
                    mock_message_text.return_value = "test content"

                    mock_update = Mock(spec=Update)
                    mock_update.effective_chat.id = 0

                    mock_message = Mock(wraps=Message)
                    mock_message.reply_text.side_effect = fake_reply_text
                    mock_update.effective_message = mock_message

                    self.bot.openai.reset_chat_history.return_value = None
                    self.openai.reset_chat_history = Mock(return_value=None)

                    asyncio.run(self.bot.reset(update=mock_update, context=None))
                    self.assertTrue(mock_info.called)
                    self.assertTrue(mock_message_text.called)
                    self.assertTrue(self.bot.openai.reset_chat_history.called)
                    self.assertTrue(mock_message.reply_text.called)
