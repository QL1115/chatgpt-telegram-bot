import asyncio
import unittest
from unittest.mock import Mock, MagicMock
from unittest.mock import patch

import os
import sys
import pathlib
current_path = str(pathlib.Path().resolve())
splits = current_path.replace("\\", "/").split("/")
current_path = splits[:-1]

path = "/".join(current_path) + "/bot"
sys.path.insert(0, path)

from telegram import Update
from telegram._message import Message

from openai_helper import OpenAIHelper, localized_text, default_max_tokens
from telegram_bot import ChatGPTTelegramBot


class TelegramBotResendMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    def test_resend_is_not_allowed(self):
        async def fake_send_disallowed_message(update, context):
            return
        
        mock_update = Mock(spec=Update)

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = False
            with patch("telegram_bot.logging.warning") as mock_warning:
                mock_warning.return_value = None

                self.bot.send_disallowed_message = Mock(side_effect=fake_send_disallowed_message)

                asyncio.run(self.bot.resend(update=mock_update, context=None))
                self.assertTrue(self.bot.send_disallowed_message.called)
    
    def test_resend_not_last_message(self):
        async def fake_reply_text(message_thread_id, text):
            return
        
        mock_update = Mock(spec=Update)
        mock_update.effective_chat.id = 0

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = True
            with patch("telegram_bot.logging.warning") as mock_warning:
                mock_warning.return_value = None

                mock_message = Mock(wraps=Message)
                mock_message.reply_text.side_effect = fake_reply_text
                mock_update.effective_message = mock_message

                asyncio.run(self.bot.resend(update=mock_update, context=None))
                self.assertTrue(mock_update.effective_message.reply_text.called)
                self.assertTrue(mock_message.reply_text.called)

    def test_resend_last_message(self):
        async def fake_prompt(update, context):
            return

        chat_id = 1
        mock_update = Mock(spec=Update)
        mock_update.effective_chat.id = chat_id
        self.bot.last_message = {0: "fake message", 1: "hello"}

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = True
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None

                mock_message = MagicMock()
                mock_message.__enter__ = Mock(return_value=(Mock(), None))
                mock_message.__exit__ = Mock(return_value=None)

                mock_update.message = mock_message
                self.bot.prompt = Mock(side_effect=fake_prompt)

                asyncio.run(self.bot.resend(update=mock_update, context=None))
                self.assertTrue(self.bot.prompt.called)
