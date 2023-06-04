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

from openai_helper import OpenAIHelper, localized_text, default_max_tokens
from telegram_bot import ChatGPTTelegramBot

class TelegramBotHelpMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    def test_help_is_group(self):

        async def fake_reply_text(help_text, disable_web_page_preview):
            bot_language = self.bot.config['bot_language']
            group_command_keywords = localized_text('chat_description', bot_language)

            # check group chat keywords: "/chat 與機器人聊天！"
            self.assertTrue(group_command_keywords in help_text)

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = True

            mock_update = Mock(spec=Update)
            mock_message = Mock(wraps=Message)
            mock_message.reply_text.side_effect = fake_reply_text
            mock_update.message = mock_message
            
            asyncio.run(self.bot.help(update=mock_update, _=None))
            self.assertTrue(mock_message.reply_text.called)

    # success
    def test_help_not_group(self):
        mock_update = Mock(spec=Update)

        async def fake_reply_text(help_text, disable_web_page_preview):
            bot_language = self.bot.config['bot_language']
            group_command_keywords = localized_text('chat_description', bot_language)

             # check no group chat keywords: "/chat 與機器人聊天！"
            self.assertFalse(group_command_keywords in help_text)

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            mock_message = Mock(wraps=Message)
            mock_message.reply_text.side_effect = fake_reply_text
            mock_update.message = mock_message
            
            asyncio.run(self.bot.help(update=mock_update, _=None))
            self.assertTrue(mock_message.reply_text.called)