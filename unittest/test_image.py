import asyncio
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import os
import sys
import pathlib
current_path = str(pathlib.Path().resolve())
splits = current_path.replace("\\", "/").split("/")
current_path = splits[:-1]

path = "/".join(current_path) + "/bot"
sys.path.insert(0, path)

from openai_helper import OpenAIHelper
from telegram_bot import ChatGPTTelegramBot
from usage_tracker import UsageTracker

from telegram import Update

class TelegramBotImageMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    def test_image_not_enable_image_generation(self):
        mock_update = Mock(wraps=Update)

        self.bot.config['enable_image_generation'] = False
        self.bot.check_allowed_and_within_budget = Mock(side_effect=None)

        asyncio.run(self.bot.image(update=mock_update, context=None))
        self.assertFalse(self.bot.check_allowed_and_within_budget.called)

    def test_image_within_budget(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return False

        mock_update = Mock(wraps=Update)
        
        self.bot.config['enable_image_generation'] = True
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        asyncio.run(self.bot.image(update=mock_update, context=None))
        self.assertTrue(self.bot.check_allowed_and_within_budget.called)

    def test_image_empty_image_query(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        async def fake_reply_text(message_thread_id, text):
            return

        with patch("telegram_bot.message_text") as fake_message_text:
            fake_message_text.return_value = ''

            mock_update = Mock(spec=Update)
            mock_update.effective_message.reply_text = Mock(side_effect=fake_reply_text)
        
            self.bot.config['enable_image_generation'] = True
            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

            asyncio.run(self.bot.image(update=mock_update, context=None))
            self.assertTrue(self.bot.check_allowed_and_within_budget.called)
            self.assertTrue(fake_message_text.called)
            self.assertTrue(mock_update.effective_message.reply_text.called)

    def test_image_generate_with_user_is_guest(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True

        async def fake_mock_wrap_with_indicator(update, context, coroutine, chat_action, is_inline=False):
            task = asyncio.create_task(coroutine())
            while not task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(task), 3)
                except asyncio.TimeoutError:
                    pass
                    return 
            return
        
        mock_user = Mock(spec=UsageTracker)
        mock_guest = Mock(spec=UsageTracker)
        mock_user.add_image_request.return_value = None
        mock_guest.add_image_request.return_value = None
        self.bot.usage = {0: mock_user, "guests": mock_guest}
        self.bot.config['allowed_user_ids'] = ""
        self.bot.config['image_prices'] = 0.001

        with patch("telegram_bot.message_text") as fake_message_text:
            fake_message_text.return_value = 'test image query'
            self.bot.config['enable_image_generation'] = True
            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                    mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0

                        async def fake_generate_image(prompt):
                            return "url", 100

                        async def fake_reply_photo(reply_to_message_id, photo):
                            return
                        
                        mock_update = Mock(spec=Update)
                        mock_update.effective_message.reply_photo.side_effect = fake_reply_photo
                        mock_update.message.from_user.id = 0

                        self.bot.openai.generate_image.side_effect = fake_generate_image

                        asyncio.run(self.bot.image(update=mock_update, context=None))
                        self.assertTrue(mock_guest.add_image_request.called)
                        self.assertTrue(mock_get_reply_to_message_id.called)
                        
    def test_image_generate_with_raise_exception(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True

        async def fake_mock_wrap_with_indicator(update, context, coroutine, chat_action, is_inline=False):
            task = asyncio.create_task(coroutine())
            while not task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(task), 3)
                except asyncio.TimeoutError:
                    pass
                    return 
            return

        with patch("telegram_bot.message_text") as fake_message_text:
            fake_message_text.return_value = 'test image'
            self.bot.config['enable_image_generation'] = True
            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                    mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator

                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0

                        with patch("telegram_bot.logging.exception") as mock_exception:
                            mock_exception.return_value = None

                            # generate execption
                            async def fake_generate_image(prompt):
                                raise Exception("test exception")
                            
                            self.bot.openai.generate_image.side_effect = fake_generate_image

                            async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode):
                                return

                            async def fake_reply_photo(reply_to_message_id, photo):
                                return

                            mock_update = Mock(spec=Update)
                            mock_update.effective_message.reply_text.side_effect = fake_reply_text
                            mock_update.effective_message.reply_photo.side_effect = fake_reply_photo
                            mock_update.message.from_user.id = 0

                            asyncio.run(self.bot.image(update=mock_update, context=None))
                            self.assertTrue(self.bot.openai.generate_image.called)
                            self.assertTrue(mock_exception.called)
                            