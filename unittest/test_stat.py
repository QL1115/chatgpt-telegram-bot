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

from usage_tracker import UsageTracker 
from openai_helper import OpenAIHelper, localized_text
from telegram_bot import ChatGPTTelegramBot

class TelegramBotStatMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    def test_stat_is_not_allowed(self):
        async def fake_is_allowed(config, update, context):
            return False
        
        async def fake_send_disallowed_message(update, context):
            return True
        
        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.side_effect = fake_is_allowed
            with patch("telegram_bot.logging.warning") as mock_warning:
                mock_warning.return_value = None

                self.bot.send_disallowed_message = Mock(side_effect=fake_send_disallowed_message)

                mock_update = Mock(spec=Update)
                asyncio.run(self.bot.stats(update=mock_update, context=None))
                self.assertTrue(mock_warning.called)
                self.assertTrue(self.bot.send_disallowed_message.called)
    
    def test_stat_unlimited_budget(self):
        async def fake_is_allowed(config, update, context):
            return True

        async def fake_reply_text(usage_text, parse_mode):
            # unlimited budget: without stats_budget keyword in `usage_text`
            bot_language = self.bot.config['bot_language']
            keyword = f"{localized_text('stats_budget', bot_language)}"
            self.assertFalse(keyword in usage_text)
            return
        
        mock_update = Mock(spec=Update)
        
        mock_user = Mock(spec=UsageTracker)
        mock_user.get_current_token_usage.return_value = 2, 1
        mock_user.get_current_image_count.return_value = 2, 1
        mock_user.get_current_transcription_duration.return_value = 0, 0, 0, 0
        mock_user.get_current_cost.return_value = {"cost_today": 0, "cost_month": 0, "cost_all_time": 0}

        self.bot.usage = {0: mock_user}
        
        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text
        mock_message.from_user.id = 0
        mock_message.from_user.name = ""
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.side_effect = fake_is_allowed
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.get_remaining_budget") as mock_get_budget:
                    mock_get_budget.return_value = float('inf')
                    with patch("telegram_bot.is_admin") as mock_is_admin:
                        mock_is_admin.return_value = True

                        self.openai.get_conversation_stats.return_value = "fake message", 0
                        self.openai.get_billing_current_month.return_value = 100

                        self.bot.config['budget_period'] = "monthly"
                        self.bot.config['admin_user_ids'] = '-'
                        
                        asyncio.run(self.bot.stats(update=mock_update, context=None))
                        self.assertTrue(mock_message.reply_text.called)
                        self.assertTrue(self.openai.get_billing_current_month.called)

    def test_stat_limited_budget_and_not_in_usage(self):
        async def fake_is_allowed(config, update, context):
            return True

        async def fake_reply_text(usage_text, parse_mode):
            # limited budget: having stats_budget keyword in `usage_text`
            bot_language = self.bot.config['bot_language']
            keyword = f"{localized_text('stats_budget', bot_language)}"
            self.assertTrue(keyword in usage_text)
            return
        
        mock_update = Mock(spec=Update)
        
        mock_user = Mock(spec=UsageTracker)
        mock_user.get_current_token_usage.return_value = 2, 1
        mock_user.get_current_image_count.return_value = 2, 1
        mock_user.get_current_transcription_duration.return_value = 0, 0, 0, 0
        mock_user.get_current_cost.return_value = {"cost_today": 0, "cost_month": 0, "cost_all_time": 0}

        self.bot.usage = {}
        
        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text
        mock_message.from_user.id = 0
        mock_message.from_user.name = "fake username"
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.side_effect = fake_is_allowed
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.UsageTracker") as mock_UsageTracker:
                    mock_UsageTracker.return_value = mock_user
                    with patch("telegram_bot.get_remaining_budget") as mock_get_budget:
                        mock_get_budget.return_value = 1
                        with patch("telegram_bot.is_admin") as mock_is_admin:
                            mock_is_admin.return_value = False

                            self.openai.get_conversation_stats.return_value = "message", 0
                            self.openai.get_billing_current_month.return_value = 100

                            self.bot.config['budget_period'] = "monthly"
                            self.bot.config['admin_user_ids'] = '-'
                            
                            asyncio.run(self.bot.stats(update=mock_update, context=None))
                            self.assertTrue(mock_message.reply_text.called)
                            self.assertFalse(self.openai.get_billing_current_month.called)

    def test_stat_is_admin(self):
        async def fake_is_allowed(config, update, context):
            return True

        async def fake_reply_text(usage_text, parse_mode):
            # admin user: having stats_openai keyword in `usage_text`
            bot_language = self.bot.config['bot_language']
            adimin_keyword = f"{localized_text('stats_openai', bot_language)}"
            self.assertTrue(adimin_keyword in usage_text)
            return
        
        mock_update = Mock(spec=Update)
        
        mock_user = Mock(spec=UsageTracker)
        mock_user.get_current_token_usage.return_value = 2, 1
        mock_user.get_current_image_count.return_value = 2, 1
        mock_user.get_current_transcription_duration.return_value = 0, 0, 0, 0
        mock_user.get_current_cost.return_value = {"cost_today": 0, "cost_month": 0, "cost_all_time": 0}

        self.bot.usage = {0: mock_user}
        
        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text
        mock_message.from_user.id = 0
        mock_message.from_user.name = ""
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.side_effect = fake_is_allowed
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.get_remaining_budget") as mock_get_budget:
                    mock_get_budget.return_value = 1
                    with patch("telegram_bot.is_admin") as mock_is_admin:
                        mock_is_admin.return_value = True

                        self.openai.get_conversation_stats.return_value = "message", 0
                        self.openai.get_billing_current_month.return_value = 0

                        self.bot.config['budget_period'] = "monthly"
                        self.bot.config['admin_user_ids'] = '-'
                        
                        asyncio.run(self.bot.stats(update=mock_update, context=None))
                        self.assertTrue(mock_message.reply_text.called)
                        self.assertTrue(self.openai.get_billing_current_month.called)

    def test_stat_not_admin(self):
        async def fake_is_allowed(config, update, context):
            return True

        async def fake_reply_text(usage_text, parse_mode):
            # admin user: having stats_openai keyword in `usage_text`
            bot_language = self.bot.config['bot_language']
            keyword = f"{localized_text('stats_openai', bot_language)}"
            self.assertFalse(keyword in usage_text)
            return
        
        mock_update = Mock(spec=Update)
        
        mock_user = Mock(spec=UsageTracker)
        mock_user.get_current_token_usage.return_value = 2, 1
        mock_user.get_current_image_count.return_value = 2, 1
        mock_user.get_current_transcription_duration.return_value = 0, 0, 0, 0
        mock_user.get_current_cost.return_value = {"cost_today": 0, "cost_month": 0, "cost_all_time": 0}

        self.bot.usage = {0: mock_user}
        
        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text
        mock_message.from_user.id = 0
        mock_message.from_user.name = ""
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.side_effect = fake_is_allowed
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None
                with patch("telegram_bot.get_remaining_budget") as mock_get_budget:
                    mock_get_budget.return_value = 1
                    with patch("telegram_bot.is_admin") as mock_is_admin:
                        mock_is_admin.return_value = False

                        self.openai.get_conversation_stats.return_value = "message", 0
                        self.openai.get_billing_current_month.return_value = 0

                        self.bot.config['budget_period'] = "monthly"
                        self.bot.config['admin_user_ids'] = '-'
                        
                        asyncio.run(self.bot.stats(update=mock_update, context=None))
                        self.assertTrue(mock_message.reply_text.called)
                        self.assertFalse(self.openai.get_billing_current_month.called)
