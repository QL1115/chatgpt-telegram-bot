import asyncio
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import os
from uuid import uuid4
import sys
import pathlib
current_path = str(pathlib.Path().resolve())
splits = current_path.split("\\")
current_path = splits[:-1]

sys.path.append("\\".join(current_path) + "\\bot")

from telegram import BotCommandScopeAllGroupChats, CallbackQuery, InlineKeyboardMarkup, Update, User
from telegram.error import RetryAfter, TimedOut
from telegram._inline.inlinequery import InlineQuery
from telegram._message import Message
from telegram.ext import CallbackContext

from openai_helper import OpenAIHelper
from telegram_bot import ChatGPTTelegramBot

class BotTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    # @unittest.skip("demonstrating skipping")
    def test_inline_query_length_than_3(self):
        """
        Handle the inline query with not exceed budget.
        """

        mock_update = Mock(wraps=Update)
        mock_update.inline_query.query = "12"

        async def fake_check_allowed_and_within_budget(update, context, is_inline):
            return True
        
        async def fake_send_inline_query_result(update, result_id, message_content, callback_data):
            return 
        
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        self.bot.send_inline_query_result = Mock(side_effect=fake_send_inline_query_result) 

        asyncio.run(self.bot.inline_query(update=mock_update, context=None))

        self.assertFalse(self.bot.check_allowed_and_within_budget.called)
        self.assertFalse( self.bot.send_inline_query_result.called)  

    # @unittest.skip("demonstrating skipping")
    def test_inline_query_limited_budget(self):
        """
        Handle the inline query with not exceed budget.
        """

        mock_update = Mock(wraps=Update)
        mock_update.inline_query.query = "123456"

        async def fake_check_allowed_and_within_budget(update, context, is_inline):
            return False
        
        async def fake_send_inline_query_result(update, result_id, message_content, callback_data):
            return 

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        self.bot.send_inline_query_result = Mock(side_effect=fake_send_inline_query_result) 

        asyncio.run(self.bot.inline_query(update=mock_update, context=None))

        self.assertTrue(self.bot.check_allowed_and_within_budget.called)
        self.assertFalse(self.bot.send_inline_query_result.called)

    # @unittest.skip("demonstrating skipping")
    def test_inline_query_normally(self):
        """
        Handle the inline query with not exceed budget.
        """

        mock_update = Mock(wraps=Update)
        mock_update.inline_query.query = "123456"

        async def fake_check_allowed_and_within_budget(update, context, is_inline):
            return True
        
        async def fake_send_inline_query_result(update, result_id, message_content, callback_data):
            return 

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        self.bot.send_inline_query_result = Mock(side_effect=fake_send_inline_query_result) 
    
        asyncio.run(self.bot.inline_query(update=mock_update, context=None))

        self.assertTrue(self.bot.check_allowed_and_within_budget.called)
        self.assertTrue(self.bot.send_inline_query_result.called) 

    # @unittest.skip("demonstrating skipping")
    def test_send_inline_query_result_with_empty_callback_data(self):
        mock_update = Mock(wraps=Update)
        mock_inquery = Mock(wraps=InlineQuery)
        mock_inquery.answer.return_value = "OK"
        mock_update.inline_query = mock_inquery

        result_id = str(uuid4())
        asyncio.run(self.bot.send_inline_query_result(update=mock_update, result_id=result_id, message_content="cc", callback_data=""))
        self.assertTrue(mock_inquery.answer.called)

    # @unittest.skip("demonstrating skipping")
    def test_send_inline_query_result_with_callback_data(self):

        mock_update = Mock(wraps=Update)
        mock_inquery = Mock(wraps=InlineQuery)
        mock_inquery.answer.return_value = "OK"
        mock_update.inline_query = mock_inquery

        with patch("telegram_bot.InlineKeyboardMarkup") as mock_InlineKeyboardMarkup:
            mock_InlineKeyboardMarkup.return_value = ""
            with patch("telegram_bot.InlineKeyboardButton") as mock_InlineKeyboarddButton:
                mock_InlineKeyboarddButton.return_value = ""

                result_id = str(uuid4())
                asyncio.run(self.bot.send_inline_query_result(update=mock_update, result_id=result_id, message_content="cc", callback_data="hi"))
                self.assertTrue(mock_InlineKeyboardMarkup.called)

    # @unittest.skip("demonstrating skipping")
    def test_handle_callback_inline_query_not_get_query(self):
        mock_update = Mock(spec=Update)

        mock_callback_query = Mock(wraps=CallbackQuery)
        mock_callback_query.data = "gpt:00"
        mock_callback_query.from_user.id = 0
        mock_callback_query.inline_message_id = 0
        mock_callback_query.from_user.name = "name"

        mock_update.callback_query = mock_callback_query

        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
            mock_edit_message_with_retry.return_value = None

            asyncio.run(self.bot.handle_callback_inline_query(update=mock_update, context=Mock(spec=CallbackContext)))
            self.assertTrue(mock_edit_message_with_retry.called)

    # @unittest.skip("demonstrating skipping")
    def test_handle_callback_inline_query_get_query_with_no_stream(self):
        async def fake_mock_wrap_with_indicator(update, context, coroutine, chat_action, is_inline=False):
            task = asyncio.create_task(coroutine())
            while not task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(task), 3)
                except asyncio.TimeoutError:
                    pass
                    return 
            return

        async def fake_get_chat_response_stream(chat_id, query):
            yield "test2", 2
        self.openai.get_chat_response_stream = Mock(side_effect=fake_get_chat_response_stream)

        mock_callback_query = Mock(wraps=CallbackQuery)
        mock_callback_query.from_user.id = 0
        mock_callback_query.inline_message_id = 0
        mock_callback_query.from_user.name = "name"
        mock_callback_query.data = "gpt:00"

        mock_update = Mock(spec=Update)
        mock_update.callback_query = mock_callback_query

        self.bot.inline_queries_cache = {"00": "test"}
        self.bot.config['stream'] = ""

        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
            mock_edit_message_with_retry.return_value = None
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                    mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                    with patch("telegram_bot.logging.info") as mock_info:
                        mock_info.return_value = None
                        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                            mock_edit_message_with_retry.return_value = None
                            with patch("telegram_bot.add_chat_request_to_usage_tracker") as mock_add_chat_request_to_usage_tracker:
                                mock_add_chat_request_to_usage_tracker.return_value = None

                                async def fake_get_chat_response(chat_id, query):
                                    return "response", 2
                                self.bot.openai.get_chat_response.side_effect = fake_get_chat_response 

                                async def fake_edit_message_text(inline_message_id, text, parse_mode):
                                    return
                                
                                mock_context = Mock(spec=CallbackContext)
                                mock_context.bot.edit_message_text.side_effect = fake_edit_message_text

                                asyncio.run(self.bot.handle_callback_inline_query(update=mock_update, context=mock_context))
                                self.assertTrue(mock_edit_message_with_retry.called)
                                self.assertTrue(self.bot.openai.get_chat_response.called)
                                self.assertTrue(mock_add_chat_request_to_usage_tracker.called)

    # @unittest.skip("demonstrating skipping")
    def test_handle_callback_inline_query(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "fake_message_text"
        
        async def reply_chat_action(action, message_thread_id):
            return
        
        async def get_get_chat_response_stream(chat_id, query):
            yield "", 0
            yield "test2", 2
            yield "RetryAfter case", 3
            yield "TimedOut case", 4
            yield "Exception case", 5
            yield "No Exception", 6
            yield "No Exception", 7

        async def fake_reply_text(message_thread_id, text, reply_to_message_id=None):
            mock_message = Mock(spec=Message)
            mock_message.chat_id = 1
            mock_message.message_id = 1
            return mock_message

        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False
        mock_update.callback_query.data = "gpt:00" 
        mock_update.message.reply_to_message.return_value = True
        mock_update.message.reply_to_message.from_user.id = 0
        mock_update.effective_message.reply_chat_action = Mock(side_effect=reply_chat_action)
        mock_update.effective_message.reply_text.side_effect = fake_reply_text

        self.bot.inline_queries_cache = {"00": "test"}
        self.bot.config['stream'] = "test"
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        async def fake_delete_message(chat_id, message_id):
            return
        
        mock_context = Mock(spec=CallbackContext)
        mock_context.bot.id = 0 
        mock_context.bot.delete_message.side_effect = fake_delete_message

        self.openai.get_chat_response_stream = Mock(side_effect=get_get_chat_response_stream)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = False
                    with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                        mock_edit_message_with_retry.return_value = None
                        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                            async def fake_edit_message_with_retry(context, chat_id, message_id, text, markdown=True, is_inline=False):
                                if("RetryAfter" in text):
                                    raise RetryAfter(1)
                                elif("TimedOut" in text):
                                    raise TimedOut("exception: TimedOut")
                                elif ("Exception" in text):
                                    raise Exception("oops")
                                else:
                                    return
                            mock_edit_message_with_retry.side_effect = fake_edit_message_with_retry

                            with patch("telegram_bot.get_stream_cutoff_values") as mock_get_stream_cutoff_values:
                                mock_get_stream_cutoff_values.return_value = 1
                                with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                                    mock_get_reply_to_message_id.return_value = 0
                                    with patch("telegram_bot.asyncio.sleep") as mock_sleep:
                                        async def fake_sleep(time):
                                            return
                                        mock_sleep.side_effect = fake_sleep

                                        asyncio.run(self.bot.handle_callback_inline_query(update=mock_update, context=Mock(spec=CallbackContext)))
                                        self.assertTrue(mock_edit_message_with_retry.called)
                                        self.assertEqual(mock_sleep.call_count, 2)
    
    # @unittest.skip("demonstrating skipping")
    def test_handle_callback_inline_query_with_exception(self):
        mock_callback_query = Mock(wraps=CallbackQuery)
        mock_callback_query.data = 1
        mock_callback_query.from_user.id = 0
        mock_callback_query.inline_message_id = 0
        mock_callback_query.from_user.name = "name"

        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
            mock_edit_message_with_retry.return_value = None
            with patch("telegram_bot.logging.exception") as mock_exception:
                mock_exception.return_value = None
                with patch("telegram_bot.logging.error") as mock_error:
                    mock_error.return_value = None
                    with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                        async def fake_edit_message_with_retry(context, chat_id, message_id, text, is_inline):
                            return
                        mock_edit_message_with_retry.side_effect = fake_edit_message_with_retry

                        mock_update = Mock(spec=Update)
                        asyncio.run(self.bot.handle_callback_inline_query(update=mock_update, context=Mock(spec=CallbackContext)))
                        self.assertTrue(mock_error.called)
                        self.assertTrue(mock_edit_message_with_retry.called)

    # @unittest.skip("demonstrating skipping")
    def test_check_not_allowed(self):
        async def fake_send_disallowed_message(update, context, is_inline):
            return
        
        user_id = str(uuid4())
        mock_user = Mock(spec=User)
        mock_user.name.ret = "fake_name"
        mock_user.id.return_value = user_id

        mock_inline_query = Mock(spec=InlineQuery, from_user=mock_user)
        mock_message = Mock(spec=Message, from_user=mock_user)

        mock_update = Mock(spec=Update)
        mock_update.inline_query = mock_inline_query
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = False
            with patch("telegram_bot.logging.warning") as mock_warning:
                mock_warning.return_value = None
                self.bot.send_disallowed_message = Mock(side_effect=fake_send_disallowed_message)
                
                asyncio.run(self.bot.check_allowed_and_within_budget(mock_update, Mock()))
                self.assertTrue(mock_warning.called)
                self.assertTrue(self.bot.send_disallowed_message.called)

    # @unittest.skip("demonstrating skipping")
    def test_check_allowed_and_within_budget(self):
        user_id = str(uuid4())
        mock_user = Mock(spec=User)
        mock_user.name.ret = "fake_name"
        mock_user.id.return_value = user_id

        mock_inline_query = Mock(spec=InlineQuery, from_user=mock_user)
        mock_message = Mock(spec=Message, from_user=mock_user)
        
        mock_update = Mock(spec=Update)
        mock_update.inline_query = mock_inline_query
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = True
            with patch("telegram_bot.is_within_budget") as mock_is_within_budget:
                mock_is_within_budget.return_value = True
                with patch("telegram_bot.logging.warning") as mock_warning:
                    mock_warning.return_value = None
                    asyncio.run(self.bot.check_allowed_and_within_budget(mock_update, Mock()))
                    self.assertFalse(mock_warning.called)

    # @unittest.skip("demonstrating skipping")
    def test_check_allowed_and_not_within_budget(self):
        async def fake_send_budget_reached_message(update, context, is_inline):
            return
        
        user_id = str(uuid4())
        mock_user = Mock(spec=User)
        mock_user.name.ret = "fake_name"
        mock_user.id.return_value = user_id

        mock_inline_query = Mock(spec=InlineQuery, from_user=mock_user)
        mock_message = Mock(spec=Message, from_user=mock_user)
        
        mock_update = Mock(spec=Update)
        mock_update.inline_query = mock_inline_query
        mock_update.message = mock_message

        with patch("telegram_bot.is_allowed") as mock_allowed:
            mock_allowed.return_value = True
            with patch("telegram_bot.is_within_budget") as mock_is_within_budget:
                mock_is_within_budget.return_value = False
                with patch("telegram_bot.logging.warning") as mock_warning:
                    mock_warning.return_value = None
                    self.bot.send_budget_reached_message = Mock(side_effect=fake_send_budget_reached_message)
                    
                    asyncio.run(self.bot.check_allowed_and_within_budget(mock_update, Mock()))
                    self.assertTrue(mock_allowed.called)
                    self.assertTrue(mock_is_within_budget.called)
                    self.assertTrue(self.bot.send_budget_reached_message.called)

    # @unittest.skip("demonstrating skipping")
    def test_send_disallowed_message_not_inline(self):
        async def fake_reply_text(message_thread_id, text, disable_web_page_preview):
            return "OK"

        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text
        
        mock_update = Mock(wraps=Update)
        mock_update.effective_message = mock_message

        asyncio.run(self.bot.send_disallowed_message(update=mock_update, _=None, is_inline=False))
        self.assertTrue(mock_message.reply_text.called)

    # @unittest.skip("demonstrating skipping")
    def test_send_disallowed_message_is_inline(self):
        async def fake_send_inline_query_result(update, result_id, message_content):
            return "OK"

        self.bot.send_inline_query_result = Mock(side_effect=fake_send_inline_query_result)

        asyncio.run(self.bot.send_disallowed_message(update= Mock(wraps=Update), _=None, is_inline=True))
        self.assertTrue(self.bot.send_inline_query_result.called)

    # @unittest.skip("demonstrating skipping")
    def test_send_budget_reached_message_not_inline(self):
        async def fake_reply_text(message_thread_id, text):
            return "OK"

        mock_message = Mock(wraps=Message)
        mock_message.reply_text.side_effect = fake_reply_text

        mock_update = Mock(wraps=Update)
        mock_update.effective_message = mock_message

        asyncio.run(self.bot.send_budget_reached_message(update=mock_update, _=None, is_inline=False))
        self.assertTrue(mock_message.reply_text.called)

    # @unittest.skip("demonstrating skipping")
    def test_send_budget_reached_message_is_inline(self):
        async def fake_send_inline_query_result(update, result_id, message_content):
            return "OK"

        self.bot.send_inline_query_result = Mock(side_effect=fake_send_inline_query_result)

        asyncio.run(self.bot.send_budget_reached_message(update= Mock(wraps=Update), _=None, is_inline=True))
        self.assertTrue(self.bot.send_inline_query_result.called)

    # @unittest.skip("demonstrating skipping")
    def test_post_init(self):
        from telegram.ext import Application
        mock_application = Mock(spec=Application)

        async def fake_set_my_commands(command, scope=BotCommandScopeAllGroupChats()):
            return

        mock_application.bot.set_my_commands.side_effect = fake_set_my_commands
        asyncio.run(self.bot.post_init(mock_application))
        self.assertEqual(mock_application.bot.set_my_commands.call_count, 2)

    # @unittest.skip("demonstrating skipping")
    def test_run(self):
        from telegram.ext import Application
        from telegram.ext import ApplicationBuilder
        
        with patch("telegram_bot.ApplicationBuilder") as mock_ApplicationBuilder:
            fake = Mock(spec=ApplicationBuilder)
            mock_ApplicationBuilder.return_value = fake

            self.bot.config['token'] = ''
            self.bot.config['proxy'] = ''
            
            fake.token.return_value = fake
            fake.proxy_url.return_value = fake
            fake.get_updates_proxy_url.return_value = fake
            fake.post_init.return_value = fake
            fake.concurrent_updates.return_value = fake

            fake_app = Mock(spec=Application)
            fake.build.return_value = fake_app

            def fake_add_handler(handler):
                return
            
            def fake_add_error_handler(error_handler):
                return
            
            def fake_run_polling():
                return

            fake_app.add_handler.side_effect = fake_add_handler
            fake_app.add_error_handler.side_effect = fake_add_error_handler
            fake_app.run_polling.side_effect = fake_run_polling

            self.bot.run()
