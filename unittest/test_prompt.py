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

from telegram import Update
from telegram.error import RetryAfter, TimedOut
from telegram._message import Message
from telegram.ext import CallbackContext

class TelegramBotPromptMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    # @unittest.skip("for testing")
    def test_prompt_true_edited_message(self):
        mock_update = Mock(spec=Update)

        mock_update.edited_message = True

        self.bot.check_allowed_and_within_budget = Mock(return_value=None)
        asyncio.run(self.bot.prompt(update=mock_update, context=None))

        self.assertFalse(self.bot.check_allowed_and_within_budget.called)
    
    # @unittest.skip("for testing")
    def test_prompt_not_message(self):
        mock_update = Mock(spec=Update)

        mock_update.edited_message = False
        mock_update.message = None

        self.bot.check_allowed_and_within_budget = Mock(return_value=None)
        asyncio.run(self.bot.prompt(update=mock_update, context=None))

        self.assertFalse(self.bot.check_allowed_and_within_budget.called)
    
    # @unittest.skip("for testing")
    def test_prompt_via_bot(self):
        mock_update = Mock(spec=Update)

        mock_update.edited_message = False
        mock_update.message = Mock(wraps=Message)
        mock_update.message.via_bot = True

        self.bot.check_allowed_and_within_budget = Mock(return_value=None)
        asyncio.run(self.bot.prompt(update=mock_update, context=None))

        self.assertFalse(self.bot.check_allowed_and_within_budget.called)
    
    # @unittest.skip("for testing")
    def test_prompt_not_allowed(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return False
        
        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(wraps=Message)
        mock_update.message.via_bot = False

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        asyncio.run(self.bot.prompt(update=mock_update, context=None))

        self.assertTrue(self.bot.check_allowed_and_within_budget.called)

    # @unittest.skip("for testing")
    def test_prompt_is_group_chat_with_exception(self):
        '''
        with self.config['stream'] not existed exception
        '''
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "group_start hello"
        
        def fake_logging_exception(exception):
            return
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode):
            return
        
        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False

        self.bot.config['group_trigger_keyword'] = 'group_start'
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = True
                    with patch("telegram_bot.logging.exception") as mock_logging_exception:
                        mock_logging_exception.side_effect = fake_logging_exception

                        with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                            mock_get_reply_to_message_id.return_value = 0

                            mock_effective_message = Mock(wraps=Message)
                            mock_effective_message.reply_text.side_effect = fake_reply_text
                            mock_update.effective_message = mock_effective_message

                            mock_context = Mock(spec=CallbackContext)
                            asyncio.run(self.bot.prompt(update=mock_update, context=mock_context))
                            self.assertTrue(mock_logging_exception.called)

    # @unittest.skip("for testing")
    def test_prompt_is_group_chat_not_startwith_trigger_keyword(self):

        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "hello"

        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = True

                    self.bot.config['group_trigger_keyword'] = 'group_start'
                    mock_context = Mock(spec=CallbackContext)

                    mock_update.message.reply_to_message.return_value = False
                    with patch("telegram_bot.logging.warning") as mock_warning:
                        mock_warning.return_value = None

                        asyncio.run(self.bot.prompt(update=mock_update, context=mock_context))

                        self.assertTrue(self.bot.check_allowed_and_within_budget.called)
                        self.assertTrue(mock_info.called)
                        self.assertTrue(mock_message_text.called)
                        self.assertTrue(mock_is_group_chat.called)
                        self.assertTrue(mock_warning.called)

    # @unittest.skip("for testing") # !!
    def test_prompt_is_group_chat_not_startwith_trigger_keyword_but_send(self):

        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "hello"
        
        async def reply_chat_action(action, message_thread_id):
            return
        
        async def get_get_chat_response_stream(chat_id, query):
            yield "response 1", 1
            yield "", 0
            yield "response 2", 0

        async def fake_reply_text(message_thread_id, text, reply_to_message_id=None):
            mock_message = Mock(spec=Message)
            mock_message.chat_id = 1
            mock_message.message_id = 1
            return mock_message

        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False
        mock_update.effective_message.reply_text.side_effect = fake_reply_text  

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = True
                    with patch("telegram_bot.split_into_chunks") as mock_split_into_chunks:
                        mock_split_into_chunks.side_effect = Mock(side_effect=["chunk1", "o", "chunk2"] )
                        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                            mock_edit_message_with_retry.return_value = None
                            with  patch("telegram_bot.get_stream_cutoff_values") as mock_get_stream_cutoff_values:
                                mock_get_stream_cutoff_values.return_value = 1

                                self.bot.config['group_trigger_keyword'] = 'group_start'
                                mock_context = Mock(spec=CallbackContext)

                                mock_update.message.reply_to_message.return_value = True
                                mock_update.message.reply_to_message.from_user.id = 0
                                mock_context.bot.id = 0

                                self.bot.config['stream'] = "test"
                                mock_update.effective_message.reply_chat_action = Mock(side_effect=reply_chat_action)
                                self.openai.get_chat_response_stream = Mock(side_effect=get_get_chat_response_stream)

                                asyncio.run(self.bot.prompt(update=mock_update, context=mock_context))

                                self.assertTrue(self.bot.check_allowed_and_within_budget.called)
                                self.assertTrue(mock_message_text.called)
                                self.assertTrue(mock_is_group_chat.called)
                                self.assertTrue(self.openai.get_chat_response_stream.called)

    # @unittest.skip("for testing")
    def test_prompt_with_serveral_stream_response(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "hello"
        
        async def reply_chat_action(action, message_thread_id):
            return
        
        async def get_get_chat_response_stream(chat_id, query):
            yield "", 1
            yield "test2", 2
            yield "test3", 3
            yield "test4", 4
            yield "test5", 5
            yield "test6", 6
            yield "test7", 7
            yield "test8", 8
            yield "test9", 9

        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False

        async def fake_reply_text(message_thread_id, text, reply_to_message_id=None):

            mock_message = Mock(spec=Message)
            mock_message.chat_id = 1
            mock_message.message_id = 1
            return mock_message

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = False
                    with patch("telegram_bot.split_into_chunks") as mock_split_into_chunks:
                        mock_split_into_chunks.side_effect = Mock(side_effect=["chunk1", "ch", "test", "x", "aaa", "bbb", "ccc", "ddd"])

                        with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                            mock_edit_message_with_retry.return_value = None
                            mock_context = Mock(spec=CallbackContext)

                            mock_update.message.reply_to_message.return_value = True
                            mock_update.message.reply_to_message.from_user.id = 0

                            with patch("telegram_bot.edit_message_with_retry") as mock_edit_message_with_retry:
                                
                                async def fake_edit_message_with_retry(context, chat_id, str, text, markdown):
                                    if(text == "a"):
                                        raise RetryAfter(1)
                                    elif(text == "b"):
                                        raise TimedOut("exception: TimedOut")
                                    elif (text== "c"):
                                        raise Exception("oops")
                                    else:
                                        return
                                
                                mock_edit_message_with_retry.side_effect = fake_edit_message_with_retry

                                with  patch("telegram_bot.get_stream_cutoff_values") as mock_get_stream_cutoff_values:
                                    mock_get_stream_cutoff_values.return_value = 1

                                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                                        mock_get_reply_to_message_id.return_value = 0

                                        with patch("telegram_bot.asyncio.sleep") as mock_sleep:
                                            async def fake_sleep(time):
                                                return
                                            mock_sleep.side_effect = fake_sleep
                                            
                                            async def fake_delete_message(chat_id, message_id):
                                                return
                                            mock_context.bot.id = 0 
                                            mock_context.bot.delete_message.side_effect = fake_delete_message

                                            self.bot.config['stream'] = "test"
                                            mock_update.effective_message.reply_chat_action = Mock(side_effect=reply_chat_action)
                                            mock_update.effective_message.reply_text.side_effect = fake_reply_text
                                            self.openai.get_chat_response_stream = Mock(side_effect=get_get_chat_response_stream)

                                            asyncio.run(self.bot.prompt(update=mock_update, context=mock_context))

                                            self.assertTrue(self.bot.check_allowed_and_within_budget.called)
                                            self.assertEqual(mock_edit_message_with_retry.call_count, 6)  # 8 inputs with 2 failures 
                                            self.assertEqual(mock_split_into_chunks.call_count, 8)        # total 8 input
                                            self.assertTrue(mock_message_text.called)


    # @unittest.skip("for testing")
    def test_prompt_with_empty_stream(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        def fake_message_text(message):
            return "fake message"
        
        async def reply_chat_action(action, message_thread_id):
            return
        
        self.bot.config['stream'] = ""

        mock_update = Mock(spec=Update)
        mock_update.edited_message = False
        mock_update.message = Mock(spec=Message)
        mock_update.message.via_bot = False
        mock_update.message.reply_to_message.return_value = True
        mock_update.message.reply_to_message.from_user.id = 0

        mock_update.effective_message.reply_chat_action = Mock(side_effect=reply_chat_action)

        async def fake_reply_text(message_thread_id, text, reply_to_message_id=None, parse_mode=None):
            raise Exception("test exception")
        mock_update.effective_message.reply_text.side_effect = fake_reply_text

        async def fake_mock_wrap_with_indicator(update, context, coroutine, chat_action, is_inline=False):
            task = asyncio.create_task(coroutine())
            while not task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(task), 3)
                except asyncio.TimeoutError:
                    pass
                    return 
            return
        
        async def fake_get_chat_response(chat_id, query):
            return "response", 2
        
        self.bot.openai.get_chat_response.side_effect = fake_get_chat_response
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        with patch("telegram_bot.logging.info") as mock_info:
            mock_info.return_value = None
            with patch("telegram_bot.message_text") as mock_message_text:
                mock_message_text.side_effect = fake_message_text
                with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
                    mock_is_group_chat.return_value = False
                    with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                        mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                        with patch("telegram_bot.split_into_chunks") as mock_split_into_chunks:
                            mock_split_into_chunks.side_effect = Mock(side_effect=["chunk1", "chunk2"])
                            with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                                def fake_get_reply_to_message_id(config, update):
                                    return
                                mock_get_reply_to_message_id.side_effect = fake_get_reply_to_message_id

                                mock_context = Mock(spec=CallbackContext)
                                try:
                                    asyncio.run(self.bot.prompt(update=mock_update, context=mock_context))
                                except Exception as e:
                                    self.assertEqual(str(e), "test exception")

                                self.assertTrue(self.bot.check_allowed_and_within_budget.called)
                                self.assertTrue(mock_message_text.called)
          