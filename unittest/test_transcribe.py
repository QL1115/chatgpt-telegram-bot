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

from telegram import Update, File
from telegram.ext import CallbackContext
from pydub import AudioSegment

class TelegramBoTrancMethodTest(unittest.TestCase):
    def setUp(self):
        telegram_config = {
            'bot_language': os.environ.get('BOT_LANGUAGE', 'zh-tw'),
        }

        openai_helper = Mock(spec=OpenAIHelper) 
        self.bot = ChatGPTTelegramBot(config=telegram_config, openai=openai_helper)
        self.openai = openai_helper

    # @unittest.skip("for testing")
    def test_transcribe_not_enable_transcription(self):
        self.bot.config['enable_transcription'] = False
        self.bot.check_allowed_and_within_budget = Mock(side_effect=None)

        mock_update = Mock(wraps=Update)
        asyncio.run(self.bot.transcribe(update=mock_update, context=None))
        self.assertFalse(self.bot.check_allowed_and_within_budget.called)

    # @unittest.skip("for testing")
    def test_transcribe_is_group_chat(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        self.bot.config['enable_transcription'] = True
        self.bot.config['ignore_group_transcriptions'] = True

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = True

            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
            
            with patch("telegram_bot.logging.info") as mock_info:
                mock_info.return_value = None

                mock_update = Mock(wraps=Update)
                asyncio.run(self.bot.transcribe(update=mock_update, context=None))
                self.assertTrue(mock_is_group_chat.called)
                self.assertTrue(mock_info.called)

    # @unittest.skip("for testing")
    def test_transcribe_not_group_chat(self):
        async def fake_check_allowed_and_within_budget(update, context):
            return True
        
        async def fake_mock_wrap_with_indicator(update, context, coroutine, chat_action):
            return

        self.bot.config['enable_transcription'] = True

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
            self.bot.config['ignore_group_transcriptions'] = True
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                
                mock_update = Mock(spec=Update)
                asyncio.run(self.bot.transcribe(update=mock_update, context=None))
                self.assertTrue(mock_is_group_chat.called)
                self.assertTrue(mock_wrap_with_indicator.called)

    # @unittest.skip("for testing")
    def test_transcribe_download_to_drive_raise_error(self):
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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode):
            return
        
        async def fake_download_to_drive(filename):
            raise Exception("Exception from fake_download_to_drive")
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_exception(e):
            return  

        mock_update = Mock(spec=Update)
        self.bot.config['enable_transcription'] = True

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
            self.bot.config['ignore_group_transcriptions'] = True
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator

                mock_update.effective_message.reply_text.side_effect = fake_reply_text
                with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                    mock_get_reply_to_message_id.return_value = 0
                    with patch("telegram_bot.logging.exception") as mock_logging_exception:
                        mock_logging_exception.side_effect = fake_logging_exception
                        with patch("telegram_bot.get_thread_id") as mock_get_thread_id:
                            mock_get_thread_id.return_value = None

                            mock_context = Mock(spec=CallbackContext)
                            mock_context.bot.get_file.side_effect = fake_get_file

                            asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                            self.assertTrue(mock_is_group_chat.called)
                            self.assertTrue(mock_wrap_with_indicator.called)
                            self.assertTrue(mock_logging_exception.called)
                            self.assertTrue(mock_update.effective_message.reply_text.called)
        
    # @unittest.skip("for testing")
    def test_transcribe_audio_tack_error(self):
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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text):
            return
        
        async def fake_download_to_drive(filename):
            return
        
        async def fake_export(filename_mp3, format):
            return
        
        async def fake_from_file(filename):
            mock = Mock()
            mock.export.side_effect = await fake_export
            return mock
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_info(e):
            raise Exception("Exception from fake_logging_info")
        
        def fake_logging_exception(e):
            return 
        
        def fake_os_exist(filename):
            return True

        mock_update = Mock(spec=Update)
        self.bot.config['enable_transcription'] = True
        self.bot.config['ignore_group_transcriptions'] = True
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        
        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                with patch.object(AudioSegment, 'from_file') as mock_from_file:
                    mock_from_file.side_effect = fake_from_file

                    mock_update.effective_message.reply_text.side_effect = fake_reply_text
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0
                        with patch("telegram_bot.logging.exception") as mock_logging_exception:
                            mock_logging_exception.side_effect = fake_logging_exception
                            with patch("telegram_bot.logging.info") as mock_logging_info:
                                mock_logging_info.side_effect = fake_logging_info
                                with patch("telegram_bot.os.path.exists") as mock_os_exist:
                                    mock_os_exist.side_effect = fake_os_exist
                                    with patch("telegram_bot.os.remove") as mock_os_remove:
                                        mock_os_remove.return_value = None

                                        mock_context = Mock(spec=CallbackContext)
                                        mock_context.bot.get_file.side_effect = fake_get_file

                                        asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                                        self.assertTrue(mock_is_group_chat.called)
                                        self.assertTrue(mock_wrap_with_indicator.called)
                                        self.assertTrue(mock_logging_exception.called)
                                        self.assertTrue(mock_update.effective_message.reply_text.called)
    
    # @unittest.skip("for testing")
    def test_transcribe_not_response_to_transcription(self):
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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode=None):
            return
        
        async def fake_download_to_drive(filename):
            return
        
        async def fake_export(filename_mp3, format):
            return
        
        async def fake_from_file(filename):
            mock = Mock()
            mock.export.side_effect = await fake_export
            return mock
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_info(e):
            return

        def fake_logging_exception(e):
            return 
        
        def fake_os_exist(filename):
            return True
        
        def fake_add_transcription_seconds(second, price):
            return

        def fake_split_into_chunks(transcript_output):
            return "test"
        
        self.bot.config['enable_transcription'] = True
        self.bot.config['allowed_user_ids'] = '3'
        self.bot.config['voice_reply_prompts'] = "no;yes"
        self.bot.config['voice_reply_transcript'] = True
        self.bot.config['ignore_group_transcriptions'] = True
        self.bot.config['transcription_price'] = 0

        mock_update = Mock(spec=Update)
        mock_update.message.from_user.id = 1
        mock_update.effective_message.reply_text.side_effect = fake_reply_text

        mock_user = Mock(spec=UsageTracker)
        mock_guest = Mock(spec=UsageTracker)
        mock_user.add_transcription_seconds = fake_add_transcription_seconds
        mock_guest.add_transcription_seconds = fake_add_transcription_seconds                     

        self.bot.usage = {"guests": mock_guest}
        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        async def fake_transcribe(filename):
            return "fake_transcribe"
        self.bot.openai.transcribe.side_effect = fake_transcribe
 
        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                with patch.object(AudioSegment, 'from_file') as mock_from_file:
                    mock_from_file.side_effect = fake_from_file
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0
                        with patch("telegram_bot.split_into_chunks") as mock_split_into_chunks:
                            mock_split_into_chunks.side_effect = fake_split_into_chunks
                            with patch("telegram_bot.logging.exception") as mock_logging_exception:
                                mock_logging_exception.side_effect = fake_logging_exception
                                with patch("telegram_bot.logging.info") as mock_logging_info:
                                    mock_logging_info.side_effect = fake_logging_info
                                    with patch("telegram_bot.UsageTracker") as mock_UsageTracker:
                                        mock_UsageTracker.return_value = mock_user
                                        with patch("telegram_bot.os.path.exists") as mock_os_exist:
                                            mock_os_exist.side_effect = fake_os_exist
                                            with patch("telegram_bot.os.remove") as mock_os_remove:
                                                mock_os_remove.return_value = None

                                                mock_context = Mock(spec=CallbackContext)
                                                mock_context.bot.get_file.side_effect = fake_get_file

                                                asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                                                self.assertTrue(mock_is_group_chat.called)
                                                self.assertTrue(mock_wrap_with_indicator.called)
                                                self.assertTrue(mock_update.effective_message.reply_text.called)
                                                self.assertTrue(mock_os_exist.called)
                                                self.assertTrue(mock_os_remove.called)

    # @unittest.skip("for testing")
    def test_transcribe_true_response_to_transcription(self):
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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode=None):
            return
        
        async def fake_download_to_drive(filename):
            return
        
        async def fake_export(filename_mp3, format):
            return
        
        def fake_from_file(filename):
            mock = Mock()
            mock.export.side_effect = fake_export
            return mock
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_info(e):
            return

        def fake_logging_exception(e):
            return 
        
        def fake_os_exist(filename):
            return True
        
        def fake_add_transcription_seconds(second, price):
            return

        def fake_split_into_chunks(transcript_output):
            return ["text1", "text2"]  

        mock_user = Mock(spec=UsageTracker)
        mock_guest = Mock(spec=UsageTracker)
        mock_user.add_transcription_seconds = fake_add_transcription_seconds
        mock_guest.add_transcription_seconds = fake_add_transcription_seconds

        self.bot.usage = {0: mock_user, "guests": mock_guest}

        self.bot.config['enable_transcription'] = True
        self.bot.config['allowed_user_ids'] = '3'
        self.bot.config['token_price'] = 0.01
        self.bot.config['voice_reply_prompts'] = "hello"
        self.bot.config['voice_reply_transcript'] = False
        self.bot.config['transcription_price'] = 0

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
        self.bot.config['ignore_group_transcriptions'] = True

        async def fake_transcribe(filename):
            return "fake transcribe"
        self.bot.openai.transcribe.side_effect = fake_transcribe
        
        async def fake_get_chat_response(chat_id, query):
            return "response", 1
        self.bot.openai.get_chat_response.side_effect = fake_get_chat_response
        
        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                with patch.object(AudioSegment, 'from_file') as mock_from_file:
                    mock_from_file.side_effect = fake_from_file
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0
                        with patch("telegram_bot.split_into_chunks") as mock_split_into_chunks:
                            mock_split_into_chunks.side_effect = fake_split_into_chunks
                            with patch("telegram_bot.logging.exception") as mock_logging_exception:
                                mock_logging_exception.side_effect = fake_logging_exception
                                with patch("telegram_bot.logging.info") as mock_logging_info:
                                    mock_logging_info.side_effect = fake_logging_info
                                    with patch("telegram_bot.os.path.exists") as mock_os_exist:
                                        mock_os_exist.side_effect = fake_os_exist
                                        with patch("telegram_bot.os.remove") as mock_os_remove:
                                            mock_os_remove.return_value = None

                                            mock_update = Mock(spec=Update)
                                            mock_update.message.from_user.id = 0
                                            mock_update.effective_message.reply_text.side_effect = fake_reply_text

                                            mock_context = Mock(spec=CallbackContext)
                                            mock_context.bot.get_file.side_effect = fake_get_file

                                            asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                                            self.assertTrue(mock_is_group_chat.called)
                                            self.assertTrue(mock_wrap_with_indicator.called)
                                            self.assertTrue(mock_split_into_chunks.called)
                                            self.assertTrue(mock_get_reply_to_message_id.called)
    
    # @unittest.skip("for testing")
    def test_transcribe_with_exception(self):
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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode=None):
            return
        
        async def fake_download_to_drive(filename):
            return
        
        async def fake_export(filename_mp3, format):
            return
        
        def fake_from_file(filename):
            mock = Mock()
            mock.export.side_effect = fake_export
            return mock
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_info(e):
            return

        def fake_logging_exception(e):
            return 
        
        def fake_os_exist(filename):
            return True

        self.bot.config['enable_transcription'] = True
        self.bot.config['allowed_user_ids'] = '3'
        self.bot.config['token_price'] = 0.01
        self.bot.config['transcription_price'] = 0
        self.bot.config['voice_reply_prompts'] = "hello"
        self.bot.config['voice_reply_transcript'] = False
        self.bot.config['ignore_group_transcriptions'] = True

        mock_update = Mock(spec=Update)
        mock_update.message.from_user.id = 0
        mock_update.effective_message.reply_text.side_effect = fake_reply_text

        mock_user = Mock(spec=UsageTracker)
        mock_guest = Mock(spec=UsageTracker)
        self.bot.usage = {0: mock_user, "guests": mock_guest}

        self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)

        async def fake_transcribe(filename):  # generate Exception
            raise Exception("Exception from fake_transcribe")
        self.bot.openai.transcribe.side_effect = fake_transcribe

        async def fake_get_chat_response(chat_id, query):
            return "response", 1
        self.bot.openai.get_chat_response.side_effect = fake_get_chat_response
        
        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                with patch.object(AudioSegment, 'from_file') as mock_from_file:
                    mock_from_file.side_effect = fake_from_file
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0
                        with patch("telegram_bot.logging.exception") as mock_logging_exception:
                            mock_logging_exception.side_effect = fake_logging_exception
                            with patch("telegram_bot.logging.info") as mock_logging_info:
                                mock_logging_info.side_effect = fake_logging_info
                                with patch("telegram_bot.os.path.exists") as mock_os_exist:
                                    mock_os_exist.side_effect = fake_os_exist
                                    with patch("telegram_bot.os.remove") as mock_os_remove:
                                        mock_os_remove.return_value = None

                                        mock_context = Mock(spec=CallbackContext)
                                        mock_context.bot.get_file.side_effect = fake_get_file

                                        asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                                        self.assertTrue(mock_is_group_chat.called)
                                        self.assertTrue(mock_wrap_with_indicator.called)
                                        self.assertTrue(mock_logging_exception.called)
                                        self.assertTrue(mock_update.effective_message.reply_text.called)
                                        self.assertTrue(mock_os_exist.called)
                                        self.assertTrue(mock_os_remove.called)

    # @unittest.skip("for testing")
    def test_transcribe(self):

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
        
        async def fake_reply_text(message_thread_id, reply_to_message_id, text, parse_mode):
            return
        
        async def fake_download_to_drive(filename):
            return
        
        async def fake_export(filename_mp3, format):
            return
        
        def fake_from_file(filename):
            mock = Mock()
            mock.export.side_effect = fake_export
            return mock
            
        async def fake_get_file(file_id):
            mock_file = Mock(spec=File)
            mock_file.download_to_drive.side_effect = fake_download_to_drive
            return mock_file
        
        def fake_logging_info(e):
            return

        def fake_logging_exception(e):
            return 
        
        def fake_os_exist(filename):
            return True
        
        def fake_add_transcription_seconds(second, price):
            return

        def fake_add_chat_tokens(tokens, price):
            return
        
        def fake_get_chat_response(chat_id, query):
            return "response", 1

        self.bot.config['enable_transcription'] = True
        self.bot.config['allowed_user_ids'] = '3'

        mock_update = Mock(spec=Update)
        mock_update.message.from_user.id = 0

        mock_user = Mock(spec=UsageTracker)
        mock_guest = Mock(spec=UsageTracker)
        mock_user.add_transcription_seconds = fake_add_transcription_seconds
        mock_user.add_chat_tokens = fake_add_chat_tokens
        mock_guest.add_transcription_seconds = fake_add_transcription_seconds
        mock_guest.add_chat_tokens = fake_add_chat_tokens
        self.bot.usage = {0: mock_user, "guests": mock_guest}
        self.bot.config['voice_reply_prompts'] = "no;yes"
        self.bot.config['voice_reply_transcript'] = False
        self.bot.config['token_price'] = 0.0001
        
        self.bot.openai.get_chat_response.side_effect = fake_get_chat_response

        with patch("telegram_bot.is_group_chat") as mock_is_group_chat:
            mock_is_group_chat.return_value = False

            self.bot.check_allowed_and_within_budget = Mock(side_effect=fake_check_allowed_and_within_budget)
            self.bot.config['ignore_group_transcriptions'] = True
            with patch("telegram_bot.wrap_with_indicator") as mock_wrap_with_indicator:
                mock_wrap_with_indicator.side_effect = fake_mock_wrap_with_indicator
                
                with patch.object(AudioSegment, 'from_file') as mock_from_file:
                    mock_from_file.side_effect = fake_from_file

                    mock_update.effective_message.reply_text.side_effect = fake_reply_text
                    with patch("telegram_bot.get_reply_to_message_id") as mock_get_reply_to_message_id:
                        mock_get_reply_to_message_id.return_value = 0

                        with patch("telegram_bot.logging.exception") as mock_logging_exception:
                            mock_logging_exception.side_effect = fake_logging_exception

                            with patch("telegram_bot.logging.info") as mock_logging_info:

                                with patch("telegram_bot.os.path.exists") as mock_os_exist:
                                    with patch("telegram_bot.os.remove") as mock_os_remove:
                                        mock_os_remove.return_value = None
                                        mock_os_exist.side_effect = fake_os_exist

                                        async def fake_transcribe(filename):
                                            return "hello"

                                        mock_logging_info.side_effect = fake_logging_info
                                        self.bot.openai.transcribe.side_effect = fake_transcribe
                                        self.bot.config['transcription_price'] = 0

                                        mock_context = Mock(spec=CallbackContext)
                                        mock_context.bot.get_file.side_effect = fake_get_file

                                        asyncio.run(self.bot.transcribe(update=mock_update, context=mock_context))
                                        self.assertTrue(mock_is_group_chat.called)
                                        self.assertTrue(mock_wrap_with_indicator.called)
                                        self.assertFalse(mock_logging_exception.called)
                                        self.assertTrue(mock_update.effective_message.reply_text.called)
 
