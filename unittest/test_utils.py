import unittest
from unittest.mock import Mock, patch
import logging
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bot.usage_tracker import UsageTracker
from bot.utils import *

class TestUtils(unittest.TestCase):
    
    @patch('telegram.MessageEntity', autospec=True)
    @patch('telegram.Message', autospec=True)
    def test_message_text(self, mock_message, mock_entity):
        mock_message.text = '/command This is a test'
        mock_entity.offset = 0
        mock_entity.length = 8
        mock_message.parse_entities.return_value = {mock_entity: '/command'}

        self.assertEqual(message_text(mock_message), 'This is a test')
    
    def test_split_into_chunks(self):
        test_text = 'a' * 1904
        result = split_into_chunks(test_text, 1000)
        self.assertEqual(len(result), 2)
        self.assertEqual(len(result[0]), 1000)
        self.assertEqual(len(result[1]), 904)


    @patch('telegram.bot.Bot.get_chat_member')
    async def test_is_user_in_group(self, mock_get_chat_member):
        update = Mock(spec=Update)
        context = Mock(spec=CallbackContext)
        context.bot.get_chat_member.return_value = ChatMember(status=ChatMember.MEMBER)

        self.assertTrue(await is_user_in_group(update, context, 12345))

        context.bot.get_chat_member.side_effect = telegram.error.BadRequest("User not found")
        self.assertFalse(await is_user_in_group(update, context, 12345))

        context.bot.get_chat_member.side_effect = telegram.error.BadRequest("Some other error")
        with self.assertRaises(telegram.error.BadRequest):
            await is_user_in_group(update, context, 12345)

        context.bot.get_chat_member.side_effect = Exception("Some other error")
        with self.assertRaises(Exception):
            await is_user_in_group(update, context, 12345)

    # TODO

    def test_is_allowed_admin_user(self):
        config = {'admin_user_ids': '12345', 'allowed_user_ids': '*'}
        update = Mock()
        context = Mock()
        result = is_allowed(config, update, context)
        self.assertTrue(result)

    def test_is_allowed_allowed_user(self):
        config = {'admin_user_ids': '12345', 'allowed_user_ids': '67890'}
        update = Mock()
        update.inline_query.from_user.id = 67890
        context = Mock()
        result = is_allowed(config, update, context, is_inline=True)
        self.assertTrue(result)

    # def test_is_allowed_not_allowed_user(self): # TODO : wrong
    #     config = {'admin_user_ids': '12345', 'allowed_user_ids': '67890'}
    #     update = Mock()
    #     update.inline_query.from_user.id = 54321
    #     context = Mock()
    #     result = is_allowed(config, update, context, is_inline=True)
    #     self.assertFalse(result)

    @patch('bot.utils.is_group_chat') 
    def test_get_stream_cutoff_values_group_chat(self, mock_is_group_chat):
        mock_is_group_chat.return_value = True
        update = Mock()
        content = "This is a test message."
        result = get_stream_cutoff_values(update, content)
        self.assertEqual(result, 50)

    @patch('bot.utils.is_group_chat')
    def test_get_stream_cutoff_values_private_chat(self, mock_is_group_chat):
        mock_is_group_chat.return_value = False
        update = Mock()
        content = "This is a test message."
        result = get_stream_cutoff_values(update, content) #
        self.assertEqual(result, 15)

    def test_is_group_chat_group(self):
        update = Mock()
        update.effective_chat.type = 'group'
        result = is_group_chat(update)
        self.assertTrue(result)

    def test_is_group_chat_private(self):
        update = Mock()
        update.effective_chat.type = 'private'
        result = is_group_chat(update)
        self.assertFalse(result)

    def test_split_into_chunks(self):
        text = "This is a long text that needs to be split into chunks."
        result = split_into_chunks(text, chunk_size=10)
        expected = ['This is a ', 'long text ', 'that needs', ' to be spl', 'it into ch', 'unks.']
        self.assertEqual(result, expected)

    @patch('telegram.error.BadRequest')
    @patch('ContextTypes.DEFAULT_TYPE.bot')
    async def test_edit_message_with_retry(self, mock_bot, mock_bad_request):
        context = Mock()
        chat_id = 123
        message_id = '456'
        text = 'Test message'
        markdown = True
        is_inline = False

        await edit_message_with_retry(context, chat_id, message_id, text, markdown, is_inline)

        mock_bot.edit_message_text.assert_called_with(
            chat_id=chat_id,
            message_id=int(message_id),
            inline_message_id=None,
            text=text,
            parse_mode='Markdown'
        )

        mock_bot.reset_mock()
        mock_bot.edit_message_text.side_effect = mock_bad_request

        await edit_message_with_retry(context, chat_id, message_id, text, markdown, is_inline)

        mock_bot.edit_message_text.assert_called_with(
            chat_id=chat_id,
            message_id=int(message_id),
            inline_message_id=None,
            text=text
        )

    async def test_error_handler(self):
        context = Mock()
        context.error = 'Test error'
        await error_handler(None, context)
        logging.error.assert_called_with(f'Exception while handling an update: {context.error}')


    @patch('bot.utils.is_admin')
    @patch('bot.utils.is_user_in_group')
    async def test_is_allowed(self, mock_is_user_in_group, mock_is_admin):
        config = {
            'allowed_user_ids': '1,2,3',
            'admin_user_ids': '4,5,6'
        }
        update = Mock()
        context = Mock()
        # Test allowed user
        user_id = 1
        is_inline = False

        mock_is_admin.return_value = False
        mock_is_user_in_group.return_value = False

        result = await is_allowed(config, update, context, is_inline)
        self.assertTrue(result)
        # Test admin user
        user_id = 4
        is_inline = False
        mock_is_admin.return_value = True
        mock_is_user_in_group.return_value = False
        result = await is_allowed(config, update, context, is_inline)
        self.assertTrue(result)
        # Test user in group
        user_id = 1
        is_inline = False
        mock_is_admin.return_value = False
        mock_is_user_in_group.return_value = True
        result = await is_allowed(config, update, context, is_inline)
        self.assertTrue(result)
        # Test disallowed user
        user_id = 7
        is_inline = False
        mock_is_admin.return_value = False
        mock_is_user_in_group.return_value = False
        result = await is_allowed(config, update, context, is_inline)
        self.assertFalse(result)

    def test_is_admin(self):
        config = {
            'admin_user_ids': '1,2,3'
        }
        # Test admin user
        user_id = 1
        result = is_admin(config, user_id)
        self.assertTrue(result)
        # Test non-admin user
        user_id = 4
        result = is_admin(config, user_id)
        self.assertFalse(result)

    def test_get_user_budget(self):
        config = {
            'allowed_user_ids': '1,2,3',
            'admin_user_ids': '4,5,6',
            'user_budgets': '10,20,30'
        }
        # Test allowed user with budget
        user_id = 1
        result = get_user_budget(config, user_id)
        self.assertEqual(result, 10.0)
        # Test admin user with budget
        user_id = 4
        result = get_user_budget(config, user_id)
        self.assertEqual(result, float('inf'))
        # Test disallowed user
        user_id = 7
        result = get_user_budget(config, user_id)
        self.assertIsNone(result)

    ###########
    # def test_is_within_budget(self): # TODO wrong

    #     config = {
    #         'allowed_user_ids': '1,2,3',
    #         'admin_user_ids': '4,5,6',
    #         'user_budgets': '10,20,30',
    #         'budget_period': 60
    #     }
    #     usage = {}
    #     update = Mock()
    #     update.inline_query.from_user.id = 1
    #     update.inline_query.from_user.name = 'User'
    #     is_inline = False

    #     # Test user within budget
    #     usage[1] = Mock()
    #     usage[1].add_chat_tokens.return_value = None

    #     result = is_within_budget(config, usage, update, is_inline)
    #     self.assertTrue(result)

    #     # Test user exceeded budget
    #     usage[1].add_chat_tokens.return_value = Exception()

    #     result = is_within_budget(config, usage, update, is_inline)
    #     self.assertFalse(result)

    #     # Test user not in usage tracker
    #     usage = {}
    #     usage_tracker_mock = Mock()
    #     usage_tracker_mock.add_chat_tokens.return_value = None
    #     UsageTracker_mock = Mock(return_value=usage_tracker_mock)
    #     with patch('your_module.UsageTracker', UsageTracker_mock):
    #         result = is_within_budget(config, usage, update, is_inline)
    #         self.assertTrue(result)

    def test_add_chat_request_to_usage_tracker(self):

        usage = {}
        config = {
            'allowed_user_ids': '1,2,3',
            'token_price': 0.1
        }
        user_id = 1
        used_tokens = 10

        usage_tracker_mock = Mock()
        usage_tracker_mock.add_chat_tokens.return_value = None
        usage[1] = usage_tracker_mock

        add_chat_request_to_usage_tracker(usage, config, user_id, used_tokens)

        usage_tracker_mock.add_chat_tokens.assert_called_with(used_tokens, config['token_price'])

    # def test_get_reply_to_message_id(self): # TODO wrong

    #     config = {
    #         'enable_quoting': True
    #     }
    #     update = Mock()

    #     # Test quoting enabled
    #     result = get_reply_to_message_id(config, update)
    #     self.assertEqual(result, update.message.message_id)

    #     # Test quoting disabled, group chat
    #     config['enable_quoting'] = False
    #     update.message.chat.type = 'group'

    #     result = get_reply_to_message_id(config, update)
    #     self.assertEqual(result, update.message.message_id)

    #     # Test quoting disabled, private chat
    #     update.message.chat.type = 'private'

    #     result = get_reply_to_message_id(config, update)
    #     self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()


