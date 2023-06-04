import unittest
from unittest import TestCase, mock
from datetime import date
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bot.usage_tracker import UsageTracker


class TestUsageTracker(TestCase):

    def setUp(self):
        self.user_id = '123456'
        self.user_name = '@test_user'
        self.usage_tracker = UsageTracker(self.user_id, self.user_name)
        self.user_file = {
            "user_name": "@user_name",
            "current_cost": {
                "day": 0.45,
                "month": 3.23,
                "all_time": 3.23,
                "last_update": "2023-03-14"
            },
            "usage_history": {
                "chat_tokens": {
                    "2023-03-13": 520,
                    "2023-03-14": 1532
                },
                "transcription_seconds": {
                    "2023-03-13": 125,
                    "2023-03-14": 64
                },
                "number_images": {
                    "2023-03-12": [0, 2, 3],
                    "2023-03-13": [1, 2, 3],
                    "2023-03-14": [0, 1, 2]
                }
            }
        }

    def test_add_chat_tokens(self):
        tokens = 1000
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_chat_tokens(tokens)
        self.assertEqual(self.user_file['usage_history']['chat_tokens'][str(date.today())], tokens)

    def test_get_current_token_usage(self):
        tokens = 1000
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_chat_tokens(tokens)
        usage_day, usage_month = self.usage_tracker.get_current_token_usage()
        self.assertEqual(usage_day, tokens)
        self.assertEqual(usage_month, tokens)

    def test_add_image_request(self):
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_image_request('512x512')
        self.assertEqual(self.user_file['usage_history']['number_images'][str(date.today())][1], 1)

    def test_get_current_image_count(self):
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_image_request('512x512')
        usage_day, usage_month = self.usage_tracker.get_current_image_count()
        self.assertEqual(usage_day, 1)
        self.assertEqual(usage_month, 1)

    def test_add_transcription_seconds(self):
        seconds = 3600
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_transcription_seconds(seconds)
        self.assertEqual(self.user_file['usage_history']['transcription_seconds'][str(date.today())], seconds)

    def test_get_current_transcription_duration(self):
        seconds = 3600
        self.usage_tracker.usage = self.user_file  # 設定初始的 usage
        self.usage_tracker.add_transcription_seconds(seconds)
        minutes_day, seconds_day, minutes_month, seconds_month = self.usage_tracker.get_current_transcription_duration()
        self.assertEqual(minutes_day, 60)
        self.assertEqual(seconds_day, 0)
        self.assertEqual(minutes_month, 60)
        self.assertEqual(seconds_month, 0)


if __name__ == '__main__':
    unittest.main()
