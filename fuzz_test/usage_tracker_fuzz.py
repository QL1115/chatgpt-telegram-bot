import atheris
import sys
from usage_tracker import UsageTracker

# 定義測試輸入
@atheris.instrument_func
def test_usage_tracker(data):
    # 建立使用者追蹤器
    tracker = UsageTracker(1, "user_name")
    
    # 解析測試輸入
    try:
        input_data = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    
    # 模擬使用者行為
    if input_data == "add_chat_tokens":
        tracker.add_chat_tokens(1000)
    elif input_data == "get_current_token_usage":
        tracker.get_current_token_usage()
    elif input_data == "add_image_request":
        tracker.add_image_request("256x256")#, image_prices=[0.016, 0.018, 0.02]
    elif input_data == "get_current_image_count":
        tracker.get_current_image_count()
    elif input_data == "add_transcription_seconds":
        tracker.add_transcription_seconds(60)
    elif input_data == "get_current_transcription_duration":
        tracker.get_current_transcription_duration()
    elif input_data == "get_current_cost":
        tracker.get_current_cost()
    else:
        pass

# 使用 Atheris 測試程式
def main():
    atheris.Setup(sys.argv, test_usage_tracker)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
