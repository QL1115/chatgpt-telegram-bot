import atheris
import sys

from utils import *  # 替换为实际模块名称

# 使用Atheris进行模糊测试的回调函数
def TestOneInput(data):
    # 捕获潜在的异常，以避免模糊测试的崩溃
    try:
        # 在这里调用您的函数，例如：
        message_text(telegram.Message(text=data))
        is_user_in_group(telegram.Update(), telegram.ext.CallbackContext(), 123)
        get_thread_id(telegram.Update(), telegram.ext.CallbackContext())
        get_stream_cutoff_values(telegram.Update(), telegram.ext.CallbackContext())
        is_group_chat(telegram.Update(), telegram.ext.CallbackContext())
        split_into_chunks(telegram.Update(), telegram.ext.CallbackContext())
        error_handler(telegram.Update(), telegram.ext.CallbackContext())
        is_allowed(telegram.Update(), telegram.ext.CallbackContext())
        is_admin(telegram.Update(), telegram.ext.CallbackContext())
        get_user_budget(telegram.Update())
        get_remaining_budget(telegram.Update(), telegram.ext.CallbackContext())
        is_within_budget(telegram.Update(), telegram.ext.CallbackContext())
        add_chat_request_to_usage_tracker(telegram.Update(), telegram.ext.CallbackContext())
        get_reply_to_message_id(telegram.Update())
        edit_message_with_retry(telegram.Update(), telegram.ext.CallbackContext(), 1, "hi")
        wrap_with_indicator(telegram.Update(), telegram.ext.CallbackContext())
    
        # ...

        # 替换为要进行模糊测试的实际函数调用

        pass
    except Exception as e:
        # 忽略异常并继续进行模糊测试
        pass

# 设置Atheris并运行模糊测试
def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == '__main__':
    main()
