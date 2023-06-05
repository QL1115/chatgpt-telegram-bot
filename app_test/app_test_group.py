from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import pickle
import os

# def rm_timestamp(string):
#     lines = string.splitlines()
#     new_string = "\n".join(lines[:-1])
#     return new_string
def rm_timestamp(string):
    new_string = ""
    # new_string = string.lstrip()
    # print(new_string)
    lines = string.splitlines()
    # print(lines)
    if len(lines) > 1:
        new_string = "\n".join(lines[:-1])
    elif len(lines) == 1:
        new_string = lines[0]
    # else:
    #     new_string = ""
    return new_string
options = Options()
options.add_argument('--headless')
options.add_argument('--window-size=1920,1080')
options.add_argument('--disable-gpu')
#options.add_argument("--enable-local-storage")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

#driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.get("https://web.telegram.org/a/")
#telegram使用local storage儲存登入資訊，但網站好像擋掉local storage的script，所以無法使用local storage登入
# time.sleep(5)
# script = """
#     window.localStorage.setItem('dc', '5');
#     window.localStorage.setItem('user_auth', '0bcf7a6c0c43e935b5424614015fe6a6a50a44d2d1de7905a9e79c3248b6537928b347ff6f92182e02f93435418c71c3af6fc5ef67da0eff24d75d08819541c7e5f080af7a99c1792ebf154bd8fc5761f912ba4d515651766f038d9054b4988e539ba2e125eccd65ce80a613e6d9fc70ec2e35403d702f019163e95592c646da257f5cb35734b422e49f9103ae3ce1e1a54e87f6bca7803e7e09644081e5959e473ffb83be5ba547539c25adf70b3a13e3b3e10f4a2cc6b8f8b3732bd9280c8fddb4a1e903262c8556c650b77389e9045803384b6dace61cfc9698d1db56b765a7b65a2953d22da7ad0162eb28fe0226f4b911c22095fb67c4ebd1cd926753fa');
# """
# driver.execute_script(script)

driver.get("https://web.telegram.org/a/")
driver.maximize_window()
driver.implicitly_wait(5000)
login = 0
if os.path.exists('cookies.pkl'):# and login == 0 telegram 不是用cookie登入所以無法成功 
    # Load the cookies
    with open('cookies.pkl', 'rb') as f:
        cookies = pickle.load(f)
        #print(cookies)
        if cookies:
            print("COOKIE EXIST")
            login = 1
            for cookie in cookies:
                driver.add_cookie(cookie)
            driver.get("https://web.telegram.org/a/")
            driver.maximize_window()
else:
    print("PLEASE LOGIN")
    #如果沒有cookie
if login == 0:
    driver.get("https://web.telegram.org/a/")
    #driver.implicitly_wait(5000)
    driver.maximize_window()
    el = WebDriverWait(driver, 6000).until(lambda d: d.find_element(By.XPATH, "/html/body/div[2]/div/div/div/div/button"))
    #el = driver.find_element(By.XPATH, "/html/body/div[2]/div/div/div/div/button")
    el.click()
    driver.implicitly_wait(50)

    #wait = WebDriverWait(driver, 20)
    country = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[1]/div/div/form/div[1]/div[1]/input")
    country.send_keys("Taiwan")
    # select_object = Select(country)
    # select_object.select_by_value("Taiwan")
    # 在座標(100, 100)單擊畫面
    action = ActionChains(driver)
    action.move_by_offset(700, 700).click().perform()#隨便點一下畫面
    # Taiwan = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[1]/div/div/form/div[1]/div[2]/div[2]/div[1]")
    # Taiwan.click()
    time.sleep(2)
    driver.implicitly_wait(50)
    phone_box = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[1]/div/div/form/div[2]/input")
    #phone_box = driver.find_element(By.NAME,"q")
    phone_num = input("Enter your phone number: ")
    phone_box.send_keys(phone_num)
    driver.implicitly_wait(50)
    #select_element = wait.until(EC.visibility_of_element_located((By.XPATH, '/html/body/div[2]/div/div[1]/div/div/form/div[1]/div[1]/input')))
    #select_element = driver.find_element(By.XPATH, '//*[@id="language_select"]')
    #select_object = Select(select_element)
    #select_object.select_by_value("Taiwan")
    next = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[1]/div/div/form/button[1]/div")
    driver.implicitly_wait(50)
    #time.sleep(100)
    next.click()

    verification_code = input("Enter your verification code: ")
    driver.implicitly_wait(500)
    code_input = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[1]/div/div/div[2]/input")
    #phone_box = driver.find_element(By.NAME,"q")
    code_input.send_keys(verification_code)
    time.sleep(5)
    with open('cookies.pkl', 'wb') as f:
        pickle.dump(driver.get_cookies(), f)

    #print("chat_ai group test:")
    chatai_group_column = driver.find_element(By.CSS_SELECTOR, "title")
    chatai_group_column = driver.find_element(By.XPATH, "//a[@class='ListItem-button' and @href='#-955937484']")
    # 點擊元素
    chatai_group_column.click()
    #driver.implicitly_wait(1000)
    chatbox_input = WebDriverWait(driver, 1000).until(lambda d: d.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/div/div[2]/div[1]/div[1]/div/div[1]"))
    #chatbox_input = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/div/div[2]/div[1]/div[1]/div/div[1]")
    chatbox_input.send_keys(Keys.RETURN)
    question_group_list = ["/start"," :p ", "/start abc","/reset","/reset You are a helpful assistant","/reset abc","/help","/resend","//123","///123","//// 123","/ help","/image","/image cat","/stats","/false_command","/chat  hihi hello 123","/chat /start"]
    #question_group_list = ["/start"," :p ","/chat hihi"]
    driver.implicitly_wait(6000)
    #time.sleep(5)
    for test_case in question_group_list:
        question = test_case
        #question = question.lstrip()#telegram訊息送出時都會移除開頭
        print("Ask group: " + question)
        chatbox_input.send_keys(question)
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(1)##
        #driver.implicitly_wait(1000)
        send_button = WebDriverWait(driver, 1000).until(lambda d: d.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/button"))#chatbox_input = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, "your_xpath_here")))
        #send = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/button")
        send_button.click()
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(6)
        # 找到具有指定 class 的所有元素
        elements = driver.find_elements(By.CLASS_NAME, "text-content")
        wait_time = 0
        if elements:
            #取得最後一個元素的內容
            while(wait_time<200):
                # for element in elements:
                #     print(element.text)
                if len(elements)>=2:
                    a = rm_timestamp(elements[-2].text)
                    print(".")
                    send_question = question.lstrip()
                    send_question = send_question.rstrip()
                    if a != send_question:
                        #print(send_question)
                        driver.implicitly_wait(5000)
                        wait_time += 1
                        continue
                    else:
                        last_element = elements[-1]
                        content = last_element.text
                        # 輸出最後一個元素的內容
                        print("ans:")
                        print(content)
                        break
                else:
                    wait_time += 1
                    continue
            if wait_time >= 200:
                print("no response.")
    while(True):
        question = input("Ask something: ")
        #question = question.lstrip()#telegram訊息送出時都會移除開頭空白，所以這裡也要移除
        chatbox_input.send_keys(question)
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(1)
        #driver.implicitly_wait(100)
        send = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/button")
        send.click()
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(6)
        # 找到具有指定 class 的所有元素
        elements = driver.find_elements(By.CLASS_NAME, "text-content")
        wait_time = 0
        if elements:
        #取得最後一個元素的內容
            while(wait_time<1000):
                # for element in elements:
                #     print(element.text)
                if len(elements)>=2:
                    a = rm_timestamp(elements[-2].text)
                    print(".")
                    send_question = question.lstrip()
                    send_question = send_question.rstrip()
                    if a != send_question:
                        #print(a)
                        #print(send_question)
                        wait_time += 1
                        continue
                    else:
                        last_element = elements[-1]
                        content = last_element.text
                        # 輸出最後一個元素的內容
                        print("ans:")
                        print(content)
                        break
                else:
                    wait_time += 1
                    continue
            if wait_time >= 1000:
                print("no response.")
   

driver.quit()