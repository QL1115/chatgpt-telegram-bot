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


def rm_timestamp(string):
    new_string = ""
    lines = string.splitlines()
    if len(lines) > 1:
        new_string = "\n".join(lines[:-1])
    elif len(lines) == 1:
        new_string = lines[0]
    return new_string
options = Options()
options.add_argument('--headless')
options.add_argument('--window-size=1920,1080')
options.add_argument('--disable-gpu')
#options.add_argument("--enable-local-storage")

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

#driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.get("https://web.telegram.org/a/")

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
    phone_num = input("Enter your phone number: ")#971234567
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




    chatai_column = driver.find_element(By.CSS_SELECTOR, "title")
    chatai_column = driver.find_element(By.XPATH, "//a[@class='ListItem-button' and @href='#5703123553']")
    # 點擊元素
    chatai_column.click()
    driver.implicitly_wait(1000)
    chatbox_input = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/div/div[2]/div[1]/div[1]/div/div[1]")
    chatbox_input.send_keys(Keys.RETURN)
    question_list = ["/start","You are a helpful assistant"," abc",":p "," 123 ", "/start abc","/reset","/reset /help","/reset You are a helpful assistant","/reset/help","/reset\help","/reset abc","/help","/resend","\help","!help","//help","/ help","help","/resend","/image","/image cat","/image "" []980,j hui 123","/stats","/false_command","/false_command 123"]
    driver.implicitly_wait(5000)
    #time.sleep(5)
    for test_case in question_list:
        question = test_case
        #question = question.lstrip()#telegram訊息送出時都會移除開頭
        print("Ask something: " + question)
        chatbox_input.send_keys(question)
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(1)
        #driver.implicitly_wait(1000)
        send = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/button")
        send.click()
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(5)
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
                print("false command.")
    while(True):
        question = input("Ask something: ")
        #question = question.lstrip()#telegram訊息送出時都會移除開頭空白，所以這裡也要移除
        chatbox_input.send_keys(question)
        #chatbox_input.send_keys(Keys.RETURN)
        driver.implicitly_wait(100)
        send = driver.find_element(By.XPATH, "/html/body/div[2]/div/div[2]/div[4]/div[2]/div/div[2]/div/button")
        send.click()
        #chatbox_input.send_keys(Keys.RETURN)
        time.sleep(5)
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
                print("please try again.")

driver.quit()