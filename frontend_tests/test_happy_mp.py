# -*- coding: utf-8 -*-
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
import traceback
import nose2
import time
import os


REPO = "https://github.com/everware/everware-cpp-example.git"

if os.environ.get('TRAVIS') == 'true':
    DRIVER = "phantomjs"
else:
    DRIVER = "firefox"

# Test matrix
SCENARIOS = ["scenario_short", "scenario_full"]
USERS = ["user1", "user2"]
TIMEOUT = 250
UPLOADDIR = os.environ['UPLOADDIR']


def make_screenshot(driver, name):
    os.makedirs(UPLOADDIR, exist_ok=True)
    driver.save_screenshot(os.path.join(UPLOADDIR, name))


class User:
    def __init__(self, login=None, repo=REPO, driver_type=DRIVER):
        self.login = login
        self.repo = repo
        self.password = ""
        self.log("init")

        self.driver_type = driver_type
        self.base_url = "http://localhost:8000/"
        self.verificationErrors = []
        self.accept_next_alert = True


    def get_driver(self):
        if self.driver_type == "phantomjs":
            os.makedirs(UPLOADDIR, exist_ok=True)
            self.driver = webdriver.PhantomJS(
                service_log_path=os.path.join(UPLOADDIR, "phantom_%s.log" % self.login))
            self.driver.set_window_size(1024, 768)
        if self.driver_type == "firefox":
            self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(TIMEOUT)
        return self.driver


    def tearDown(self):
        self.driver.quit()
        # return self.verificationErrors

    def log(self, message):
        print("{}:     {}".format(self.login, message))


    def wait_for_element_present(self, how, what, displayed=True, timeout=TIMEOUT):
        for i in range(timeout):
            element = self.driver.find_element(by=how, value=what)
            if element is not None and element.is_displayed() == displayed:
                time.sleep(1)  # let handlers attach to the button
                break
            time.sleep(1)
        else: assert False, "time out waiting for (%s, %s)" % (how, what)


    def is_element_present(self, how, what):
        try: self.driver.find_element(by=how, value=what)
        except NoSuchElementException as e: return False
        return True


def test_generator():
    for username in USERS:
        yield run_scenario, username, SCENARIOS


def run_scenario(username, scenario):
    user = User(username)
    try:
        if isinstance(scenario, str):
            globals()[scenario](user)
        if isinstance(scenario, list):
            for s in scenario:
                globals()[s](user)
    except Exception as e:
        make_screenshot(user.driver, "{}-{}.png".format(scenario, username))
        print("oops,  Exception: {}\n{}".format(repr(e), ''.join(traceback.format_stack())))
        raise e
        # assert False, "Exception: {}\n{}".format(e.msg, ''.join(traceback.format_stack()))
    finally:
        user.tearDown()

  

def scenario_short(user):
    driver = user.get_driver()
    driver.get(user.base_url + "/hub/login")
    user.log("login")
    driver.find_element_by_id("username_input").clear()
    driver.find_element_by_id("username_input").send_keys(user.login)
    driver.find_element_by_id("password_input").clear()
    driver.find_element_by_id("password_input").send_keys(user.password)
    driver.find_element_by_id("login_submit").click()
    user.wait_for_element_present(By.ID, "start")
    driver.find_element_by_id("logout").click()
    user.log("logout clicked")


def scenario_short_bad(user):
    driver = user.get_driver()
    driver.get(user.base_url + "/hub/login")
    user.log("login")
    driver.find_element_by_id("username_input").clear()
    driver.find_element_by_id("username_input").send_keys(user.login)
    driver.find_element_by_id("password_input").clear()
    driver.find_element_by_id("password_input").send_keys(user.password)
    driver.find_element_by_id("login_submit").click()
    user.wait_for_element_present(By.ID, "start1")
    driver.find_element_by_id("logout").click()
    user.log("logout clicked")


def scenario_full(user):
    driver = user.get_driver()
    driver.get(user.base_url + "/hub/login")
    user.log("login")
    driver.find_element_by_id("username_input").clear()
    driver.find_element_by_id("username_input").send_keys(user.login)
    driver.find_element_by_id("password_input").clear()
    driver.find_element_by_id("password_input").send_keys(user.password)
    driver.find_element_by_id("login_submit").click()
    user.wait_for_element_present(By.ID, "start")
    driver.find_element_by_id("start").click()
    driver.find_element_by_id("repository_input").clear()
    driver.find_element_by_id("repository_input").send_keys(user.repo)
    driver.find_element_by_xpath("//input[@value='Spawn']").click()
    user.log("spawn clicked")
    user.wait_for_element_present(By.LINK_TEXT, "Control Panel")
    driver.find_element_by_link_text("Control Panel").click()
    user.wait_for_element_present(By.ID, "stop")
    driver.find_element_by_id("stop").click()
    user.log("stop clicked")
    user.wait_for_element_present(By.ID, "start")
    driver.find_element_by_id("logout").click()
    user.log("logout clicked")

if __name__ == "__main__":
    nose2.main()
