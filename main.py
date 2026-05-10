import json
import os
import sys 
import subprocess
import filecmp
import shutil
import time
import pwd
from pathlib import Path
import re

DRY_RUN = False
# DRY_RUN = True

username = subprocess.getoutput("loginctl list-users --no-legend | awk 'NR==1{print $2}'")

home_path = pwd.getpwnam(username).pw_dir
firefox_path = os.path.join(home_path, 'snap/firefox/common/.mozilla/firefox')
profiles_ini_path = os.path.join(firefox_path, 'profiles.ini')
with open(profiles_ini_path) as fd:
    while True:
        line = fd.readline()
        if not line:
            break
        if re.match('^Path=', line):
            profile_path = os.path.join(firefox_path, line.split('=')[1].strip())
            break

ext_path = os.path.join(profile_path, 'extensions.json')
with open(ext_path) as fd:
     json_data = json.load(fd)
addon_startup_path = os.path.join(profile_path, 'addonStartup.json.lz4')

killed = False
restart = False

for addon in json_data["addons"]:
    if addon["id"] == "leechblockng@proginosko.com":
        print(f"EXTENSION ACTIVE: {addon["active"]}", flush=True)
        # if True:
        if not addon["active"]:
            print("NOT ACTIVE", flush=True)
            addon["active"] = True
            addon["userDisabled"] = False
            os.system("pkill firefox")
            killed = True
            with open(ext_path, 'w') as f:
                json.dump(json_data, f)
            restart = True
            break

policies_path = "/etc/firefox/policies/policies.json"
if not os.path.isfile(policies_path) or not filecmp.cmp("policies.json", policies_path):
    print("COPIING policies.json file", flush=True)
    if not DRY_RUN:
        shutil.copyfile("policies.json", policies_path)
    restart = True

chrome_path = os.path.join(profile_path, 'chrome', 'userChrome.css')
if not os.path.isfile(chrome_path) or not filecmp.cmp("userChrome.css", chrome_path):
    print("COPYING userChrome.css file", flush=True)
    if not DRY_RUN:
        shutil.copyfile("userChrome.css", chrome_path)
    restart = True

if restart:
    if not killed:
        print("KILLING FIREFOX", flush=True)
        if not DRY_RUN:
            os.system("pkill firefox")
    print("RESTARTING FIREFOX", flush=True)
    if not DRY_RUN:
        if os.path.exists(addon_startup_path):
            os.remove(addon_startup_path)
        new_env = os.environ | {"DISPLAY": ":0", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{pwd.getpwnam(username).pw_uid}/bus"}
        p = subprocess.Popen(["/snap/bin/firefox"], env=new_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, user=username)

# UNINSTALL DISCORD
# UNINSTALL VIVALDI AND REMOVE .deb file for ~/Downloads (global path)
# Add killswitch - check if vivaldi was installed and if it is, count amount of installations in an hour and if it is >10 stop service for and hour (it could be en emergency, but if isn't removing .deb file will make it harder)
# Add some kind of update code that will check certain path and will load code but if it tries to stop everything it should load code before this update (to not be outsmarted)
# if I will disable network, killswitch could be adding and removing specific file 60 times during five minutes

time.sleep(30)
