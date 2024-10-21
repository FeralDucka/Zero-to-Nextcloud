import sys
import requests
TELEGRAM_API_KEY = "[API_KEY]"
TELEGRAM_CHAT_ID = "[CHAT_ID]"
message = " ".join(sys.argv[1:])
if not message:
    sys.exit(1)
response = requests.get(f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&parse_mode=markdown&text={message}")
if response.status_code != 200:
    sys.exit(2)
