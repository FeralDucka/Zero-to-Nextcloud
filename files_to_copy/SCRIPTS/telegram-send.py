import sys
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
TELEGRAM_API_KEY = "[API_KEY]"
TELEGRAM_CHAT_ID = "[CHAT_ID]"
message = "".join(sys.argv[1:])
if not message:
    sys.exit(1)
retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
session = requests.Session()
session.mount('https://', HTTPAdapter(max_retries=retries))
try:
    response = session.get(f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendMessage?chat_id={TELEGRAM_CHAT_ID}&parse_mode=markdown&text={message}")
    if response.status_code != 200:
        sys.exit(2)
except:
    sys.exit(3)
