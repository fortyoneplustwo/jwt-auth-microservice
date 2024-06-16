import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

domain = 'http://localhost:8000'
endpoint = '/validate'
api_key = os.getenv('API_KEY')
headers={'Authorization': f'Bearer {api_key}'}

with open('cookies.json', 'r') as f:
    payload = json.load(f)

r = requests.post(domain + endpoint, json=payload, headers=headers)

assert r.status_code == 200

with open('decoded.json', 'w') as f:
    json.dump(r.json(), f)
