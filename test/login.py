import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

domain = 'http://localhost:8000'
endpoint = '/login'
api_key = os.getenv('API_KEY')
headers={'Authorization': f'Bearer {api_key}'}
payload={'id': '7'}

r = requests.post(f'{domain}/login', json=payload, headers=headers)

assert r.status_code == 200

with open('cookies.json', 'w') as f:
    json.dump(r.json(), f)
