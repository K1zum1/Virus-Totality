import requests
import json
import pyperclip
import time
import tkinter as tk
from threading import Thread
from tkinter import scrolledtext
import os
from dotenv import load_dotenv


load_dotenv()
api_key = os.getenv('API_KEY')

def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        "x-apikey": api_key  
    }
    response = requests.get(url, headers=headers)
    return response.json()


