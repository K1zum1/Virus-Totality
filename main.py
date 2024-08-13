import requests
import json
import pyperclip
import time
import tkinter as tk
from threading import Thread
from tkinter import scrolledtext
import os
from dotenv import load_dotenv
import re

pyperclip.copy('')
load_dotenv()
api_key = os.getenv('API_KEY')

requests_per_minute = 4  
request_count = 0
start_time = time.time()

def scan_content(content, content_type):
    url = f'https://www.virustotal.com/api/v3/{content_type}/{content}'
    headers = {
        "x-apikey": api_key  
    }
    response = requests.get(url, headers=headers)
    return response.json()

def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    text_widget.see(tk.END)

def determine_content_type(content):
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', content):  # ipaddress
        return 'ip_addresses'
    elif re.match(r'^https?://', content):  # url
        return 'urls'
    elif re.match(r'^[a-fA-F0-9]{32,64}$', content):  # hash
        return 'files'
    else:
        return 'domains'

def load_scanned_content():
    if os.path.exists('scanned_content.json'):
        with open('scanned_content.json', 'r') as file:
            return set(json.load(file))
    return set()

def save_scanned_content(scanned_content):
    with open('scanned_content.json', 'w') as file:
        json.dump(list(scanned_content), file)

def main(text_widget):
    global request_count, start_time
    last_content = ""
    scanned_content = load_scanned_content()  

    while True:
        if request_count >= requests_per_minute:
            time.sleep(60 - (time.time() - start_time))
            request_count = 0
            start_time = time.time()

        clipboard_content = pyperclip.paste().strip()
        content_type = determine_content_type(clipboard_content)

        # Only process valid content types
        if content_type and clipboard_content and clipboard_content != last_content:
            if clipboard_content not in scanned_content:
                try:
                    if content_type == 'urls':
                        clipboard_content = requests.utils.quote(clipboard_content, safe='')
                    result = scan_content(clipboard_content, content_type)
                    filtered_result = {
                        "Content": clipboard_content,
                        "Last Analysis Stats": result.get("data", {}).get("attributes", {}).get("last_analysis_stats"),
                    }
                    update_text(text_widget, json.dumps(filtered_result, indent=4))
                    scanned_content.add(clipboard_content)  
                    save_scanned_content(scanned_content) 
                    request_count += 1
                except Exception as e:
                    update_text(text_widget, f"Error: {e}")
            last_content = clipboard_content
        time.sleep(1)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Content Scanner")
    root.geometry("500x500")
    text = scrolledtext.ScrolledText(root, bg='black', fg='light green', font=("Courier", 10))
    text.pack(fill=tk.BOTH, expand=True)
    thread = Thread(target=main, args=(text,))
    thread.start()
    root.mainloop()
