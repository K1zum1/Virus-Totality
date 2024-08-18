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
import urllib.parse
import base64

pyperclip.copy('')
load_dotenv()
api_key = os.getenv('API_KEY')

requests_per_minute = 4  
request_count = 0
start_time = time.time()

def scan_content(content, content_type):
    if content_type == 'urls':
        content_bytes = content.encode('utf-8')
        base64_encoded_content = base64.urlsafe_b64encode(content_bytes).rstrip(b'=').decode('utf-8')
        url = f'https://www.virustotal.com/api/v3/urls/{base64_encoded_content}'
    else:
        url = f'https://www.virustotal.com/api/v3/{content_type}/{content}'

    headers = {
        "x-apikey": api_key  
    }
    response = requests.get(url, headers=headers)
    response_data = response.json()

    if 'error' in response_data and response_data['error']['code'] == 'NotFoundError':
        return {"Content": urllib.parse.unquote(content), "Error": "Resource not found in VirusTotal database."}

    data = response_data.get("data", {}).get("attributes", {})
    
    result = {
        "Content": urllib.parse.unquote(content),
        "Last Analysis Date": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get("last_analysis_date", 0))),
        "Reputation": data.get("reputation"),
        "Total Votes": data.get("total_votes"),
        "Categories": data.get("categories"),
        "Last Analysis Stats": data.get("last_analysis_stats"),
        "Scans": {engine: result["result"] for engine, result in data.get("scans", {}).items()},
    }

    return result


def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    text_widget.see(tk.END)

def determine_content_type(content):
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', content):
        return 'ip_addresses'
    elif re.match(r'^https?://', content):
        return 'urls'
    elif re.match(r'^[a-fA-F0-9]{32,64}$', content):
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

        if content_type and clipboard_content and clipboard_content != last_content:
            if clipboard_content not in scanned_content:
                try:
                    result = scan_content(clipboard_content, content_type)
                    decoded_content = urllib.parse.unquote(clipboard_content)

                    if "Error" in result:
                        update_text(text_widget, f"Error: {result['Error']}")
                    else:
                        
                        display_text = f"Content: {result['Content']}\n\n"
                        display_text += f"Last Analysis Date: {result['Last Analysis Date']}\n\n"
                        display_text += f"Reputation: {result['Reputation']}\n\n"
                        display_text += f"Total Votes: {result['Total Votes']}\n\n"
                        display_text += f"Categories: {result['Categories']}\n\n"
                        display_text += f"Last Analysis Stats: {json.dumps(result['Last Analysis Stats'], indent=4)}\n\n"
                        display_text += f"Scans:\n"

                        for engine, scan_result in result['Scans'].items():
                            display_text += f"  {engine}: {scan_result}\n"
                        
                        update_text(text_widget, display_text)
                    
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
    initial_message = "Welcome to the Virus Totality!\n\nCopy any URL, IP address, domain, or file hash to the clipboard, and it will be automatically scanned using the VirusTotal API.\n"
    update_text(text, initial_message)
    thread.start()
    root.mainloop()
