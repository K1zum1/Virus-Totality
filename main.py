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


def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    text_widget.see(tk.END)

def main(text_widget):
    last_ip = ""
    while True:
        clipboard_ip = pyperclip.paste()
        if clipboard_ip != last_ip:
            try:
                result = scan_ip(clipboard_ip)
                filtered_result = {
                    "IP": result.get("data", {}).get("id"),
                    "Last Analysis Stats": result.get("data", {}).get("attributes", {}).get("last_analysis_stats"),
                }
                update_text(text_widget, json.dumps(filtered_result, indent=4))
                last_ip = clipboard_ip
            except Exception as e:
                update_text(text_widget, f"Error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("IP Scanner")
    root.geometry("500x500")
    text = scrolledtext.ScrolledText(root, bg='black', fg='light green', font=("Courier", 10))
    text.pack(fill=tk.BOTH, expand=True)
    thread = Thread(target=main, args=(text,))
    thread.start()
    root.mainloop()