# Virus Totality

This is a fun project that I made to develop my API and Cybersecurity skills. This is a Python application that automatically scans IP addresses, URLs, domains, and file hashes copied to your clipboard using the VirusTotal API. The results are displayed in a Tkinter GUI.

## Set Up

**Add your api key**

```
API_KEY = "your_api_key_here"
```
**Then install your packages**

```bash
python -m venv venv
```

```bash
venv\Scripts\activate
pip install -r packages.txt
pip freeze > packages.txt
python main.py
```

**You can manually clear your clipboard manually or add this piece of code to do it automatically**

```python
import pyperclip
pyperclip.copy('')
```

**On Windows you can manually clear it like this**

```bash
echo off | clip
```

**On MacOS you can manually clear it like this**
```   
pbcopy < /dev/null
```