# 📘 The Ultimate Beginner's Guide to PhoenixSec

Welcome to **PhoenixSec**! If you're reading this, you probably want to write secure code but don't have the time to learn everything about cybersecurity. That is exactly why we built this tool!

PhoenixSec is an **Auto-Healing Security Tool**. It acts like a Senior Security Engineer sitting next to you. It finds vulnerabilities, explains why they are bad, and (most importantly) **fixes them for you automatically**.

This guide is designed for absolute beginners. We will go step-by-step to get you set up in minutes.

---

## 🛠️ Step 1: Super Easy Setup

### 1. Install PhoenixSec
Open your terminal (Command Prompt, PowerShell, or Mac Terminal) and type these commands:

```bash
# Download the tool to your computer
git clone https://github.com/thefayid/PhoenixSec.git

# Go into the folder
cd PhoenixSec

# Install the tool globally
pip install -e .
```

*To check if it worked, type `phoenixsec version`. You should see a version number pop up!*

### 2. Add your AI Brain (Optional but highly recommended)
PhoenixSec uses AI (Google Gemini) to write secure code fixes for you. 
1. Get a free API Key from [Google AI Studio](https://aistudio.google.com/).
2. Save it in your computer's environment variables or create a file named `.env` in your project folder and add this line:
   ```bash
   GEMINI_API_KEY="your-api-key-here"
   ```

You are done setting up! 🎉 Now, let's learn how to use the 4 superpowers of PhoenixSec.

---

## 🦸‍♂️ Superpower 1: The Basic Scanner
The most basic thing you can do is ask PhoenixSec to scan your project for security holes.

### How to use it:
Open your terminal inside your coding project folder and type:
```bash
phoenixsec scan .
```
*(The `.` means "scan everything in this current folder")*

### What happens:
PhoenixSec will read your code and print out a beautifully colorized report. If you have an SQL Injection or Cross-Site Scripting (XSS) vulnerability, it will point out the exact file, the exact line number, and explain how to fix it!

---

## 🦸‍♂️ Superpower 2: The Auto-Fixer (AI Patcher)
Finding bugs is boring. Fixing them automatically is awesome. Let's tell PhoenixSec to fix the bugs for us.

### How to use it:
```bash
phoenixsec scan . --patch
```

### What happens:
1. PhoenixSec finds a vulnerability.
2. It sends the broken code to its AI brain.
3. The AI writes a highly secure fix.
4. PhoenixSec pops up a color-coded preview on your screen showing you exactly what lines of code will change.
5. It asks: `Apply this patch? [y/N]`
6. You press `y`, hit Enter, and your code is instantly rewritten securely!

---

## 🦸‍♂️ Superpower 3: The Secret Auto-Rotator
Have you ever accidentally pasted an AWS API Key or GitHub Token into your code? Hackers steal these in seconds. PhoenixSec has a built-in auto-rotator to save you.

### How to use it:
```bash
phoenixsec scan . --rotate-secrets
```

### What happens:
If PhoenixSec finds an exposed AWS Key in your code, it won't just yell at you. It actually connects to the cloud, **destroys the leaked key so hackers can't use it**, generates a brand new secure key, and securely saves it into your local `.env` file! It neutralizes the threat for you.

---

## 🦸‍♂️ Superpower 4: The Agentic Red Teamer (Proof-of-Exploit)
Sometimes security scanners lie. They flag "false positives" (things that look like vulnerabilities but aren't actually hackable). The Red Teamer stops this.

### How to use it:
```bash
phoenixsec scan . --prove
```

### What happens:
When PhoenixSec finds a vulnerability, it spawns an invisible "Hacker Bot" in the background. The bot actually writes a hacking script and attacks your code in a safe sandbox. 
* If the bot successfully hacks your code, it tells you: **"✓ PROVEN"**
* If the bot fails to hack it, it throws out the warning so you don't waste your time!

---

## 🪄 The Ultimate Superpower: Real-Time Vibe-Guard (For VS Code & Cursor)
What if you didn't even have to open the terminal? What if PhoenixSec just fixed your code *as you type*?

We built a **Language Server** that hooks directly into your code editor (like VS Code, Cursor, or Neovim).

### How to set it up:
1. Open your terminal and start the background server:
   ```bash
   phoenixsec lsp
   ```
2. *(If you use VS Code/Cursor)*: Install the `phoenixsec-vscode` extension inside the `ide/` folder.

### What happens:
As you type code, if you write something insecure (or if GitHub Copilot hallucinates bad code), you will instantly get a **squiggly line** under your text—just like a spelling mistake in Microsoft Word!

**The Magic Trick:** Hover your mouse over the squiggly line and press **`Ctrl + .`** (Quick Fix).
A menu will pop up saying *"PhoenixSec: Apply Auto-Fix"*. Click it, and PhoenixSec will rewrite your code to be perfectly secure right in front of your eyes!

---

## 🔁 Automating it in GitHub (CI/CD)
Want PhoenixSec to automatically scan your code every time you push to GitHub? 

Create a file in your project at `.github/workflows/security.yml` and paste this exactly:

```yaml
name: 🛡️ PhoenixSec Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install PhoenixSec
        run: pip install git+https://github.com/thefayid/PhoenixSec.git
      - name: Run Security Scan
        run: phoenixsec scan .
```
Now, every time you push code, PhoenixSec will automatically run and inspect your project for security issues!

---

### You're ready!
You are now fully equipped to write hyper-secure code at lightning speed. Have fun building!
