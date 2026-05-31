# 🛡️ PhishGuard — Phishing Detection Web App

A beginner-friendly phishing detection web application built with **React** and **Node.js**. Paste any URL to instantly analyze it for phishing threats.

![Status](https://img.shields.io/badge/status-ready-brightgreen)
![Node](https://img.shields.io/badge/node-%3E%3D16-blue)
![React](https://img.shields.io/badge/react-18-61dafb)

---

## ✨ Features

- 🔍 **URL Scanner** — Paste any URL and get instant phishing analysis
- 📊 **Risk Score** — Visual risk gauge (0-100) with color-coded results
- 🛡️ **15 Detection Checks** — HTTP, IP addresses, suspicious TLDs, brand impersonation, homograph attacks, and more
- 📋 **Scan History** — All scans are stored in a SQLite database
- 📈 **Dashboard Stats** — Track total scans, safe/suspicious/phishing counts
- 🎨 **Modern Dark UI** — Glassmorphism, gradients, micro-animations
- 📱 **Fully Responsive** — Works on desktop, tablet, and mobile

---

## 🚀 How to Run Locally

### Prerequisites
- **Node.js** v16 or higher
- **npm** (comes with Node.js)

### Step 1: Install Dependencies

```bash
# Install backend dependencies
npm install

# Install frontend dependencies
cd client && npm install && cd ..
```

### Step 2: Build the React Frontend

```bash
cd client && npm run build && cd ..
```

### Step 3: Start the Server

```bash
npm start
```

### Step 4: Open the App

Visit **http://localhost:5000** in your browser.

---

## 🔧 Development Mode (Hot Reload)

To run both backend and frontend with hot reload:

```bash
npm run dev
```

- Backend runs on **http://localhost:5000**
- Frontend runs on **http://localhost:3000** (proxied to backend)

---

## 🖥️ How to Run on Replit (Step-by-Step)

### Step 1: Create a New Replit
1. Go to [replit.com](https://replit.com) and sign in
2. Click **"+ Create Repl"**
3. Choose **"Node.js"** as the template
4. Name it `phishing-detection` and click **"Create Repl"**

### Step 2: Upload the Project Files
1. Delete any default files Replit created
2. Drag and drop ALL the project files into the Replit file panel, OR:
   - Use the **"Upload file"** or **"Upload folder"** option in Replit's file panel
   - Make sure the folder structure matches exactly

### Step 3: Install Dependencies
In the Replit **Shell** tab, run:

```bash
npm install
cd client && npm install && cd ..
```

### Step 4: Build the Frontend
In the Shell, run:

```bash
cd client && npm run build && cd ..
```

### Step 5: Click Run!
- Press the green **▶ Run** button at the top
- Replit will start the server and show the app in the Webview panel
- The `.replit` file is already configured to run `npm start`

### Step 6: Open in New Tab
- Click the **"Open in new tab"** button in the Webview panel to see the full app
- Share the Replit URL with others!

---

## 📁 Project Structure

```
phishing-detection/
├── server.js              # Express backend with phishing detection engine
├── package.json           # Backend dependencies & scripts
├── .replit                # Replit run configuration
├── replit.nix             # Replit Nix packages
├── db/
│   └── database.js        # SQLite database setup
├── client/
│   ├── package.json       # React dependencies
│   ├── public/
│   │   └── index.html     # HTML entry point
│   └── src/
│       ├── index.js       # React entry point
│       ├── index.css      # Full design system & styles
│       └── App.js         # Main React application
```

---

## 🔍 Detection Checks

| # | Check | Risk Weight |
|---|-------|-------------|
| 1 | HTTP vs HTTPS | +15 |
| 2 | IP address instead of domain | +30 |
| 3 | Suspicious TLDs (.xyz, .tk, etc.) | +20 |
| 4 | Excessive subdomains | +15 |
| 5 | Extremely long hostname | +15 |
| 6 | Contains @ symbol | +25 |
| 7 | Homograph/Cyrillic characters | +35 |
| 8 | Brand impersonation | +30 |
| 9 | Suspicious keywords in path | +8-25 |
| 10 | URL shortener | +10 |
| 11 | Excessive hyphens | +15 |
| 12 | Long numeric sequences | +10 |
| 13 | Punycode domain | +20 |
| 14 | Data/JavaScript protocol | +40 |
| 15 | Unusual characters | +15 |

### Risk Levels
- **0-24** → 🟢 **Safe**
- **25-59** → 🟡 **Suspicious**
- **60-100** → 🔴 **Phishing**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Scan a URL for phishing |
| GET | `/api/history` | Get scan history |
| GET | `/api/stats` | Get scanning statistics |
| DELETE | `/api/history` | Clear all history |
| DELETE | `/api/history/:id` | Delete a single scan |

---

## 🛠️ Tech Stack

- **Frontend:** React 18, Vanilla CSS
- **Backend:** Node.js, Express
- **Database:** SQLite (via better-sqlite3)
- **Fonts:** Inter (Google Fonts)

---

## 📝 License

MIT License — Free to use, modify, and distribute.
