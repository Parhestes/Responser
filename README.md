# Responser - Burp Suite Extension

**Responser** is a lightweight Burp Suite extension written in Python (Jython) that monitors HTTP traffic in real-time to detect specific keywords within HTTP responses. It is designed to help security researchers and bug hunters identify sensitive data, role-based access control (RBAC) issues, or interesting debug information.

## Features
- **Real-time Monitoring:** Automatically scans responses from Proxy, Repeater, and Intruder.
- **Customizable Keywords:** Easily add/remove keywords via the UI.
- **Active/Passive Control:** Toggle specific keywords using checkboxes without deleting them.
- **Detailed Table:** View findings with ID, Status, Method, Path, and Response Length.
- **Integrated View:** Click on any finding to see the original Request and Response.

## Default Keywords
The tool comes pre-loaded with common sensitive patterns:
- `"isAdmin": true/false`
- `"role": "user/admin"`
- `"success": false`
- `"authenticated": false`
- And more...

## Installation
1. Download `Responser.py`.
2. Open Burp Suite.
3. Go to **Extensions** -> **Installed** -> **Add**.
4. Select **Extension Type** as `Python`.
5. Select `Responser.py` as the extension file.
*Note: You must have [Jython](https://www.jython.org/download) configured in Burp Suite.*

## Screenshots
[Add your screenshots here to show the UI]

## License
MIT License - Feel free to use and contribute!
