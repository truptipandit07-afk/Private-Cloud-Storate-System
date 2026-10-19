# Private-Cloud-Storate-System
# Private Cloud Storage (Flask + SQLite + Linux, optional Nextcloud)

Features: register/login, multi-file upload, download, rename, delete, search,
expiring share links, per-user 1 GB quota, CSRF protection, hashed passwords.

## Run (Linux)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
python app.py                       # dev: http://<server-ip>:5000
gunicorn -w 3 -b 0.0.0.0:8000 app:app   # production-style
```

## Optional: mirror uploads to Nextcloud (WebDAV)
Install Nextcloud (e.g. `docker run -d -p 8080:80 nextcloud`), create an app password, then:
```bash
export NEXTCLOUD_URL=http://localhost:8080
export NEXTCLOUD_USER=admin
export NEXTCLOUD_PASS=<app-password>
```
Every upload is then also PUT to `remote.php/dav/files/<user>/` on Nextcloud.

## Run as a service (systemd) - /etc/systemd/system/pcloud.service
```
[Unit]
Description=Private Cloud
After=network.target
[Service]
User=www-data
WorkingDirectory=/opt/private-cloud
Environment=SECRET_KEY=change-me
ExecStart=/opt/private-cloud/venv/bin/gunicorn -w 3 -b 127.0.0.1:8000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
```
Put Nginx in front (`client_max_body_size 500M;`) and enable HTTPS (Let's Encrypt or a self-signed cert on LAN).
