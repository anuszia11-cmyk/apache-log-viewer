import json

logs = [
    {"ip": "192.168.1.10", "timestamp": "2026-10-30 09:00:01", "request": "GET /home", "status": 200, "size": 1520},
    {"ip": "192.168.1.11", "timestamp": "2026-10-30 09:00:05", "request": "GET /products", "status": 200, "size": 2450},
    {"ip": "192.168.1.12", "timestamp": "2026-10-30 09:01:10", "request": "GET /login", "status": 200, "size": 980},
    {"ip": "192.168.1.20", "timestamp": "2026-10-30 09:02:15", "request": "POST /login", "status": 401, "size": 620},
    {"ip": "192.168.1.20", "timestamp": "2026-10-30 09:02:18", "request": "POST /login", "status": 401, "size": 620},
    {"ip": "192.168.1.20", "timestamp": "2026-10-30 09:02:22", "request": "POST /login", "status": 401, "size": 620},
    {"ip": "192.168.1.15", "timestamp": "2026-10-30 09:03:00", "request": "GET /products/chair", "status": 200, "size": 3100},
    {"ip": "192.168.1.16", "timestamp": "2026-10-30 09:03:20", "request": "GET /products/table", "status": 200, "size": 2900},
    {"ip": "192.168.1.20", "timestamp": "2026-10-30 09:04:01", "request": "GET /admin", "status": 403, "size": 450},
    {"ip": "192.168.1.17", "timestamp": "2026-10-30 09:04:15", "request": "GET /contact", "status": 200, "size": 1200},
    {"ip": "192.168.1.18", "timestamp": "2026-10-30 09:05:00", "request": "GET /about", "status": 200, "size": 1100},
    {"ip": "192.168.1.21", "timestamp": "2026-10-30 09:05:10", "request": "GET /robots.txt", "status": 200, "size": 350},
    {"ip": "192.168.1.22", "timestamp": "2026-10-30 09:06:00", "request": "GET /products/sofa", "status": 200, "size": 2800},
    {"ip": "192.168.1.23", "timestamp": "2026-10-30 09:06:30", "request": "POST /login", "status": 401, "size": 620},
    {"ip": "192.168.1.24", "timestamp": "2026-10-30 09:07:00", "request": "GET /cart", "status": 200, "size": 1750},
    {"ip": "192.168.1.25", "timestamp": "2026-10-30 09:07:30", "request": "GET /checkout", "status": 200, "size": 2100},
    {"ip": "192.168.1.26", "timestamp": "2026-10-30 09:08:00", "request": "GET /admin", "status": 403, "size": 450},
    {"ip": "192.168.1.27", "timestamp": "2026-10-30 09:08:30", "request": "GET /products/desk", "status": 200, "size": 2600},
    {"ip": "192.168.1.28", "timestamp": "2026-10-30 09:09:00", "request": "GET /search?q=chair", "status": 200, "size": 1400},
    {"ip": "192.168.1.20", "timestamp": "2026-10-30 09:09:30", "request": "GET /admin", "status": 403, "size": 450}
]

with open("logs.json", "w", encoding="utf-8") as file:
    json.dump(logs, file, indent=4)

print("Successfully generated 20 sample log entries!")