## Use these commands from your Linux VM with the repo mounted at something like `/home/oriongd/CNS_LOCAL/CNS`.

---

### 1. Infrastructure services

#### Redis
```bash
sudo systemctl start redis
sudo systemctl status redis
```

If Redis is not installed:
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl enable --now redis
```

#### PostgreSQL
```bash
sudo systemctl start postgresql
sudo systemctl status postgresql
```

If you need to use the repo’s default DB env:
```bash
export DATABASE_URL="postgresql://<user>:<pass>@localhost:5433/<dbname>"
```

#### Elasticsearch
Run Elasticsearch in Docker:
```bash
sudo docker run -d --name elasticsearch -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0
```

Verify:
```bash
curl http://localhost:9200
```

---

### 2. Backend environment

From repo root:

```bash
cd /home/oriongd/CNS_LOCAL/CNS
python3 -m venv .venv
source .venv/bin/activate
pip install -r back-end/requirements.txt
```

---

### 3. Run the Backend API

From back-end:
```bash
cd /home/oriongd/CNS_LOCAL/CNS/back-end
uvicorn api.main:app --reload --port 8000
```

Or from repo root:
```bash
cd /home/oriongd/CNS_LOCAL/CNS
uvicorn api.main:app --reload --port 8000 --app-dir back-end
```

---

### 4. Start background workers

Open separate terminals for each:

```bash
cd /home/oriongd/CNS_LOCAL/CNS
source .venv/bin/activate
python back-end/core/analysis_worker.py
```

```bash
cd /home/oriongd/CNS_LOCAL/CNS
source .venv/bin/activate
python back-end/core/soar_worker.py
```

```bash
cd /home/oriongd/CNS_LOCAL/CNS
source .venv/bin/activate
python back-end/core/snort_bridge.py http://localhost:8000 logs/alert.json
```

---

### 5. Start Snort for real packet capture

In a separate terminal:
```bash
cd /home/oriongd/CNS_LOCAL/CNS
sudo bash scripts/run_snort.sh
```

Make sure the script selects the correct network interface on the VM.

---

### 6. Frontend dashboard

```bash
cd /home/oriongd/CNS_LOCAL/CNS/front-end
npm install
npm run dev
```

Then open:
```text
http://localhost:5173
```

---

### 7. Verify system

- API: `http://localhost:8000/docs`
- Frontend: `http://localhost:5173`
- Redis: `redis-cli ping`
- Elasticsearch: `curl http://localhost:9200`

---

## Notes

Verifying frontend network configuration before answering so I can give the exact cross-host setup.

Read [](file:///e%3A/PROJECTS/CNS/front-end/vite.config.js)

Searched for regex `fetch\(|axios|http://|localhost:|process.env|API` (`**/front-end/src/**/*.{js,jsx,ts,tsx}`), 39 results

Read [](file:///e%3A/PROJECTS/CNS/front-end/src/services/api.js)

Searched for files matching `**/.env*`, 1 match

Read [](file:///e%3A/PROJECTS/CNS/.env.example)

## Yes — backend in VMware, frontend on Windows is fine

### How to do it

1. Run backend in the VM
   - Start backend from the VM repo path:
     ```bash
     cd /home/oriongd/CNS_LOCAL/CNS/back-end
     source .venv/bin/activate
     uvicorn api.main:app --host 0.0.0.0 --port 8000
     ```
   - `--host 0.0.0.0` is important so the VM accepts connections from your Windows host.

2. Find the VM IP
   - On the VM, run:
     ```bash
     ip a
     ```
   - Use the VM IP on the same network, e.g. `192.168.x.y`.

3. Run frontend on Windows
   - From Windows, in front-end:
     ```powershell
     npm install
     set VITE_API_BASE_URL=http://<vm-ip>:8000
     npm run dev
     ```
   - Or create a .env in front-end:
     ```env
     VITE_API_BASE_URL=http://<vm-ip>:8000
     VITE_WS_URL=ws://<vm-ip>:8000/ws/events
     ```

4. Open dashboard on Windows
   - Visit:
     ```text
     http://localhost:1234
     ```

### Why it works

- Front-end uses `VITE_API_BASE_URL` in api.js
- Backend already allows CORS from any origin
- Frontend will call the VM backend through `http://<vm-ip>:8000`

### Important network details

- If VMware is bridged, Windows and VM are on the same LAN.
- If VMware is NAT, you need port forwarding from the host to the VM.
- If you use `localhost` on Windows, it refers to Windows, not the VM.

### Example

```powershell
# On Windows
cd C:\path\to\CNS\front-end
npm install
set VITE_API_BASE_URL=http://192.168.1.10:8000
set VITE_WS_URL=ws://192.168.1.10:8000/ws/events
npm run dev
```

If you want, I can also give you the exact VMware network mode and Windows port-forward setup for your environment.