# STOMPscan (Ningu Module) 

> **STOMPscan v1.3.2** – A graphical reconnaissance tool that fingerprints ActiveMQ / Artemis / other STOMP‑speaking brokers from within the modular **Ningu (忍具)** framework.  
> **Part of the [HACKtiveMQ] tool suite** for broker reconnaissance and penetration testing.

---

## ✨ What it does
* **Mass‑scan hosts** (IPv4 or DNS) on a user‑selected port using raw STOMP frames over **TCP or SSL**  
* **Identifies broker version** by hashing server stack‑traces and mapping them to known releases  
* **Detects authentication state** (enabled/disabled) and brute‑tests **default credential pairs** from `stomp-defaults.txt`  
* **Captures server banner** (`server:` line in CONNECTED frame)  
* **Generates SHA‑256 fingerprints** for unknown stack‑trace combinations  
* Real‑time status output and **sortable results table** exportable to CSV

---

## 📂 Repository layout
```

modules/
├─ 1_STOMPscan.py          # ← this file (rename as you wish)
├─ stomp-defaults.txt     # username\:password pairs, one per line
└─ …                      # any other Ningu modules

````

---

## 🚀 Setup

1. **Clone / copy** the two files above into the `modules/` directory of your **Ningu** project.  
2. Verify Python 3.8+ and **PySide6** (≥ 6.4) are installed:
   ```bash
   pip install PySide6
````

3. Launch your main Ningu GUI (e.g. `python ningu-v1.0.0.py` or `python HACKtiveMQ-v1.0.0.py`).
   Ningu/HACKtiveMQ auto‑discovers the module and adds a **“STOMPscan v1.3.2”** tab.

---

## 🖥️ Using STOMPscan

| Step  | Action                                                                                                                                 |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | Paste or load a list of hosts/IPs into **Hosts** box.<br/>🛈  Use **Load**, **Save**, **Clear**, or **Sort+Dedup** to manage the list. |
| **2** | Pick the **port** (default **61613**) and toggle **TCP / SSL**.                                                                        |
| **3** | Click **Scan** or press **Enter** in the port box.                                                                                     |
| **4** | Watch the **Status** pane for live logging; results populate in the table.                                                             |
| **5** | Save results with **Output → Save** (CSV).                                                                                             |

**Column meanings**

| Column        | Description                                                   |        |
| ------------- | ------------------------------------------------------------- | ------ |
| Timestamp     | Local scan time (YYYY‑MM‑DD HH\:MM\:SS)                       |        |
| Hostname      | Target host                                                   |        |
| Port          | \`<port>/\<tcp                                                | ssl>\` |
| Defaults      | `username:password` pairs that succeeded, `None`, or `error`  |        |
| Auth Status   | `disabled` / `enabled` / `unknown`                            |        |
| Server String | Broker banner (if provided)                                   |        |
| Fingerprint   | ‑ Known version (*e.g.* `v5.15.0-5.15.4`) or raw SHA‑256 hash |        |

---

## ⚙️ Configuration

* **Default credential list** → edit `modules/stomp-defaults.txt`
  Format: `username:password` (one per line).
  Lines starting with `#` are ignored.
* **Stack‑trace ↔ version mapping** lives in `STACK_TRACE_TO_VERSION` inside the module.
  Add new hashes as you discover them.

---

## 🛠️ Extending

STOMPscan follows Ningu’s plugin contract:

```python
class TabContent(QWidget):
    # exported QWidget inserted directly as a tab
```

Feel free to subclass, add new STOMP probes, or integrate other broker checks. Pull requests welcome!

---

## ❗ Disclaimer

This tool is intended for **authorized security testing and administrative auditing** only.
Unauthorized scanning may violate law or service terms; **use responsibly**.

---

## 📜 License

STOMPscan is released under the **GPL‑3.0** (same as Ningu).
See the project root for full license text.
