import os
import subprocess
import json
import re
import psycopg2

# --- CONFIGURATION ---
PYTHON_EXEC = "python"
# Adjust this path if your volatility3 folder is elsewhere
VOL_PATH = os.path.join(os.getcwd(), "volatility3", "vol.py") 
DB_HOST = "localhost"
DB_NAME = "sentra_db"
DB_USER = "postgres"
DB_PASS = "admin"

def get_db_connection():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        return conn
    except Exception as e:
        print(f"❌ [Runner] Database Error: {e}")
        return None

def run_volatility_analysis(case_id, file_path, analysis_type, active_scans_dict):
    """
    Executes Volatility 3 plugins in a secure, isolated thread.
    Generates a GUARANTEED JSON block for the ATS Table with Context-Aware Scoring.
    """
    print(f"⚙️ [Case #{case_id}] Starting Context-Aware Analysis...")
    
    conn = get_db_connection()
    if not conn: return
    cur = conn.cursor()

    # --- STATE TRACKING (For Correlation Logic) ---
    process_map = {}      # PID -> Process Name
    parent_map = {}       # PID -> Parent PID (PPID)
    network_counts = {}   # PID -> Number of Connections
    
    # --- FINDINGS ACCUMULATOR ---
    local_findings = [] 
    local_text_summary = []
    local_full_log = f"ANALYSIS LOG - CASE #{case_id}\n" + "="*50 + "\n"
    
    # Base score accumulator
    raw_risk_score = 0

    try:
        cur.execute("UPDATE cases SET status = 'processing' WHERE case_id = %s", (case_id,))
        conn.commit()

        # Define Plugins
        plugins = [
            {'name': 'windows.info', 'desc': 'System Information'},
            {'name': 'windows.pslist', 'desc': 'Process Check'},
            {'name': 'windows.pstree', 'desc': 'Process Tree (Context)'}, 
            {'name': 'windows.netscan', 'desc': 'Network Check'},
            {'name': 'windows.malfind', 'desc': 'Injection Scan'},
            {'name': 'windows.ldrmodules', 'desc': 'Rootkit Check'}
        ]

        if analysis_type == 'quick':
            plugins = [p for p in plugins if p['name'] in ['windows.info', 'windows.pslist', 'windows.malfind']]

        # --- PHASE 1: EXECUTION & INGESTION ---
        for plugin in plugins:
            if active_scans_dict.get(case_id, {}).get('stopped'): break

            print(f"--> [Case #{case_id}] Running {plugin['name']}...")
            
            command = [PYTHON_EXEC, VOL_PATH, '-f', file_path, plugin['name']]
            
            # UTF-8 Encoding Fix
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                text=True, encoding='utf-8', errors='replace', env=env
            )
            
            if case_id in active_scans_dict: active_scans_dict[case_id]['process'] = process

            try:
                # 20 Minute Timeout per plugin
                stdout, stderr = process.communicate(timeout=1200)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = "", "Timeout"

            if process.returncode != 0:
                local_full_log += f"\n\n[!] {plugin['name']} Failed:\n{stderr}"
                continue

            local_full_log += f"\n\n=== {plugin['desc']} ===\n{stdout}"

            # --- ROBUST PARSING LOGIC (FIXED) ---

            # A. Build Process Map (Using Split instead of Regex)
            # Vol3 pslist columns: PID, PPID, ImageFileName, ...
            if plugin['name'] == 'windows.pslist':
                for line in stdout.splitlines():
                    parts = line.split()
                    # We need at least PID, PPID, Name (3 items)
                    if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                        pid = parts[0]
                        ppid = parts[1]
                        name = parts[2]
                        process_map[pid] = name
                        parent_map[pid] = ppid

            # B. Build Parent Map (Reinforcement)
            if plugin['name'] == 'windows.pstree':
                for line in stdout.splitlines():
                    # Remove tree characters for cleaner parsing if needed, but split usually handles it
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                        pid = parts[0]
                        ppid = parts[1]
                        name = parts[2]
                        process_map[pid] = name
                        parent_map[pid] = ppid

            # C. Count Network Connections (Anchor Logic)
            if plugin['name'] == 'windows.netscan':
                # Vol3 netscan is tricky. We look for "LISTENING" or "ESTABLISHED" and grab the NEXT integer.
                for line in stdout.splitlines():
                    if "ESTABLISHED" in line or "LISTENING" in line:
                        parts = line.split()
                        try:
                            # Find the index of the state
                            if "ESTABLISHED" in parts:
                                state_idx = parts.index("ESTABLISHED")
                            else:
                                state_idx = parts.index("LISTENING")
                            
                            # PID is typically the item RIGHT AFTER the state
                            if len(parts) > state_idx + 1:
                                pid = parts[state_idx + 1]
                                if pid.isdigit():
                                    network_counts[pid] = network_counts.get(pid, 0) + 1
                        except ValueError:
                            continue

                        # Check Bad Ports
                        bad_ports = ['4444', '8808', '31337', '1337', '6667', '8080']
                        for port in bad_ports:
                            if f":{port}" in line:
                                raw_risk_score += 30
                                found_pid = pid if 'pid' in locals() and pid.isdigit() else "?"
                                local_findings.append({
                                    "process": "Network Socket", "pid": found_pid, 
                                    "issue": f"Suspicious C2 Port :{port}", 
                                    "severity": "HIGH", "action": "BLOCK & KILL"
                                })
                                local_text_summary.append(f"HIGH: C2 Port {port} active")

            # D. Malfind (Critical Injection)
            if plugin['name'] == 'windows.malfind':
                for line in stdout.splitlines():
                    if "PAGE_EXECUTE_READWRITE" in line:
                        raw_risk_score += 50
                        # Regex to capture PID (Start of line or after 'Pid:')
                        pid_match = re.search(r'Pid:\s*(\d+)', line)
                        if not pid_match: pid_match = re.search(r'^\s*(\d+)', line)
                        
                        pid = pid_match.group(1) if pid_match else "?"
                        
                        # Try to find Name (ends in .exe)
                        name_match = re.search(r'\s([a-zA-Z0-9_\-\.]+\.exe)', line)
                        proc = name_match.group(1) if name_match else "Unknown"
                        
                        local_findings.append({
                            "process": proc, "pid": pid, 
                            "issue": "Memory Injection (RWX Found)", 
                            "severity": "CRITICAL", "action": "KILL PROCESS"
                        })
                        local_text_summary.append(f"CRITICAL: Injection in {proc} ({pid})")

            # E. LdrModules (Rootkits)
            if plugin['name'] == 'windows.ldrmodules':
                for line in stdout.splitlines():
                    # False False True pattern
                    if "False" in line and "True" in line:
                        parts = line.split()
                        if len(parts) > 2 and parts[0].isdigit():
                            raw_risk_score += 40
                            local_findings.append({
                                "process": parts[1], "pid": parts[0], 
                                "issue": "Hidden Module (Unlinked from PEB)",
                                "severity": "HIGH", "action": "DEEP SCAN"
                            })
                            local_text_summary.append(f"WARN: Rootkit behavior in {parts[1]}")
                            # Limit findings to avoid spamming table
                            if len([x for x in local_findings if x['issue'] == "Hidden Module (Unlinked from PEB)"]) > 5:
                                break

        # --- PHASE 2: ADVANCED CONTEXTUAL ANALYSIS (Logic Update) ---
        
        # DEBUG PRINTS (Check your terminal!)
        print(f"DEBUG: Process Map Size: {len(process_map)}")
        print(f"DEBUG: Network Map Size: {len(network_counts)}")

        # 1. PARENT-CHILD CONTEXT LOGIC
        suspicious_tools = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']
        office_parents = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe']
        
        for pid, name in process_map.items():
            if name.lower() in suspicious_tools:
                ppid = parent_map.get(pid)
                parent_name = process_map.get(ppid, "Unknown").lower()
                
                if parent_name in office_parents:
                    raw_risk_score += 50
                    local_findings.append({
                        "process": name, "pid": pid, 
                        "issue": f"Malicious Context: Spawned by {parent_name}",
                        "severity": "CRITICAL", "action": "ISOLATE HOST"
                    })
                    local_text_summary.append(f"CRITICAL: {name} spawned by {parent_name}")
                
                elif parent_name == "explorer.exe":
                    pass # Whitelisted
                
                else:
                    raw_risk_score += 15
                    local_findings.append({
                        "process": name, "pid": pid, 
                        "issue": "Suspicious Admin Tool",
                        "severity": "MEDIUM", "action": "INVESTIGATE"
                    })
                    local_text_summary.append(f"WARN: Admin tool {name} detected")

        # 2. FREQUENCY ANALYSIS
        for pid, count in network_counts.items():
            proc_name = process_map.get(pid, "Unknown")
            is_browser = proc_name.lower() in ['chrome.exe', 'firefox.exe', 'msedge.exe']
            
            if count > 10 and not is_browser:
                raw_risk_score += 30
                local_findings.append({
                    "process": proc_name, "pid": pid, 
                    "issue": f"High Freq Network Activity ({count} conns)",
                    "severity": "HIGH", "action": "CHECK TRAFFIC"
                })
                local_text_summary.append(f"HIGH: {proc_name} has {count} connections")

        # 3. RISK MULTIPLIERS (Tag Generator)
        for finding in local_findings:
            pid = finding['pid']
            # Correlation: Does this PID exist in the Network Map?
            if pid in network_counts and network_counts[pid] > 0:
                raw_risk_score += 20
                if "NETWORK ACTIVE" not in finding['issue']:
                    finding['issue'] += " + [NETWORK ACTIVE]" # This tag should now appear
                    finding['severity'] = "CRITICAL"
                    local_text_summary.append(f"ESCALATION: {finding['process']} is network active! Score boosted.")

        # --- DATA ASSEMBLY ---
        unique_findings = []
        seen = set()
        for f in local_findings:
            key = f"{f['process']}_{f['pid']}_{f['issue']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Force Logic: If threats exist, Score MUST reflect it
        if unique_findings and raw_risk_score < 35:
            raw_risk_score = 35 

        # Final Score Cap
        final_score = min(raw_risk_score, 100)

        # Verdict
        verdict = "CLEAN"
        if final_score >= 75: verdict = "CRITICAL INFECTION"
        elif final_score >= 35: verdict = "SUSPICIOUS ACTIVITY"
        elif unique_findings: verdict = "POTENTIAL THREATS"

        ats_json = json.dumps(unique_findings)
        
        summary = f"RISK VERDICT: {verdict}\nRISK SCORE: {final_score}/100\n"
        if local_text_summary:
            summary += "THREAT INTELLIGENCE:\n" + "\n".join(list(set(local_text_summary)))
        else:
            summary += "No behavioral anomalies detected."

        # FINAL OUTPUT
        final_report = f"<<<JSON_START>>>{ats_json}<<<JSON_END>>>\n\n" + \
                       f"=== EXECUTIVE SUMMARY ===\n{summary}\n\n" + \
                       f"{local_full_log}"

        cur.execute(
            "UPDATE cases SET status = 'completed', analysis_result = %s, risk_score = %s WHERE case_id = %s",
            (final_report, final_score, case_id)
        )
        print(f"✅ [Case #{case_id}] Smart Analysis Complete. Score: {final_score}, Findings: {len(unique_findings)}")

    except Exception as e:
        print(f"❌ [Case #{case_id}] Failed: {e}")
        cur.execute("UPDATE cases SET status = 'failed', analysis_result = %s WHERE case_id = %s", (str(e), case_id))

    finally:
        if case_id in active_scans_dict: del active_scans_dict[case_id]
        conn.commit()
        cur.close()
        conn.close()