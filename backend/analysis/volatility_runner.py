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
    # These exist ONLY for this specific function call (Case ID)
    local_findings = [] 
    local_text_summary = []
    local_full_log = f"ANALYSIS LOG - CASE #{case_id}\n" + "="*50 + "\n"
    
    # Base score accumulator (will be adjusted by multipliers later)
    raw_risk_score = 0

    try:
        cur.execute("UPDATE cases SET status = 'processing' WHERE case_id = %s", (case_id,))
        conn.commit()

        # Define Plugins (Added pstree to Standard for Context Logic)
        plugins = [
            {'name': 'windows.info', 'desc': 'System Information'},
            {'name': 'windows.pslist', 'desc': 'Process Check'},
            {'name': 'windows.pstree', 'desc': 'Process Tree (Context)'}, 
            {'name': 'windows.netscan', 'desc': 'Network Check'},
            {'name': 'windows.malfind', 'desc': 'Injection Scan'},
            {'name': 'windows.ldrmodules', 'desc': 'Rootkit Check'}
        ]

        if analysis_type == 'quick':
            # Quick scan only runs essential plugins
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
            
            # Register process so it can be killed if user clicks Stop
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

            # --- PARSING & STATE BUILDING ---

            # A. Build Process Map (PID -> Name)
            if plugin['name'] == 'windows.pslist':
                for line in stdout.splitlines():
                    # Regex to capture PID, PPID and Name. Vol3 usually: PID PPID ... Name
                    # Adjusted regex to be flexible for variable whitespace
                    match = re.search(r'^\s*(\d+)\s+(\d+)\s+.*?\s([a-zA-Z0-9_\-]+\.exe)', line)
                    if match:
                        pid, ppid, name = match.group(1), match.group(2), match.group(3)
                        process_map[pid] = name
                        parent_map[pid] = ppid

            # B. Build Parent Map (Better source)
            if plugin['name'] == 'windows.pstree':
                for line in stdout.splitlines():
                    # Parse tree structure to reinforce parent_map if pslist missed it
                    # Pstree output often uses indentation or special chars
                    match = re.search(r'^\s*(\d+)\s+(\d+)\s+.*?\s([a-zA-Z0-9_\-]+\.exe)', line)
                    if match:
                        pid, ppid, name = match.group(1), match.group(2), match.group(3)
                        process_map[pid] = name
                        parent_map[pid] = ppid

            # C. Count Network Connections (Frequency Logic)
            if plugin['name'] == 'windows.netscan':
                # Common Rat/C2 Ports
                bad_ports = ['4444', '8808', '31337', '1337', '6667', '8080']
                
                for line in stdout.splitlines():
                    if "ESTABLISHED" in line or "LISTENING" in line:
                        # Find PID at end of line
                        pid_match = re.search(r'\s(\d+)$', line)
                        if pid_match:
                            pid = pid_match.group(1)
                            network_counts[pid] = network_counts.get(pid, 0) + 1
                            
                        # Also check for specific bad ports here for immediate flagging
                        for port in bad_ports:
                            if f":{port}" in line:
                                raw_risk_score += 30
                                pid = pid_match.group(1) if pid_match else "?"
                                local_findings.append({
                                    "process": "Network Socket", "pid": pid, 
                                    "issue": f"Suspicious C2 Port :{port}", 
                                    "severity": "HIGH", "action": "BLOCK & KILL"
                                })
                                local_text_summary.append(f"HIGH: C2 Port {port} active")

            # D. Immediate Threat Detection (Malfind/LdrModules)
            if plugin['name'] == 'windows.malfind':
                for line in stdout.splitlines():
                    if "PAGE_EXECUTE_READWRITE" in line:
                        raw_risk_score += 50
                        pid_match = re.search(r'^\s*(\d+)', line)
                        name_match = re.search(r'\s([a-zA-Z0-9_]+\.exe)', line)
                        pid = pid_match.group(1) if pid_match else "?"
                        proc = name_match.group(1) if name_match else "Unknown"
                        
                        local_findings.append({
                            "process": proc, "pid": pid, 
                            "issue": "Memory Injection (RWX Found)", 
                            "severity": "CRITICAL", "action": "KILL PROCESS"
                        })
                        local_text_summary.append(f"CRITICAL: Injection in {proc} ({pid})")

            if plugin['name'] == 'windows.ldrmodules':
                for line in stdout.splitlines():
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
                            # Limit findings to avoid spamming
                            if len([x for x in local_findings if x['issue'] == "Hidden Module (Unlinked from PEB)"]) > 5:
                                break

        # --- PHASE 2: ADVANCED CONTEXTUAL ANALYSIS (The Logic Update) ---
        
        # 1. PARENT-CHILD CONTEXT LOGIC (Suggestion #1)
        # Goal: Whitelist "Explorer -> Powershell" but flag "Word -> Powershell"
        suspicious_tools = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']
        office_parents = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'acrord32.exe']
        
        for pid, name in process_map.items():
            if name.lower() in suspicious_tools:
                ppid = parent_map.get(pid)
                parent_name = process_map.get(ppid, "Unknown").lower()
                
                if parent_name in office_parents:
                    # MALICIOUS CONTEXT: Office spawned Shell
                    raw_risk_score += 50
                    local_findings.append({
                        "process": name, "pid": pid, 
                        "issue": f"Malicious Context: Spawned by {parent_name}",
                        "severity": "CRITICAL", "action": "ISOLATE HOST"
                    })
                    local_text_summary.append(f"CRITICAL: {name} spawned by {parent_name}")
                
                elif parent_name == "explorer.exe":
                    # BENIGN CONTEXT: User launched it
                    # We do NOT add score (Whitelisted)
                    pass 
                
                else:
                    # NEUTRAL/SUSPICIOUS: Standard check
                    raw_risk_score += 15
                    local_findings.append({
                        "process": name, "pid": pid, 
                        "issue": "Suspicious Admin Tool",
                        "severity": "MEDIUM", "action": "INVESTIGATE"
                    })
                    local_text_summary.append(f"WARN: Admin tool {name} detected")

        # 2. FREQUENCY ANALYSIS (Suggestion #2)
        # Goal: Flag processes with abnormal network behavior
        for pid, count in network_counts.items():
            proc_name = process_map.get(pid, "Unknown")
            
            # Threshold: More than 10 connections is suspicious for non-browsers
            is_browser = proc_name.lower() in ['chrome.exe', 'firefox.exe', 'msedge.exe']
            
            if count > 10 and not is_browser:
                raw_risk_score += 30
                local_findings.append({
                    "process": proc_name, "pid": pid, 
                    "issue": f"High Frequency Network Activity ({count} conns)",
                    "severity": "HIGH", "action": "CHECK TRAFFIC"
                })
                local_text_summary.append(f"HIGH: {proc_name} has {count} connections")

        # 3. RISK MULTIPLIERS (Suggestion #3)
        # Goal: Escalate score if a suspicious tool is also talking to the network
        for finding in local_findings:
            pid = finding['pid']
            # If a flagged process also has network connections...
            if pid in network_counts and network_counts[pid] > 0:
                # We don't change the finding text significantly, but we boost the GLOBAL score
                # Multiplier Logic: Add 20 extra points for "Active Threat" capability
                raw_risk_score += 20
                if "NETWORK ACTIVE" not in finding['issue']:
                    finding['issue'] += " + [NETWORK ACTIVE]"
                    finding['severity'] = "CRITICAL" # Elevate severity
                    local_text_summary.append(f"ESCALATION: {finding['process']} is network active! Score boosted.")

        # --- DATA ASSEMBLY ---
        unique_findings = []
        seen = set()
        for f in local_findings:
            key = f"{f['process']}_{f['pid']}_{f['issue']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Force Logic: If we found threats (even just one), Score MUST reflect it
        # This prevents "Clean Verdict" when threats are listed in the table
        if unique_findings and raw_risk_score < 35:
            raw_risk_score = 35 # Force at least SUSPICIOUS

        # Final Score Cap
        final_score = min(raw_risk_score, 100)

        # Verdict Determination
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

        # FINAL OUTPUT FORMAT (Strict Structure)
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
        # Cleanup scan tracking
        if case_id in active_scans_dict: del active_scans_dict[case_id]
        conn.commit()
        cur.close()
        conn.close()