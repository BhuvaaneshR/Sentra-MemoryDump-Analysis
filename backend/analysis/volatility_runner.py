import os
import subprocess
import json
import csv
import io
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
    Executes Volatility 3 in CSV Mode (-r csv).
    Uses csv.DictReader for 100% accurate parsing of threats.
    """
    print(f"⚙️ [Case #{case_id}] Starting CSV-Based Context Analysis...")
    
    conn = get_db_connection()
    if not conn: return
    cur = conn.cursor()

    # --- STATE TRACKING ---
    process_map = {}      # PID -> Process Name
    parent_map = {}       # PID -> Parent PID (PPID)
    network_counts = {}   # PID -> Number of Connections
    
    # --- FINDINGS ACCUMULATOR ---
    local_findings = [] 
    local_text_summary = []
    # Initialize Log with clean text header
    local_full_log = f"ANALYSIS LOG (CSV FORMAT) - CASE #{case_id}\n" + "="*50 + "\n"
    
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

            print(f"--> [Case #{case_id}] Running {plugin['name']} (CSV Mode)...")
            
            # CRITICAL UPDATE: "-r", "csv" forces structured output matching the video
            command = [PYTHON_EXEC, VOL_PATH, '-f', file_path, '-r', 'csv', plugin['name']]
            
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

            # Append Raw CSV to Log (This will look clean in the report)
            local_full_log += f"\n\n=== {plugin['desc']} (CSV) ===\n{stdout}"

            # --- ROBUST CSV PARSING LOGIC ---
            # We use io.StringIO to treat the string output like a file for the CSV reader
            csv_file = io.StringIO(stdout)
            
            # Volatility CSVs output the headers in the first line. 
            # DictReader automatically uses them as keys.
            try:
                reader = csv.DictReader(csv_file)
                
                # A. PsList (Process Map)
                if plugin['name'] == 'windows.pslist':
                    for row in reader:
                        try:
                            # 'PID', 'PPID', 'ImageFileName' are standard CSV headers in Vol3
                            pid = row.get('PID', '?')
                            ppid = row.get('PPID', '?')
                            name = row.get('ImageFileName', 'Unknown')
                            
                            process_map[pid] = name
                            parent_map[pid] = ppid
                        except: pass

                # B. PsTree (Parent Map Backup)
                elif plugin['name'] == 'windows.pstree':
                    for row in reader:
                        try:
                            pid = row.get('PID', '?')
                            ppid = row.get('PPID', '?')
                            name = row.get('ImageFileName', 'Unknown')
                            process_map[pid] = name
                            parent_map[pid] = ppid
                        except: pass

                # C. Netscan (Network Map)
                elif plugin['name'] == 'windows.netscan':
                    bad_ports = ['4444', '8808', '31337', '1337', '6667', '8080']
                    
                    for row in reader:
                        try:
                            state = row.get('State', '')
                            pid = row.get('PID', '?')
                            local_port = row.get('LocalPort', '')
                            foreign_port = row.get('ForeignPort', '')

                            if state in ['ESTABLISHED', 'LISTENING']:
                                # Populate Network Map
                                if pid and pid.isdigit():
                                    network_counts[pid] = network_counts.get(pid, 0) + 1

                                # Immediate Threat Check
                                for port in bad_ports:
                                    # Ensure we match ports correctly (string comparison)
                                    if str(port) == str(local_port) or str(port) == str(foreign_port):
                                        raw_risk_score += 30
                                        local_findings.append({
                                            "process": "Network Socket", "pid": pid, 
                                            "issue": f"Suspicious C2 Port :{port}", 
                                            "severity": "HIGH", "action": "BLOCK & KILL"
                                        })
                                        local_text_summary.append(f"HIGH: C2 Port {port} active")
                        except: pass

                # D. Malfind (Critical Injection) - NOW 100% ACCURATE
                elif plugin['name'] == 'windows.malfind':
                    for row in reader:
                        try:
                            protection = row.get('Protection', '')
                            # CSV makes this easy: we just check the 'Protection' column
                            if "PAGE_EXECUTE_READWRITE" in protection:
                                pid = row.get('PID', '?')
                                proc = row.get('Process', 'Unknown')
                                
                                raw_risk_score += 50
                                local_findings.append({
                                    "process": proc, "pid": pid, 
                                    "issue": "Memory Injection (RWX Found)", 
                                    "severity": "CRITICAL", "action": "KILL PROCESS"
                                })
                                local_text_summary.append(f"CRITICAL: Injection in {proc} ({pid})")
                        except: pass

                # E. LdrModules (Rootkits)
                elif plugin['name'] == 'windows.ldrmodules':
                    for row in reader:
                        try:
                            # CSV Reader reads booleans as strings 'True'/'False'
                            in_load = row.get('InLoad', 'True')
                            in_init = row.get('InInit', 'True')
                            in_mem = row.get('InMem', 'False') 
                            
                            # The Rootkit Pattern: Not in Load Order, Not in Init Order, But IS in Memory
                            if in_load == 'False' and in_init == 'False' and in_mem == 'True':
                                pid = row.get('Pid', '?')
                                proc = row.get('Process', 'Unknown')
                                
                                raw_risk_score += 40
                                local_findings.append({
                                    "process": proc, "pid": pid, 
                                    "issue": "Hidden Module (Unlinked from PEB)",
                                    "severity": "HIGH", "action": "DEEP SCAN"
                                })
                                local_text_summary.append(f"WARN: Rootkit behavior in {proc}")
                                
                                # Anti-Spam
                                if len([x for x in local_findings if "Hidden Module" in x['issue']]) > 5: break
                        except: pass

            except Exception as e:
                print(f"Error parsing CSV for {plugin['name']}: {e}")
                continue

        # --- PHASE 2: ADVANCED CONTEXTUAL ANALYSIS (Logic Update) ---
        
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
                    pass 
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
            if pid in network_counts and network_counts[pid] > 0:
                raw_risk_score += 20
                if "NETWORK ACTIVE" not in finding['issue']:
                    finding['issue'] += " + [NETWORK ACTIVE]"
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

        if unique_findings and raw_risk_score < 35: raw_risk_score = 35 
        final_score = min(raw_risk_score, 100)

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
        print(f"✅ [Case #{case_id}] CSV Analysis Complete. Score: {final_score}")

    except Exception as e:
        print(f"❌ [Case #{case_id}] Failed: {e}")
        cur.execute("UPDATE cases SET status = 'failed', analysis_result = %s WHERE case_id = %s", (str(e), case_id))

    finally:
        if case_id in active_scans_dict: del active_scans_dict[case_id]
        conn.commit()
        cur.close()
        conn.close()