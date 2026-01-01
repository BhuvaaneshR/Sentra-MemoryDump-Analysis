import os
import subprocess
import json
import re
import psycopg2

# --- CONFIGURATION ---
PYTHON_EXEC = "python"
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
    print(f"⚙️ [Case #{case_id}] Starting Analysis...")
    
    conn = get_db_connection()
    if not conn: return
    cur = conn.cursor()

    # --- SCOPED VARIABLES ---
    local_findings = [] 
    local_text_summary = []
    local_full_log = f"ANALYSIS LOG - CASE #{case_id}\n" + "="*50 + "\n"
    local_risk_score = 0

    try:
        cur.execute("UPDATE cases SET status = 'processing' WHERE case_id = %s", (case_id,))
        conn.commit()

        # Define Plugins
        plugins = [
            {'name': 'windows.info', 'desc': 'System Information'},
            {'name': 'windows.pslist', 'desc': 'Process Check'},
            {'name': 'windows.netscan', 'desc': 'Network Check'},
            {'name': 'windows.malfind', 'desc': 'Injection Scan'},
            {'name': 'windows.ldrmodules', 'desc': 'Rootkit Check'}
        ]

        if analysis_type == 'quick':
            plugins = plugins[:2]

        for plugin in plugins:
            if active_scans_dict.get(case_id, {}).get('stopped'): break

            print(f"--> [Case #{case_id}] Running {plugin['name']}...")
            
            command = [PYTHON_EXEC, VOL_PATH, '-f', file_path, plugin['name']]
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                text=True, encoding='utf-8', errors='replace', env=env
            )
            
            if case_id in active_scans_dict: active_scans_dict[case_id]['process'] = process

            try:
                stdout, stderr = process.communicate(timeout=1200)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = "", "Timeout"

            if process.returncode != 0:
                local_full_log += f"\n\n[!] {plugin['name']} Failed:\n{stderr}"
                continue

            local_full_log += f"\n\n=== {plugin['desc']} ===\n{stdout}"

            # ==========================================
            #  ROBUST THREAT PARSING (Fixed Logic)
            # ==========================================

            # 1. MALFIND (Code Injection) - CRITICAL
            if plugin['name'] == 'windows.malfind':
                # Volatility 3 'malfind' output is often tabular: "PID  Process  ..."
                # We scan line by line for the RWX indicator
                for line in stdout.splitlines():
                    if "PAGE_EXECUTE_READWRITE" in line:
                        # Attempt to extract PID (digits at start) and Name (string ending in .exe)
                        pid_match = re.search(r'^\s*(\d+)', line)
                        name_match = re.search(r'\s([a-zA-Z0-9_]+\.exe)', line)
                        
                        pid = pid_match.group(1) if pid_match else "?"
                        proc = name_match.group(1) if name_match else "Unknown Process"

                        local_findings.append({
                            "process": proc, "pid": pid, 
                            "issue": "Memory Injection (RWX Found)", 
                            "severity": "CRITICAL", "action": "KILL PROCESS"
                        })
                        local_risk_score += 40
                        local_text_summary.append(f"CRITICAL: Injection in {proc} ({pid})")

            # 2. NETSCAN (C2 Detection) - HIGH
            if plugin['name'] == 'windows.netscan':
                bad_ports = ['4444', '8808', '31337', '1337', '6667', '8080']
                for line in stdout.splitlines():
                    for port in bad_ports:
                        if f":{port}" in line and ("ESTABLISHED" in line or "LISTENING" in line):
                            # Extract PID (last number in line usually)
                            pid_match = re.search(r'\s(\d+)$', line)
                            pid = pid_match.group(1) if pid_match else "?"
                            
                            local_findings.append({
                                "process": "Network Socket", "pid": pid, 
                                "issue": f"Suspicious C2 Port :{port}", 
                                "severity": "HIGH", "action": "BLOCK & KILL"
                            })
                            local_risk_score += 25
                            local_text_summary.append(f"HIGH: C2 Port {port} active")

            # 3. PSLIST (Rogue Admins) - MEDIUM
            if plugin['name'] == 'windows.pslist':
                bad_tools = ['mimikatz.exe', 'psexec.exe', 'powershell.exe', 'cmd.exe', 'vssadmin.exe']
                for line in stdout.splitlines():
                    for tool in bad_tools:
                        if tool.lower() in line.lower():
                            # Vol 3 pslist: PID is usually column 1
                            pid_match = re.search(r'^\s*(\d+)', line)
                            pid = pid_match.group(1) if pid_match else "?"

                            local_findings.append({
                                "process": tool, "pid": pid, 
                                "issue": "Suspicious Admin Tool", 
                                "severity": "MEDIUM", "action": "INVESTIGATE"
                            })
                            local_risk_score += 15
                            local_text_summary.append(f"WARN: Admin tool {tool} detected")

            # 4. LDRMODULES (Rootkits) - HIGH
            if plugin['name'] == 'windows.ldrmodules':
                for line in stdout.splitlines():
                    if "False" in line and "True" in line:
                        # Extract PID (col 1) and Name (col 2)
                        parts = line.split()
                        if len(parts) > 2 and parts[0].isdigit():
                            local_findings.append({
                                "process": parts[1], "pid": parts[0],
                                "issue": "Hidden Module (Unlinked from PEB)",
                                "severity": "HIGH", "action": "DEEP SCAN"
                            })
                            local_risk_score += 20
                            local_text_summary.append(f"WARN: Rootkit behavior in {parts[1]}")
                            # Limit findings to avoid spamming the table
                            if len([x for x in local_findings if x['issue'] == "Hidden Module (Unlinked from PEB)"]) > 5:
                                break

        # --- DATA ASSEMBLY ---
        
        # Deduplicate Findings
        unique_findings = []
        seen = set()
        for f in local_findings:
            key = f"{f['process']}_{f['pid']}_{f['issue']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Force Logic: If we found threats, Score MUST reflect it
        if unique_findings and local_risk_score < 30:
            local_risk_score = 35 # Force at least SUSPICIOUS

        local_risk_score = min(local_risk_score, 100)

        # Determine Verdict
        verdict = "CLEAN"
        if local_risk_score >= 70: verdict = "CRITICAL INFECTION"
        elif local_risk_score >= 30: verdict = "SUSPICIOUS ACTIVITY"
        elif unique_findings: verdict = "POTENTIAL THREATS" # Fallback if score is low but threats exist

        # Generate JSON Block
        ats_json = json.dumps(unique_findings)
        
        # Generate Text Summary
        summary_text = f"RISK VERDICT: {verdict}\nRISK SCORE: {local_risk_score}/100\n"
        if local_text_summary:
            summary_text += "THREATS DETECTED:\n" + "\n".join(list(set(local_text_summary)))
        else:
            summary_text += "System appears clean based on standard heuristics."

        # FINAL OUTPUT FORMAT
        final_report = f"<<<JSON_START>>>{ats_json}<<<JSON_END>>>\n\n" + \
                       f"=== EXECUTIVE SUMMARY ===\n{summary_text}\n\n" + \
                       f"{local_full_log}"

        cur.execute(
            "UPDATE cases SET status = 'completed', analysis_result = %s, risk_score = %s WHERE case_id = %s",
            (final_report, local_risk_score, case_id)
        )
        print(f"✅ [Case #{case_id}] Saved. Score: {local_risk_score}, Findings: {len(unique_findings)}")

    except Exception as e:
        print(f"❌ [Case #{case_id}] Failed: {e}")
        cur.execute("UPDATE cases SET status = 'failed', analysis_result = %s WHERE case_id = %s", (str(e), case_id))

    finally:
        if case_id in active_scans_dict: del active_scans_dict[case_id]
        conn.commit()
        cur.close()
        conn.close()