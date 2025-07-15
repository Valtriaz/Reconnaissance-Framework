from flask import Flask, render_template, request
import subprocess
import re

app = Flask(__name__)

# ----------------------------
# 🔍 NMAP Parser
# ----------------------------
def parse_nmap_output(output):
    services = []
    os_guess = ""
    hostname = ""
    ip = ""

    lines = output.splitlines()
    port_section = False

    for line in lines:
        if line.startswith("Nmap scan report for"):
            match = re.search(r"Nmap scan report for ([\w\.\-]+) \(([\d\.]+)\)", line)
            if match:
                hostname = match.group(1)
                ip = match.group(2)
            else:
                ip_match = re.search(r"Nmap scan report for ([\d\.]+)", line)
                if ip_match:
                    ip = ip_match.group(1)

        if line.startswith("PORT"):
            port_section = True
            continue

        if port_section:
            if line.strip() == "" or line.startswith("Service Info:"):
                port_section = False
                continue
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 3:
                services.append({
                    'port': parts[0],
                    'state': parts[1],
                    'service': parts[2],
                    'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                })

        if "Running:" in line:
            os_guess = line.split("Running:")[1].strip()

    return {
        'hostname': hostname,
        'ip': ip,
        'os': os_guess,
        'services': services
    }

# ----------------------------
# Nmap Route
# ----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    output = None
    data = None

    if request.method == "POST":
        ip = request.form.get("target_ip")
        if ip:
            try:
                cmd = ["nmap", "-T4", "-A", "-v", ip]
                result = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=300
                )
                output = result
                data = parse_nmap_output(result)
            except subprocess.CalledProcessError as e:
                output = f"Nmap error:\n{e.output}"
            except subprocess.TimeoutExpired:
                output = "Nmap scan timed out."
            except Exception as e:
                output = f"Unexpected error:\n{str(e)}"
        else:
            output = "No IP provided."

    return render_template("index.html", output=output, data=data)

# ----------------------------
# GOBUSTER DIR Route (filtered)
# ----------------------------
@app.route("/gobuster", methods=["GET", "POST"])
def gobuster():
    output = None
    results = []

    if request.method == "POST":
        target = request.form.get("target")
        wordlist = request.form.get("wordlist")

        if not target or not wordlist:
            output = "❌ Missing target or wordlist."
        else:
            try:
                cmd = [
    "gobuster", "dir",
    "-u", target,
    "-w", wordlist,
    "-s", "200,204,403,500",
    "--exclude-length", "154",
    "--no-error",
    "--status-codes-blacklist", ""
]


                print("Running:", " ".join(cmd))
                result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=300)

                for line in result.splitlines():
                    if line.startswith("/"):
                        parts = line.split()
                        path = parts[0]
                        status = parts[1].strip("()") if len(parts) > 1 else "?"
                        size = parts[-1] if "Size:" in line else "?"
                        results.append({'path': path, 'status': status, 'size': size})

                output = result

            except subprocess.CalledProcessError as e:
                output = f"Gobuster error:\n{e.output}"
            except subprocess.TimeoutExpired:
                output = "Gobuster timed out."
            except Exception as e:
                output = f"Unexpected error:\n{str(e)}"

    return render_template("gobuster.html", results=results, output=output)

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
