import sys
import os
import re

def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        return os.path.join(os.path.dirname(__file__), "..", relative_path)

def parse_log_line(line):
    match = re.search(
        r'(\d+\.\d+\.\d+\.\d+)',
        line,
    )
    if match:
        src_ip = match.group(1)
        return f"Source IP: {src_ip}", src_ip
    else:
        return line, None

def parse_whois_output(output, selected_fields=None):
    if not selected_fields:
        selected_fields = ["inetnum", "netname", "country", "org", "admin-c", "tech-c", "status", "mnt-by", "created", "last-modified"]
    result = {}
    key_fields = {
        "inetnum": "IP Range", "netname": "Network Name", "country": "Country", "org": "Organization",
        "admin-c": "Admin Contact", "tech-c": "Tech Contact", "status": "Status", "mnt-by": "Maintained By",
        "created": "Created", "last-modified": "Last Modified"
    }
    lines = output.split('\n')
    for line in lines:
        for key, display_name in key_fields.items():
            if key in selected_fields and line.lower().startswith(key + ':'):
                value = line.split(':', 1)[1].strip()
                result[display_name] = value
                break
    formatted = "\n".join([f"{k}: {v}" for k, v in result.items()])
    return formatted if formatted else "No relevant data found"