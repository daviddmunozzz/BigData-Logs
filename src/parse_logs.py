import re
import pandas as pd

def parse_logs():
    with open('./assets/SSH.log', 'r') as f:
        lines = f.readlines()

    logs = []

    for line in lines:
        match = re.match(
            r'(\w+)\s+(\d+)\s+([\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+(.*)', line)
        if match:
            month, day, time, host, pid, message = match.groups()

            ip_match = re.search(r'from ([\d\.]+)|\[(\d+\.\d+\.\d+\.\d+)\]', message)
            ip = ip_match.group(1) if ip_match and ip_match.group(1) else (ip_match.group(2) if ip_match else None)

            user_match = re.search(r'Invalid user (\S+)', message) or \
                        re.search(r'user=(\S+)', message) or \
                        re.search(r'for (\w+) from', message)
            user = user_match.group(1) if user_match else None

            port_match = re.search(r'port (\d+)', message)
            port = port_match.group(1) if port_match else None

            rhost_match = re.search(r'rhost=([^\s]+)', message)
            rhost = rhost_match.group(1) if rhost_match else None

            tty_match = re.search(r'tty=([^\s]+)', message)
            tty = tty_match.group(1) if tty_match else None

            logname_match = re.search(r'logname=([^\s]*)', message)
            logname = logname_match.group(1) if logname_match else None

            uid_match = re.search(r'uid=(\d+)', message)
            uid = uid_match.group(1) if uid_match else None

            euid_match = re.search(r'euid=(\d+)', message)
            euid = euid_match.group(1) if euid_match else None

            ruser_match = re.search(r'ruser=([^\s]*)', message)
            ruser = ruser_match.group(1) if ruser_match else None

            method_match = re.search(r'pam_(\w+)\(sshd:(\w+)\)', message)
            method = method_match.group(1) if method_match else None

            if "Invalid user" in message:
                event = "invalid_user"
            elif "Failed password" in message:
                event = "failed_password"
            elif "authentication failure" in message:
                event = "auth_failure"
            elif "reverse mapping" in message:
                event = "reverse_mapping_check"
            elif "Connection closed" in message:
                event = "connection_closed"
            elif "Received disconnect" in message:
                event = "disconnect"
            elif "Did not receive identification string" in message:
                event = "no_identification"
            elif "Too many authentication failures" in message:
                event = "too_many_failures"
            elif "ignoring max retries" in message:
                event = "ignoring_max_retries"
            elif "Failed none" in message:
                event = "failed_none"
            else:
                event = "other"

            proto_match = re.search(r'ssh(\d)', message)
            protocol_version = f"ssh{proto_match.group(1)}" if proto_match else None

            disconnect_reason = None
            if "Received disconnect" in message:
                disconnect_reason = "received_disconnect"
            elif "Connection closed" in message:
                disconnect_reason = "connection_closed"
            elif "Disconnected from" in message:
                disconnect_reason = "disconnected"
            elif "timeout" in message.lower():
                disconnect_reason = "timeout"

            logs.append({
                'month': month,
                'day': day,
                'time': time,
                'host': host,
                'pid': pid,
                'message': message,
                'ip': ip,
                'user': user,
                'port': port,
                'event': event,
                'rhost': rhost,
                'tty': tty,
                'logname': logname,
                'uid': uid,
                'euid': euid,
                'ruser': ruser,
                'method': method,
                'protocol_version': protocol_version,
                'disconnect_reason': disconnect_reason
            })

    df = pd.DataFrame(logs)

    print(df.head(10))

    df.to_csv('./assets/parsed_logs.csv', index=False)


if __name__ == "__main__":
    parse_logs()

