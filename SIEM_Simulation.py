# Simple SIEM Simulation in Python
# This script simulates a basic Security Information and Event Management (SIEM) system
# that detects brute force login attempts and potential Denial of Service (DoS) attacks.
# It uses simulated data for firewall traffic and Windows Security logs.

# Simulated firewall traffic (IP: number of connection attempts)
firewall_traffic = {
    "192.168.1.100": 5,
    "185.23.56.78": 2,
    "45.67.89.10": 20,  # Potential DoS attacker
    "203.98.123.45": 1,
    "102.89.34.12": 15, # Potential DoS attacker
}

# Simulated Windows Security log events
windows_logs = [
    {"event_id": 4624, "description": "Successful login", "account": "user1"},
    {"event_id": 4625, "description": "Failed login", "account": "admin"},
    {"event_id": 4625, "description": "Failed login", "account": "admin"},
    {"event_id": 4625, "description": "Failed login", "account": "admin"},
    {"event_id": 4624, "description": "Successful login", "account": "user2"},
    {"event_id": 4625, "description": "Failed login", "account": "guest"},
    {"event_id": 4625, "description": "Failed login", "account": "guest"},
]

# --- Simple SIEM logic ---

# Initialize counter to track failed login attempts per account
counter = {}

"""Why did I initialize counter = {} and not counter = 0?
The reason is:
We are tracking failed login attempts per account (usernames).
If you use counter = 0, you'd only have one counter for everything, 
but we need a separate count for each user account to detect if specific accounts are under attack.
So, we use a dictionary to map each account to its count of failed login attempts."""

print("=== SIEM Collection: Windows Event Logs ===\n")
for log in windows_logs:
    event_id = log["event_id"] 
    account = log["account"]
    description = log["description"]
    print(f"Event ID: {event_id} | Account: {account} | Description: {description}")

    # Count failed login attempts
    if event_id == 4625:
        if account in counter:
            counter[account] += 1
        else:
            counter[account] = 1

print("\n=== SIEM Collection: Firewall Traffic ===\n")
for ip, attempts in firewall_traffic.items():
    print(f"IP: {ip} | Connection Attempts: {attempts}")

# --- Alerting Logic ---

DOS_THRESHOLD = 10  # Define threshold for too many requests
dos_attackers = []

for ip, attempts in firewall_traffic.items():
    if attempts > DOS_THRESHOLD:
        dos_attackers.append(ip)

# --- Output Alerts ---

print("\n=== SIEM Alert Report ===\n")

# Report brute force attempts
for account, count in counter.items():
    if count >= 3:
        print(f"[ALERT] Multiple failed login attempts detected for account '{account}' ({count} times)")

# Report DoS attack attempts
for ip in dos_attackers:
    print(f"[ALERT] Potential DoS attack detected from IP address {ip} ({firewall_traffic[ip]} connection attempts)")

print("\n=== End of Report ===")
