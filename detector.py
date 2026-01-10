from collections import Counter

FAILED_LOGIN_THRESHOLD = 5

def flag_suspicious_ips(ip_list):
    """
    Flags IPs that exceed the failed login threshold
    """
    ip_counts = Counter(ip_list)

    suspicious = {
        ip: count 
        for ip, count in ip_counts.items()
        if count >= FAILED_LOGIN_THRESHOLD
    }
    return suspicious