import re
FAILED_LOGIN_REGEX = re.compile(
    r"failed login.*from (\d{1,3}(?:\.\d{1,3}){3})"
    
)

def extract_failed_login_ips(log_lines):
    """
    Extract IP addresses from failed login log entries."""

    ips =[]

    for line in log_lines:
        match = FAILED_LOGIN_REGEX.search(line)
        if match:
            ips.append(match.group(1))

            return ips