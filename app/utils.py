import re
import pandas as pd

# Define the log pattern using regex
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) .*sshd\[\d+\]: (?P<status>Failed|Accepted) password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
)

def parse_log_file(filepath):
    """
    Parses an auth.log file and extracts features for analysis.
    Returns a pandas DataFrame.
    """
    records = []

    with open(filepath, 'r') as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                data = match.groupdict()
                records.append(data)

    df = pd.DataFrame(records)

    if not df.empty:
        # Label: 1 = Failed login (potential threat), 0 = Accepted login
        df['label'] = df['status'].apply(lambda x: 1 if x == 'Failed' else 0)
    else:
        print("⚠️ No log entries matched the expected pattern.")

    return df
