import csv
import json
import re

# Define regex patterns for PII
PHONE_REGEX = re.compile(r"^\d{10}$")
AADHAR_REGEX = re.compile(r"^\d{12}$")
PASSPORT_REGEX = re.compile(r"^[A-PR-WY][0-9]{7}$")  # P1234567 format
UPI_REGEX = re.compile(r"^[\w.\-]{2,256}@[a-zA-Z]{2,32}$")
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")  # Simple validation
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Masking helper functions
def mask_phone(phone):
    return phone[:2] + "XXXXXX" + phone[-2:]

def mask_aadhar(aadhar):
    return aadhar[:4] + "XXXX XXXX"

def mask_passport(passport):
    return passport[0] + "XXXXXXX"

def mask_name(name):
    parts = name.split()
    return " ".join([p[0] + "X" * (len(p)-1) for p in parts])

def mask_email(email):
    user, domain = email.split("@")
    return user[:2] + "X" * (len(user)-2) + "@" + domain

def mask_upi(upi):
    user, domain = upi.split("@")
    return user[:2] + "X" * (len(user)-2) + "@" + domain

# Define standalone and combinatorial PII fields
STANDALONE_PII = ['phone', 'aadhar', 'passport', 'upi_id']
COMBINATORIAL_PII = ['name', 'email', 'address', 'device_id', 'ip_address']

def is_standalone_pii(field, value):
    if field == 'phone' and PHONE_REGEX.match(value):
        return True
    if field == 'aadhar' and AADHAR_REGEX.match(value):
        return True
    if field == 'passport' and PASSPORT_REGEX.match(value):
        return True
    if field == 'upi_id' and UPI_REGEX.match(value):
        return True
    return False

def redact_standalone(field, value):
    if field == 'phone':
        return mask_phone(value)
    if field == 'aadhar':
        return mask_aadhar(value)
    if field == 'passport':
        return mask_passport(value)
    if field == 'upi_id':
        return mask_upi(value)
    return '[REDACTED_PII]'

def redact_combinatorial(data):
    redacted = dict(data)
    if 'name' in redacted:
        redacted['name'] = mask_name(redacted['name'])
    if 'email' in redacted:
        redacted['email'] = mask_email(redacted['email'])
    if 'address' in redacted:
        redacted['address'] = '[REDACTED_PII]'
    if 'device_id' in redacted:
        redacted['device_id'] = '[REDACTED_PII]'
    if 'ip_address' in redacted:
        redacted['ip_address'] = '[REDACTED_PII]'
    return redacted

def has_combinatorial_pii(data):
    count = 0
    for key in COMBINATORIAL_PII:
        if key in data and data[key]:
            count += 1
    return count >= 2

def process_record(record_json):
    data = json.loads(record_json)
    is_pii = False
    redacted_data = dict(data)

    # Check standalone PII
    for field in STANDALONE_PII:
        if field in data and data[field]:
            if is_standalone_pii(field, str(data[field])):
                is_pii = True
                redacted_data[field] = redact_standalone(field, str(data[field]))

    # Check combinatorial PII
    if has_combinatorial_pii(data):
        is_pii = True
        redacted_data = redact_combinatorial(redacted_data)

    return json.dumps(redacted_data, ensure_ascii=False), is_pii

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        return

    input_csv = sys.argv[1]
    output_csv = 'redacted_output_candidate_full_name.csv'

    with open(input_csv, newline='') as fin, open(output_csv, 'w', newline='') as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        for row in reader:
            redacted_json, pii_flag = process_record(row['data_json'])
            writer.writerow({
                'record_id': row['record_id'],
                'redacted_data_json': redacted_json,
                'is_pii': pii_flag
            })
    print(f"Redacted output saved to {output_csv}")

if __name__ == "__main__":
    main()
