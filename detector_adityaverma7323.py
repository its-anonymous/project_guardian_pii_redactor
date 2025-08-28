import csv
import json
import re
import sys

###### Define REGEX patterns for PII 
PHONE_PATTERN = re.compile(r"^\d{10}$")                      # 10-digit phone number
AADHAR_PATTERN = re.compile(r"^\d{12}$")                     # 12-digit Aadhar
PASSPORT_PATTERN = re.compile(r"^[A-PR-WYa-pr-wy][0-9]{7}$") # Indian passport
UPI_PATTERN = re.compile(r"^[\w\.\-]{2,256}@[a-zA-Z]{2,32}$")# UPI ID
EMAIL_PATTERN = re.compile(r"[^@]+@[^@]+\.[^@]+")            # Email
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")          # IPv4

###### Masking functions
def mask_phone(phone):
    return phone[:2] + "XXXXXX" + phone[-2:]

def mask_aadhar(aadhar):
    return aadhar[:4] + "XXXX XXXX"

def mask_passport(passport):
    return passport[0] + "XXXXXXX"

def mask_name(name):
    parts = name.split()
    # Each part: first letter + all X's
    return " ".join([p[0] + "X" * (len(p)-1) for p in parts])

def mask_email(email):
    try:
        user, domain = email.split("@")
    except ValueError:
        return "[REDACTED_PII]"
    return user[:2] + "X" * max(len(user)-2,0) + "@" + domain

def mask_upi(upi):
    try:
        user, bank = upi.split("@")
    except ValueError:
        return "[REDACTED_PII]"
    return user[:2] + "X" * max(len(user)-2,0) + "@" + bank

###### Helper lists
STANDALONE_PII = ['phone', 'aadhar', 'passport', 'upi_id']
COMBINATORIAL_PII = ['name', 'email', 'address', 'device_id', 'ip_address']

def is_standalone_pii(field, value):
    if field == 'phone' and PHONE_PATTERN.match(value):
        return True
    if field == 'aadhar' and AADHAR_PATTERN.match(value):
        return True
    if field == 'passport' and PASSPORT_PATTERN.match(value):
        return True
    if field == 'upi_id' and UPI_PATTERN.match(value):
        return True
    return False

def redact_standalone(field, value):
    # Field-specific masking
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
    if 'name' in redacted and redacted['name']:
        redacted['name'] = mask_name(redacted['name'])
    if 'email' in redacted and redacted['email']:
        redacted['email'] = mask_email(redacted['email'])
    if 'address' in redacted and redacted['address']:
        redacted['address'] = '[REDACTED_PII]'
    if 'device_id' in redacted and redacted['device_id']:
        redacted['device_id'] = '[REDACTED_PII]'
    if 'ip_address' in redacted and redacted['ip_address']:
        redacted['ip_address'] = '[REDACTED_PII]'
    return redacted

def has_combinatorial_pii(data):
    # Count how many combinatorial keys are present and non-empty
    count = 0
    for key in COMBINATORIAL_PII:
        if key in data and str(data[key]).strip():
            count += 1
    return count >= 2

def process_record(record_json):
    # Clean up JSON
    try:
        data = json.loads(record_json)
    except Exception:
        # Try fixing common errors
        fixed = record_json.replace("'", "\"")
        try:
            data = json.loads(fixed)
        except Exception:
            # Return unchanged, no pii
            return record_json, False

    is_pii = False
    redacted_data = dict(data)

    ###### Standalone PII detection and masking
    for field in STANDALONE_PII:
        if field in data and str(data[field]).strip():
            if is_standalone_pii(field, str(data[field]).strip()):
                is_pii = True
                redacted_data[field] = redact_standalone(field, str(data[field]).strip())

    ###### Combinatorial PII masking if 2 or more are present
    if has_combinatorial_pii(data):
        is_pii = True
        redacted_data = redact_combinatorial(redacted_data)

    return json.dumps(redacted_data, ensure_ascii=False), is_pii

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_adityaverma7323.py iscp_pii_dataset.csv")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = 'redacted_output_adityaverma7323.csv'
    with open(input_csv, newline='', encoding='utf-8') as fin, open(output_csv, 'w', newline='', encoding='utf-8') as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        for row in reader:
            # READ CSV COLUMN EXACTLY AS PRESENT IN HEADER
            json_str = row.get('data_json') or row.get('Data_json')
            if not json_str:
                # Skip rows without the field
                continue
            redacted_json, pii_flag = process_record(json_str)
            writer.writerow({
                'record_id': row['record_id'],
                'redacted_data_json': redacted_json,
                'is_pii': str(pii_flag)
            })
    print(f"Redacted output saved to {output_csv}")

if __name__ == "__main__":
    main()
