import csv
import json
import re

# Regular expressions for PII detection
phone_pattern = re.compile(r"^\d{10}$")
aadhar_pattern = re.compile(r"^\d{12}$")
passport_pattern = re.compile(r"^[A-PR-WY][0-9]{7}$")  # Example format: P1234567
upi_pattern = re.compile(r"^[\w.\-]{2,256}@[a-zA-Z]{2,32}$")
email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")  # Simple email pattern
ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Functions to mask/redact PII
def mask_phone(phone):
    return phone[:2] + "XXXXXX" + phone[-2:]

def mask_aadhar(aadhar):
    return aadhar[:4] + "XXXX XXXX"

def mask_passport(passport):
    return passport[0] + "XXXXXXX"

def mask_name(full_name):
    parts = full_name.split()
    masked_parts = [p[0] + "X" * (len(p) - 1) for p in parts]
    return " ".join(masked_parts)

def mask_email(email):
    user, domain = email.split("@")
    masked_user = user[:2] + "X" * (len(user) - 2)
    return masked_user + "@" + domain

def mask_upi(upi_id):
    user, domain = upi_id.split("@")
    masked_user = user[:2] + "X" * (len(user) - 2)
    return masked_user + "@" + domain

# Lists of fields that are standalone PII or combinatorial PII
standalone_pii_fields = ["phone", "aadhar", "passport", "upi_id"]
combinatorial_pii_fields = ["name", "email", "address", "device_id", "ip_address"]

def is_standalone_pii(field, value):
    value = str(value)
    if field == "phone" and phone_pattern.fullmatch(value):
        return True
    if field == "aadhar" and aadhar_pattern.fullmatch(value):
        return True
    if field == "passport" and passport_pattern.fullmatch(value):
        return True
    if field == "upi_id" and upi_pattern.fullmatch(value):
        return True
    return False

def redact_standalone(field, value):
    if field == "phone":
        return mask_phone(value)
    if field == "aadhar":
        return mask_aadhar(value)
    if field == "passport":
        return mask_passport(value)
    if field == "upi_id":
        return mask_upi(value)
    return "[REDACTED_PII]"

def redact_combinatorial(fields_dict):
    redacted_dict = dict(fields_dict)
    if 'name' in redacted_dict and redacted_dict['name']:
        redacted_dict['name'] = mask_name(redacted_dict['name'])
    if 'email' in redacted_dict and redacted_dict['email']:
        redacted_dict['email'] = mask_email(redacted_dict['email'])
    if 'address' in redacted_dict and redacted_dict['address']:
        redacted_dict['address'] = "[REDACTED_PII]"
    if 'device_id' in redacted_dict and redacted_dict['device_id']:
        redacted_dict['device_id'] = "[REDACTED_PII]"
    if 'ip_address' in redacted_dict and redacted_dict['ip_address']:
        redacted_dict['ip_address'] = "[REDACTED_PII]"
    return redacted_dict

def has_combinatorial_pii(data):
    count = 0
    for field in combinatorial_pii_fields:
        if field in data and data[field]:
            count += 1
    return count >= 2

def process_record(json_str):
    data = json.loads(json_str)
    is_pii = False
    redacted_data = dict(data)
    
    # Check standalone PII fields
    for field in standalone_pii_fields:
        if field in data and data[field]:
            if is_standalone_pii(field, data[field]):
                is_pii = True
                redacted_data[field] = redact_standalone(field, data[field])
    
    # Check combinatorial PII presence and redact if needed
    if has_combinatorial_pii(data):
        is_pii = True
        redacted_data = redact_combinatorial(redacted_data)
    
    return json.dumps(redacted_data, ensure_ascii=False), is_pii

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input_csv_file.csv")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"
    
    with open(input_csv, newline='', encoding='utf-8') as infile, \
         open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        
        reader = csv.DictReader(infile)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for row in reader:
            redacted_json, pii_flag = process_record(row['data_json'])
            writer.writerow({
                "record_id": row['record_id'],
                "redacted_data_json": redacted_json,
                "is_pii": pii_flag
            })
    
    print(f"PII detection and redaction complete. Output saved to {output_csv}")

if __name__ == "__main__":
    main()
