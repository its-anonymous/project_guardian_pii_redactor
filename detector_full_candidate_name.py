import re
import json
import csv

def safe_json_loads(s):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        s_fixed = s.replace('""', '"').replace('\\"', '"')
        try:
            return json.loads(s_fixed)
        except:
            return {}

PII_PATTERNS = {
    'phone': re.compile(r'^\d{10}$'),
    'aadhar': re.compile(r'^\d{12}$'),
    'passport': re.compile(r'^[A-Za-z]\d{7,8}$'),
    'upi_id': re.compile(r'^\w+@\w+$'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    'name': re.compile(r'^[A-Za-z]+ [A-Za-z]+$'),
    'address': re.compile(r'.*\\d.*'),
    'ip_address': re.compile(r'^\d{1,3}(\.\d{1,3}){3}$'),
}
STANDALONE_KEYS = ['phone', 'aadhar', 'passport', 'upi_id']
COMBINATORIAL_KEYS = ['name', 'email', 'address', 'ip_address']

def mask_phone(val):
    if PII_PATTERNS['phone'].match(val):
        return val[:2] + 'XXXXXX' + val[-2:]
    return val

def mask_aadhar(val):
    if PII_PATTERNS['aadhar'].match(val):
        return val[:4] + ' XXXX ' + val[-4:]
    return val

def mask_passport(val):
    if PII_PATTERNS['passport'].match(val):
        return '[REDACTED_PII]'
    return val

def mask_upi(val):
    if PII_PATTERNS['upi_id'].match(val):
        username, domain = val.split('@', 1)
        return username[:2] + 'XXXXX@' + domain
    return val

def mask_name(val):
    parts = val.split(' ')
    return ' '.join([p + 'XXX' for p in parts if p])

def mask_email(val):
    local, _, domain = val.partition('@')
    return local[:2] + 'XXX@' + domain

def mask_address(val): return '[REDACTED_PII]'
def mask_ip(val):
    parts = val.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3] + ['XXX'])
    return val

redact_map = {
    'phone': mask_phone,
    'aadhar': mask_aadhar,
    'passport': mask_passport,
    'upi_id': mask_upi,
    'name': mask_name,
    'email': mask_email,
    'address': mask_address,
    'ip_address': mask_ip,
}

def is_pii_record(d):
    for k in STANDALONE_KEYS:
        if k in d and d[k] and PII_PATTERNS[k].match(str(d[k])):
            return True
    present = [k for k in COMBINATORIAL_KEYS if k in d and d[k]]
    return len(present) > 1

def redact_record(d):
    out = {}
    for k, v in d.items():
        if k in redact_map and ((k in STANDALONE_KEYS and PII_PATTERNS[k].match(str(v))) or (k in COMBINATORIAL_KEYS)):
            out[k] = redact_map[k](str(v))
        else:
            out[k] = v
    return out

with open('iscp_pii_dataset.csv', 'r', encoding='utf-8') as f_in, \
     open('redacted_output_candidate_full_name.csv', 'w', newline='', encoding='utf-8') as f_out:
    reader = csv.DictReader(f_in)
    writer = csv.DictWriter(f_out, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
    writer.writeheader()
    for row in reader:
        record_id = row['record_id']
        data = safe_json_loads(row['data_json'])
        pii = is_pii_record(data)
        redacted = redact_record(data) if pii else data
        writer.writerow({
            'record_id': record_id,
            'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
            'is_pii': str(pii)
        })
