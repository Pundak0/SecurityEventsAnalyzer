#!/usr/bin/env python3

import json
import sys
import re

def extract_sigma(zircolite_json_path):
    with open(zircolite_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    results = []
    
    for alert in data:
        sigma_sql = alert.get('sigma', [''])[0]
        
        event_ids = set()
        for match in re.findall(r"EventID\s*=\s*['\"]?(\d+)['\"]?", sigma_sql, re.IGNORECASE):
            event_ids.add(match)
        for match in re.findall(r"EventID\s+IN\s*\(([^)]+)\)", sigma_sql, re.IGNORECASE):
            for eid in re.findall(r"(\d+)", match):
                event_ids.add(eid)
        
        results.append({
            'event_ids': sorted(event_ids, key=int),
            'count': alert.get('count', 0),
            'sigma': sigma_sql
        })
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Использование: python extract_sigma_from_zircolite.py <result.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    results = extract_sigma(input_file)
    
    out_file = input_file.replace('.json', '_sigma_info.json')
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"Сохранено в: {out_file}")

if __name__ == "__main__":
    main()
