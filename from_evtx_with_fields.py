#!/usr/bin/env python3

import os
import sys
import json
import xml.etree.ElementTree as ET
from collections import Counter
from typing import List, Dict, Tuple

try:
    from evtx import PyEvtxParser
    USING_RUST_EVTX = True
except ImportError:
    try:
        import Evtx.Evtx as EvtxLib
        USING_RUST_EVTX = False
    except ImportError:
        print("Ошибка: Библиотека для парсинга EVTX не найдена.")
        print("Установите: pip install evtx или pip install python-evtx")
        sys.exit(1)

TARGET_FIELDS = {
    '4657': ['ObjectName', 'ObjectValueName', 'ProcessName', 'Accesses'],
    '4660': ['ObjectName', 'ProcessName'],
    '4670': ['ObjectName', 'NewSecurityDescriptor', 'ProcessName'],
    '4689': ['ProcessName', 'ProcessId', 'SubjectUserName'],
    '4698': ['TaskName', 'TaskContent', 'Author'],
    '4699': ['TaskName', 'Author'],
    '4700': ['TaskName', 'TaskContent'],
    '4701': ['TaskName'],
    '4702': ['TaskName'],
    '4719': ['SubjectUserName', 'AuditPolicyChanges'],
    '4735': ['GroupName', 'SubjectUserName'],
    '4740': ['AccountName', 'SubjectUserName'],
    '4798': ['SubjectUserName', 'TargetUserName'],
    '4799': ['SubjectUserName', 'TargetUserName'],
    '5142': ['ShareName', 'SharePath', 'SubjectUserName'],
    '5145': ['ShareName', 'RelativeTargetName', 'AccessMask'],
    '2': ['TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime'],
    '5': ['Image', 'User'],
    '8': ['StartAddress', 'TargetImage', 'SourceImage'],
    '9': ['Image', 'Device'],
    '12': ['TargetObject', 'Details', 'EventType'],
    '13': ['TargetObject', 'Details', 'EventType'],
    '14': ['TargetObject', 'Details'],
    '15': ['TargetFilename', 'CreationUtcTime'],
    '16': ['Configuration'],
    '17': ['PipeName', 'Image'],
    '18': ['PipeName', 'Image'],
    '22': ['QueryName', 'QueryStatus', 'Image'],
    '23': ['TargetFilename', 'Image'],
    '24': ['SourceImage', 'TargetImage'],
    '25': ['Image', 'ProcessId'],
    '4104': ['ScriptBlockText', 'Path', 'ScriptBlockId'],
    '4103': ['Payload', 'Context'],
    '4105': ['ScriptBlockId'],
    '4106': ['ScriptBlockId'],
    '1116': ['Threat Name', 'Action Name', 'Detection Source'],
    '5007': ['ValueType', 'OperationType'],
    '7045': ['ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName'],
    '7036': ['ServiceName', 'State'],
    '7040': ['ServiceName', 'StartType'],
    '1102': ['SubjectUserName'],
    '104': ['SubjectUserName', 'Channel'],
    '5136': ['AttributeLDAPDisplayName', 'AttributeValue', 'ObjectDN'],
    '4662': ['Properties', 'ObjectName'],
    '1116': ['Threat Name', 'Action Name', 'Source Name'],
    '1117': ['Threat Name', 'Action Name', 'Source Name'],
    '1151': ['Status', 'Feature', 'Product Name'],
    '1': ['CommandLine', 'Image', 'ParentImage', 'ProcessId', 'IntegrityLevel'],
    '7': ['TargetFilename', 'CreationUtcTime', 'SystemTimeSystemTime'],
    '3': ['DestinationIp', 'DestinationPort', 'Image', 'Protocol', 'ProcessId', 'User'],
    '10': ['SourceProcessGUID', 'TargetProcessGUID', 'GrantedAccess', 'CallTrace'],
    '11': ['TargetFilename', 'CreationUtcTime', 'SystemTime', 'Hashes'],
    '4624': ['LogonType', 'TargetUserName', 'IpAddress', 'AuthenticationPackageName', 'WorkstationName'],
    '4625': ['FailureReason', 'Status', 'LogonType', 'TargetUserName', 'IpAddress', 'SubStatus'],
    '4648': ['TargetUserName', 'SubjectUserName', 'ProcessName'],
    '4661': ['ObjectName', 'AccessMask', 'ProcessName', 'ObjectType'],
    '4663': ['ObjectName', 'AccessMask', 'ProcessName', 'Accesses', 'ObjectType'],
    '4672': ['SubjectUserName', 'PrivilegeList'],
    '4673': ['ServiceName', 'PrivilegeList', 'ProcessName'],
    '4674': ['ObjectName', 'PrivilegeList', 'ProcessName', 'ObjectType'],
    '4685': ['TargetUserName', 'TargetDomainName', 'TargetSid', 'SubjectUserName'],
    '4688': ['CommandLine', 'ProcessName', 'ParentProcessName', 'NewProcessId', 'SubjectUserName'],
    '4697': ['ServiceName', 'ImagePath', 'StartType', 'AccountName'],
    '4719': ['ObjectDN', 'ObjectClass', 'AccessMask', 'SubjectUserName'],
    '4720': ['Account Created', 'Security ID', 'Account Name'],
    '4721': ['Account Created', 'Security ID', 'Account Name'],
    '4722': ['Account Enabled', 'Security ID', 'Account Name'],
    '4723': ['Account Changed', 'Security ID', 'Account Name', 'PasswordLastSet'],
    '4724': ['Account Changed', 'Security ID', 'Account Name', 'PasswordLastSet'],
    '4725': ['Account Disabled', 'Security ID', 'Account Name'],
    '4726': ['Account Deleted', 'Security ID', 'Account Name'],
    '4738': ['Account Changed', 'Security ID', 'Account Name', 'SamAccountName'],
    '4742': ['Computer Changed', 'Security ID', 'Computer Name'],
    '4765': ['Target Account', 'Security ID', 'Account Name', 'SidHistory'],
    '4766': ['Target Account', 'Security ID', 'Account Name', 'SidHistory'],
    '4767': ['Target Account', 'Security ID', 'Account Name', 'SidHistory'],
    '4768': ['TargetUserName', 'IpAddress', 'TicketOptions', 'EncryptionType'],
    '4769': ['ServiceName', 'TicketOptions', 'IpAddress', 'EncryptionType'],
    '4770': ['ServiceName', 'TicketOptions', 'IpAddress'],
    '4771': ['TargetUserName', 'IpAddress', 'PreAuthType'],
    '4776': ['TargetUserName', 'Workstation', 'ErrorCode'],
    '4778': ['SessionName', 'AccountName', 'ClientAddress'],
    '4779': ['SessionName', 'AccountName', 'ClientAddress'],
    '4781': ['Account Changed', 'Security ID', 'Account Name', 'OldUserName'],
    '4935': ['Computer', 'ServiceName', 'Principal'],
    '5033': ['DriverName', 'ServiceName'],
    '5137': ['ObjectDN', 'AttributeLDAPDisplayName', 'AttributeValue'],
    '5138': ['ObjectDN', 'AttributeLDAPDisplayName', 'AttributeValue'],
    '5139': ['ObjectDN', 'AttributeLDAPDisplayName', 'AttributeValue'],
    '5140': ['ShareName', 'AccessMask', 'IpAddress', 'RelativeTargetName'],
    '5141': ['ObjectDN', 'AttributeLDAPDisplayName', 'AttributeValue'],
    '5145': ['RelativeTargetName', 'AccessMask', 'IpAddress', 'ShareName'],
    '5156': ['Application', 'Protocol', 'Direction', 'DestAddress', 'DestPort'],
    '5157': ['Application', 'Protocol', 'Direction', 'DestAddress', 'DestPort'],
    '5158': ['Application', 'Protocol', 'Direction', 'DestAddress', 'DestPort'],
    '5376': ['TargetName', 'Type', 'User'],
    '5377': ['TargetName', 'Type', 'User'],
    '5381': ['TargetName', 'Type', 'User'],
    '5382': ['TargetName', 'Type', 'User'],
    '541': ['LogName', 'Channel', 'SubjectUserName'],
    '5857': ['ProviderName', 'ApplicationName', 'CommandLine'],
    '6416': ['Volume', 'EncryptionMethod', 'ProtectionStatus'],
    '15457': ['ProcedureName', 'QueryText'],
    '4103': ['CommandName', 'SequenceNumber', 'HostId'],
    '4104': ['ScriptBlockText', 'Path', 'Payload'],
    '800': ['ProviderName', 'CommandName', 'SequenceNumber'],
    '803': ['ProviderName', 'CommandName', 'SequenceNumber'],
    '4': ['State', 'Version', 'Configuration'],
    '6': ['ImageLoaded', 'Hashes', 'Signature', 'SignatureStatus'],
    '19': ['EventNamespace', 'Name', 'Query', 'Operation'],
    '20': ['Name', 'Type', 'Destination', 'Operation'],
    '59': ['Device', 'Image'],
    '60': ['RuleName', 'Rule', 'Action', 'Direction'],
    '70': ['SearchSuffix', 'Interface'],
    '300': ['Feature', 'Status'],
    '301': ['Product', 'Version'],
    '316': ['Action'],
    '325': ['Action'],
    '327': ['Action'],
    '354': ['Status'],
    '400': ['HostApplication', 'PipelineId', 'RunspaceId'],
    '472': ['CommandName', 'CommandType', 'ScriptName'],
    '600': ['NewProviderState', 'NewEngineState'],
    '768': ['ProviderName', 'Payload'],
    '770': ['ProviderName', 'Payload'],
    '775': ['Payload'],
    '793': ['Payload'],
    '796': ['Payload'],
    '808': ['Payload'],
    '817': ['Payload'],
    '823': ['Payload'],
    '840': ['Payload'],
    '848': ['Payload'],
    '4616': ['SubjectUserName', 'ProcessName', 'PreviousTime', 'NewTime'],
    '4622': ['PackageName', 'ModulePath'],
    '4656': ['ObjectName', 'ObjectServer', 'ProcessName', 'AccessMask', 'HandleId'],
    '4658': ['HandleId', 'ProcessName'],
    '4664': ['SourceFileName', 'TargetFileName', 'ProcessName'],
    '4704': ['PrivilegeList', 'SubjectUserName'],
    '4705': ['PrivilegeList', 'SubjectUserName'],
    '4706': ['TrustPartner', 'TrustType', 'TrustDirection'],
    '4717': ['AccountName', 'RightsList', 'Modifier'],
    '4718': ['AccountName', 'RightsList', 'Modifier'],
    '4728': ['MemberName', 'GroupName', 'SubjectUserName'],
    '4732': ['MemberName', 'TargetUserName', 'SubjectUserName'],
    '4733': ['MemberName', 'TargetUserName', 'SubjectUserName'],
    '4739': ['OpCode', 'DomainPolicyID', 'PolicyChange'],
    '4741': ['AccountName', 'DnsHostName', 'SubjectUserName'],
    '4743': ['AccountName', 'DnsHostName', 'SubjectUserName'],
    '4756': ['MemberName', 'GroupName', 'SubjectUserName'],
    '4794': ['SubjectUserName', 'ProcessName'],
    '4825': ['RuleId', 'RuleName', 'Action'],
    '4865': ['TrustedDomainName', 'ForestInformation'],
    '4876': ['BackupVersion', 'SubjectUserName'],
    '4877': ['Status', 'SubjectUserName'],
    '4885': ['CategoryName', 'SubcategoryName', 'SubcategoryGUID'],
    '4908': ['SpecialGroup', 'SubjectUserName'],
    '4950': ['Param1', 'Param2', 'Param3'],
    '4964': ['SpecialGroups', 'TargetUserName'],
    '5007': ['SubjectUserName', 'ObjectName', 'ValueType', 'OperationType'],
    '5123': ['SubjectUserName', 'LogName'],
    '5124': ['SubjectUserName', 'LogName'],
    '5143': ['ShareName', 'SharePath', 'SubjectUserName'],
    '5379': ['TargetName', 'Type', 'User'],
    '5447': ['ProviderKey', 'ProviderName', 'SubjectUserName'],
    '5600': ['ProcessId', 'ServiceName'],
    '6004': ['ProviderName', 'ProcessName'],
    '7000': ['ServiceName', 'ErrorCode'],
    '7009': ['ServiceName', 'Timeout'],
    '11715': ['Product', 'Action', 'Result'],
    '18466': ['Message', 'Data']
}

def find_evtx_files(directory: str) -> List[str]:
    if not os.path.isdir(directory):
        print(f"Ошибка: Директория '{directory}' не существует.")
        sys.exit(1)
        
    evtx_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.evtx'):
                full_path = os.path.abspath(os.path.join(root, file))
                evtx_files.append(full_path)
                
    if not evtx_files:
        print(f"Предупреждение: В директории '{directory}' не найдено файлов .evtx.")
        sys.exit(0)
        
    return evtx_files

def extract_event_info_from_evtx(file_path: str) -> Tuple[Counter, List[Dict]]:
    counts = Counter()
    extracted_events = []
    
    try:
        if USING_RUST_EVTX:
            parser = PyEvtxParser(file_path)
            records = parser.records()
        else:
            parser = EvtxLib.Evtx(file_path)
            records = parser.records()

        for record in records:
            try:
                xml_str = record['data'] if USING_RUST_EVTX else record.xml()
                root = ET.fromstring(xml_str)
                
                system_elem = None
                for child in root: 
                    if child.tag.endswith('System'):
                        system_elem = child
                        break
                
                event_id, channel = 'UNKNOWN', 'UNKNOWN'
                time_created = 'UNKNOWN'
                
                if system_elem is not None:
                    for child in system_elem:
                        if child.tag.endswith('EventID'):
                            event_id = child.text if child.text else 'UNKNOWN'
                        elif child.tag.endswith('Channel'):
                            channel = child.text if child.text else 'UNKNOWN'
                        elif child.tag.endswith('TimeCreated'):
                            time_created = child.attrib.get('SystemTime', 'UNKNOWN')
                            
                key = f"{event_id}|{channel}"
                counts[key] += 1
                
                if event_id in TARGET_FIELDS:
                    fields_to_extract = TARGET_FIELDS[event_id]
                    event_details = {
                        "EventID": event_id,
                        "Channel": channel,
                        "TimeCreated": time_created,
                        "File": os.path.basename(file_path)
                    }
                    
                    for field in fields_to_extract:
                        event_details[field] = None
                        
                    for elem in root.iter():
                        tag_name = elem.tag.split('}')[-1]
                        
                        if tag_name == 'Data':
                            name_attr = elem.attrib.get('Name')
                            if name_attr in fields_to_extract:
                                event_details[name_attr] = elem.text
                        elif tag_name in fields_to_extract:
                            event_details[tag_name] = elem.text
                            
                    extracted_events.append(event_details)

            except ET.ParseError:
                continue
                
    except Exception as e:
        print(f"\nОшибка при чтении файла {file_path}: {e}")
        
    return counts, extracted_events

def process_all_files(evtx_files: List[str], base_dir: str) -> Tuple[Counter, Dict[str, Counter], List[Dict]]:
    global_counter = Counter()
    per_file_results = {}
    all_extracted_events = []
    total_files = len(evtx_files)

    for idx, file_path in enumerate(evtx_files, 1):
        rel_path = os.path.relpath(file_path, base_dir).replace('\\', '/')
        print(f"[{idx}/{total_files}] {rel_path}")
        
        file_counter, extracted_events = extract_event_info_from_evtx(file_path)
        
        per_file_results[rel_path] = file_counter
        global_counter.update(file_counter)
        all_extracted_events.extend(extracted_events)

    return global_counter, per_file_results, all_extracted_events

def format_global_summary(global_counter: Counter) -> Dict:
    by_channel = {}
    
    for key, count in global_counter.most_common():
        parts = key.split('|', 1)
        event_id = parts[0]
        channel = parts[1] if len(parts) > 1 else 'UNKNOWN'
        
        if channel not in by_channel:
            by_channel[channel] = {}
        by_channel[channel][event_id] = count

    return {
        "by_channel": by_channel,
        "by_event_channel": dict(global_counter.most_common())
    }

def save_json_output(results: Dict, output_path: str) -> None:
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nJSON сохранён: {output_path}")
    except Exception as e:
        print(f"\nОшибка при сохранении JSON: {e}")

def main() -> None:
    BASE_DIR = "."
    OUTPUT_JSON = "evtx_event_analysis.json"
    
    if len(sys.argv) > 1:
        BASE_DIR = sys.argv[1]

    print(f"Поиск EVTX файлов в директории: {os.path.abspath(BASE_DIR)}")
    evtx_files = find_evtx_files(BASE_DIR)
    print(f"Найдено файлов: {len(evtx_files)}")
    print("Парсинг...\n")
    
    global_counter, per_file_results, all_extracted_events = process_all_files(evtx_files, BASE_DIR)
    
    summary = format_global_summary(global_counter)
    per_file_clean = {path: dict(counter.most_common()) for path, counter in per_file_results.items()}
    
    final_output = {
        "GLOBAL_SUMMARY": summary,
        "per_file": per_file_clean,
        "EXTRACTED_EVENTS": all_extracted_events
    }
    
    save_json_output(final_output, OUTPUT_JSON)
    
    total_records = sum(global_counter.values())
    print(f"Всего обработано записей: {total_records}")
    print(f"Извлечено целевых событий с деталями: {len(all_extracted_events)}")

if __name__ == "__main__":
    main()
