import json
import os
import sys
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class Classification(Enum):
    TP = "TP"
    FP = "FP"
    TN = "TN"
    FN = "FN"


@dataclass
class GroundTruthEvent:
    event_id: str
    channel: str
    time_created: str
    file_name: str
    threat_name: str
    details: Dict = field(default_factory=dict)


@dataclass
class SigmaMatch:
    rule_id: str
    rule_title: str
    rule_level: str
    event_id: str
    channel: str
    file_name: str
    match_data: Dict


def load_ground_truth(filepath: str) -> List[GroundTruthEvent]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        events = []
        extracted = data.get("EXTRACTED_EVENTS", [])
        
        for e in extracted:
            events.append(GroundTruthEvent(
                event_id=str(e.get("EventID", "")),
                channel=e.get("Channel", ""),
                time_created=e.get("TimeCreated", ""),
                file_name=e.get("File", ""),
                threat_name=e.get("Threat Name") or e.get("Image") or "Unknown Threat",
                details=e
            ))
        return events
    except Exception as e:
        print(f"Ошибка загрузки эталона: {e}")
        return []


def load_sigma_results(filepath: str) -> List[SigmaMatch]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        matches = []
        for rule in data:
            rule_id = rule.get("id", "N/A")
            rule_title = rule.get("title", "Unknown Rule")
            rule_level = rule.get("level", "low")
            
            for m in rule.get("matches", []):
                raw_path = m.get("OriginalLogfile", "")
                file_name = os.path.basename(raw_path.replace("\\", "/"))
                
                matches.append(SigmaMatch(
                    rule_id=rule_id,
                    rule_title=rule_title,
                    rule_level=rule_level,
                    event_id=str(m.get("EventID", "")),
                    channel=m.get("Channel", ""),
                    file_name=file_name,
                    match_data=m
                ))
        return matches
    except Exception as e:
        print(f"Ошибка загрузки результатов Zircolite: {e}")
        return []


def calculate_metrics(tp: int, fp: int, fn: int) -> Dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3)
    }


def evaluate_detection(ground_truth: List[GroundTruthEvent], sigma_matches: List[SigmaMatch]):
    truth_by_file = defaultdict(list)
    for e in ground_truth:
        truth_by_file[e.file_name].append(e)
        
    matches_by_file = defaultdict(list)
    for m in sigma_matches:
        matches_by_file[m.file_name].append(m)
        
    all_files = set(truth_by_file.keys()) | set(matches_by_file.keys())
    
    final_report = {}
    total_tp, total_fp, total_fn = 0, 0, 0

    print(f"\n{'='*80}")
    print("АНАЛИЗ ЭФФЕКТИВНОСТИ СИГНАТУР")
    print(f"{'='*80}")

    for fname in sorted(all_files):
        print(f"\nФайл: {fname}")
        
        file_truth = truth_by_file[fname]
        file_matches = matches_by_file[fname]
        
        file_evals = []
        matched_truth_keys = set()
        
        tp_in_file = 0
        fp_in_file = 0
        
        for m in file_matches:
            is_tp = False
            for t in file_truth:
                if m.event_id == t.event_id and m.channel == t.channel:
                    is_tp = True
                    matched_truth_keys.add(f"{t.event_id}|{t.channel}|{t.time_created}")
                    break
            
            status = Classification.TP if is_tp else Classification.FP
            if is_tp:
                tp_in_file += 1
            else:
                fp_in_file += 1
            
            file_evals.append({
                "rule": m.rule_title,
                "level": m.rule_level,
                "status": status.value,
                "event_id": m.event_id
            })
            
            icon = "[+]" if is_tp else "[-]"
            print(f"  {icon} {status.value}: {m.rule_title} (ID:{m.event_id})")

        missed = []
        for t in file_truth:
            key = f"{t.event_id}|{t.channel}|{t.time_created}"
            if key not in matched_truth_keys:
                missed.append(t)
        
        fn_in_file = len(missed)
        total_tp += tp_in_file
        total_fp += fp_in_file
        total_fn += fn_in_file

        if missed:
            print(f"  [!] FN (Пропущено):")
            for m in missed:
                print(f"     - {m.threat_name} (EventID: {m.event_id})")

        metrics = calculate_metrics(tp_in_file, fp_in_file, fn_in_file)
        final_report[fname] = {
            "metrics": metrics,
            "evaluations": file_evals,
            "missed": [m.threat_name for m in missed]
        }
        print(f"  Metrics: P:{metrics['precision']} R:{metrics['recall']} F1:{metrics['f1_score']}")

    global_metrics = calculate_metrics(total_tp, total_fp, total_fn)
    print(f"\n{'='*80}")
    print("ИТОГОВАЯ СТАТИСТИКА:")
    print(f"{'='*80}")
    print(f"Всего TP: {total_tp}")
    print(f"Всего FP: {total_fp}")
    print(f"Всего FN: {total_fn}")
    print(f"Точность (Precision): {global_metrics['precision']}")
    print(f"Полнота (Recall): {global_metrics['recall']}")
    print(f"F1-Score: {global_metrics['f1_score']}")

    return final_report


def main():
    SIGMA_FILE = r"C:\Users\vboxuser\result_with_our_rules_second_dataset.json"
    TRUTH_FILE = r"C:\Users\vboxuser\evtx_event_analysis_second_dataset_with_eventID.json"
    OUTPUT_FILE = "classification_with_out_rules_second_dataset.json"

    if not os.path.exists(SIGMA_FILE) or not os.path.exists(TRUTH_FILE):
        print(f"Ошибка: Убедитесь, что {SIGMA_FILE} и {TRUTH_FILE} существуют.")
        return

    print("Загрузка данных...")
    truth_data = load_ground_truth(TRUTH_FILE)
    sigma_data = load_sigma_results(SIGMA_FILE)

    report = evaluate_detection(truth_data, sigma_data)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nПолный отчет сохранен в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
