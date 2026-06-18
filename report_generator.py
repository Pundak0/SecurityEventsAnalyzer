#!/usr/bin/env python3
"""
Генератор отчётов Zircolite - Анализ событий безопасности
"""

import json
import sys
import os
from datetime import datetime

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4
}

# Для красивого отображения в отчёте
SORT_DISPLAY_NAMES = {
    "severity": "По уровню критичности (Severity)",
    "count": "По количеству срабатываний (Count)",
    "title": "По названию правила (Title)",
    "computer": "По компьютеру (Computer)",
    "channel": "По каналу событий (Channel)",
    "eventid": "По EventID",
}

def is_compromise_indicator(rule):
    """Определяет, является ли правило признаком компрометации"""
    rule_level = rule.get('rule_level', '').lower()
    return rule_level in ['critical', 'high', 'medium'] and rule.get('count', 0) > 0


def extract_user_from_message(msg):
    """Извлекает имя пользователя из сообщения"""
    if 'session_server_principal_name:' in msg:
        for line in msg.split('\n'):
            if 'session_server_principal_name:' in line:
                user = line.split(':')[-1].strip()
                if user:
                    return user
    return None


def get_sort_key(rule, sort_by):
    """Возвращает ключ для сортировки правила"""
    if sort_by == "severity":
        return SEVERITY_ORDER.get(rule.get('rule_level', 'informational').lower(), 99)
    elif sort_by == "count":
        return -rule.get('count', 0)          # по убыванию
    elif sort_by == "title":
        return rule.get('title', '').lower()
    elif sort_by == "computer":
        matches = rule.get('matches', [])
        return matches[0].get('Computer', 'N/A').lower() if matches else 'N/A'
    elif sort_by == "channel":
        matches = rule.get('matches', [])
        return matches[0].get('Channel', 'N/A').lower() if matches else 'N/A'
    elif sort_by == "eventid":
        matches = rule.get('matches', [])
        return matches[0].get('EventID', 999999) if matches else 999999
    return 0


def generate_report(zircolite_output_file, report_file=None, sort_by="severity"):
    if not os.path.exists(zircolite_output_file):
        print(f"Ошибка: Файл не найден: {zircolite_output_file}")
        return False
    
    with open(zircolite_output_file, 'r', encoding='utf-8') as f:
        results = json.load(f)
    
    if report_file is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"security_report_{timestamp}_{sort_by}.txt"
    
    if isinstance(results, list):
        results = sorted(results, key=lambda x: get_sort_key(x, sort_by))
    
    # Название сортировки для отчёта
    sort_display = SORT_DISPLAY_NAMES.get(sort_by, "По уровню критичности (Severity)")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("Отчет по инцидентам безопасности - Анализ Zircolite\n")
        f.write(f"Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Исходный файл: {zircolite_output_file}\n")
        f.write(f"Сортировка: {sort_display}\n\n")
        
        # === СВОДКА ===
        f.write("Статистика анализа\n")
        
        total_alerts = len(results) if isinstance(results, list) else 1
        levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        for rule in results if isinstance(results, list) else [results]:
            level = rule.get('rule_level', 'informational').lower()
            if level in levels:
                levels[level] += 1
        
        f.write(f"Всего срабатываний: {total_alerts}\n")
        f.write(f"Критические: {levels['critical']}\n")
        f.write(f"Высокие: {levels['high']}\n")
        f.write(f"Средние: {levels['medium']}\n")
        f.write(f"Низкие: {levels['low']}\n")
        f.write(f"Информационные: {levels['informational']}\n\n")
        
        # === ОБНАРУЖЕНИЯ ===
        f.write("Обнаруженные правила и признаки компроментации\n")
        
        for rule in results if isinstance(results, list) else [results]:
            rule_level = rule.get('rule_level', 'informational').lower()
            is_ioc = is_compromise_indicator(rule)

            f.write("-"* 50 + "\n\n")
            
            if is_ioc:
                f.write(f"Признак компроментации: {rule.get('title', 'N/A')} [{rule_level.upper()}]\n")
            else:
                f.write(f"Правило: {rule.get('title', 'N/A')} [{rule_level.upper()}]\n")
            
            f.write(f"ID: {rule.get('id', 'N/A')}\n")
            f.write(f"Описание: {rule.get('description', 'N/A')}\n")
            f.write(f"Количество срабатываний: {rule.get('count', 0)}\n")
            
            if is_ioc and rule.get('matches'):
                f.write(f"\n  ДОКАЗАТЕЛЬСТВА КОМПРОМЕТАЦИИ:\n")
                
                
                for idx, match in enumerate(rule.get('matches', [])[:15]):
                    f.write(f"\n  Доказательство #{idx + 1}:\n")
                    f.write(f"     EventID: {match.get('EventID', 'N/A')}\n")
                    f.write(f"     Время: {match.get('SystemTime', 'N/A')}\n")
                    f.write(f"     Компьютер: {match.get('Computer', 'N/A')}\n")
                    f.write(f"     Канал: {match.get('Channel', 'N/A')}\n")
                    
                    event_id = match.get('EventID')
                    msg = match.get('Message', '')
                    
                    if event_id == 33205:
                        if 'ALTER LOGIN [sa] ENABLE' in msg:
                            f.write(f"     Действие: Учётная запись SA включена - Повышение привилегий\n")
                        elif 'STATE = OFF' in msg:
                            f.write(f"     Действие: Аудит отключён - Сокрытие следов\n")
                        elif 'DROP' in msg:
                            f.write(f"     Действие: Аудит удалён - Сокрытие следов\n")
                    
                    elif event_id == 15457:
                        if 'xp_cmdshell' in msg and '1' in msg:
                            f.write(f"     Действие: xp_cmdshell включён - Выполнение команд\n")
                    
                    f.write(f"     Исходный файл: {match.get('OriginalLogfile', 'N/A')}\n")
                
                if len(rule.get('matches', [])) > 15:
                    f.write(f"\n  ... и ещё {len(rule.get('matches', [])) - 15} записей\n")
            
            f.write("\n")
        
        f.write("Конец отчета\n")
    
    print(f"Отчёт успешно создан: {report_file} (сортировка: {sort_by})")
    return True


def interactive_mode():
    """Интерактивный выбор сортировки"""
    print("Выберите способ сортировки отчёта:\n")
    print("  1) По уровню критичности (Severity)")
    print("  2) По количеству срабатываний (Count)")
    print("  3) По названию правила (Title)")
    print("  4) По компьютеру (Computer)")
    print("  5) По каналу событий (Channel)")
    print("  6) По EventID")

    
    choice = input("\nВаш выбор (1-6) [по умолчанию 1]: ").strip()
    mapping = {"1": "severity", "2": "count", "3": "title", 
               "4": "computer", "5": "channel", "6": "eventid"}
    return mapping.get(choice, "severity")


def main():
    if len(sys.argv) < 2:
        print("Использование: python report_generator_3_sections.py <zircolite_output.json> [output.txt] [--sort <тип>]")
        print("\nПример:")
        print("  python report_generator_3_sections.py results.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
    
    sort_by = "severity"
    
    if "--sort" in sys.argv:
        try:
            idx = sys.argv.index("--sort")
            sort_key = sys.argv[idx + 1].lower()
            if sort_key in SORT_DISPLAY_NAMES:
                sort_by = sort_key
        except:
            pass
    elif len(sys.argv) <= 3:   # интерактивный режим
        sort_by = interactive_mode()
    
    generate_report(input_file, output_file, sort_by)


if __name__ == "__main__":
    main()
