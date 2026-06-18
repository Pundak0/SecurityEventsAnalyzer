Инструменты для анализа и оценки сигнатур
Описание скриптов
1. evtx_parser.py
Назначение: Парсинг EVTX файлов и создание эталонного датасета.

Вход: Путь к папке с EVTX файлами

bash
python evtx_parser.py C:\EVTX_logs\
Выход: evtx_event_analysis.json - извлеченные события с полями из TARGET_FIELDS

2. extract_sigma_info.py
Назначение: Извлечение информации о сигнатурах из результатов Zircolite.

Вход: JSON файл с результатами Zircolite

bash
python extract_sigma_info.py result.json
Выход: result_sigma_info.json - структурированная информация о сигнатурах (EventID, SQL-запросы)

3. classification_evaluator.py
Назначение: Сравнение эталонных событий с результатами Zircolite, расчет TP/FP/FN и метрик (Precision, Recall, F1).

Требуемые файлы:

result.json - результат работы Zircolite

evtx_event_analysis.json - эталонный датасет

Запуск:

bash
python classification_evaluator.py
Выход:

classification_output.json - детальный отчет по каждому файлу

В консоль выводится статистика по каждому файлу и итоговые метрики

4. json_to_excel.py
Назначение: Преобразование JSON с классификацией в форматированную Excel таблицу.

Вход: JSON файл с классификацией (создается classification_evaluator.py)

Запуск:

bash
python json_to_excel.py
Выход: classification_results.xlsx - таблица с цветовым кодированием (TP - зеленый, FP - оранжевый, FN - красный)

Взаимосвязь скриптов

evtx_parser.py
      ↓
evtx_event_analysis.json (эталон)
      ↓
classification_evaluator.py ← result.json (Zircolite)
      ↓
classification_output.json (TP/FP/FN)
      ↓
json_to_excel.py
      ↓
classification_results.xlsx (Excel таблица)

extract_sigma_info.py (отдельно, для анализа правил)
      ↓
result_sigma_info.json

Требования
bash
pip install evtx pandas openpyxl