#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import subprocess
import os
import sys
from datetime import datetime
import json
import threading

class SecurityAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Events Analyzer - Windows Logs Analysis Tool")
        self.root.geometry("950x850")
        self.root.resizable(True, True)
        
        self.input_path = tk.StringVar(value="")
        self.input_type = tk.StringVar(value="directory")
        self.sort_var = tk.StringVar(value="severity")
        self.rules_files = []
        self.output_json = None
        self.last_report = None
        self.is_running = False
        
        self.create_widgets()
        self.add_rules_file("rules/rules_windows_merged.json")
        self.log("Анализатор событий безопасности запущен")
        self.log("Готов к анализу файлов Windows Event Log (.evtx)")
        
    def create_widgets(self):
        source_frame = tk.LabelFrame(self.root, text="1. Выберите источник", padx=10, pady=10)
        source_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Radiobutton(source_frame, text="Один EVTX файл", variable=self.input_type, 
                       value="file", command=self.toggle_input_type).grid(row=0, column=0, padx=5, sticky=tk.W)
        tk.Radiobutton(source_frame, text="Папка (все EVTX файлы)", variable=self.input_type, 
                       value="directory", command=self.toggle_input_type).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        self.path_entry = tk.Entry(source_frame, textvariable=self.input_path, width=70)
        self.path_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        tk.Button(source_frame, text="Обзор...", command=self.browse_input).grid(row=1, column=2, padx=5)
        
        rules_frame = tk.LabelFrame(self.root, text="2. Правила обнаружения (можно выбрать несколько)", padx=10, pady=10)
        rules_frame.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = tk.Frame(rules_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(btn_frame, text="Добавить файл правил", command=self.add_rules_dialog, padx=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Удалить выбранные", command=self.remove_selected_rules, padx=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Просмотреть все правила", command=self.view_all_rules, padx=10).pack(side=tk.LEFT, padx=5)
        
        list_frame = tk.Frame(rules_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.rules_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, height=4, selectmode=tk.EXTENDED)
        self.rules_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.rules_listbox.yview)
        
        control_frame = tk.LabelFrame(self.root, text="3. Запуск анализа", padx=10, pady=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        sort_frame = tk.LabelFrame(control_frame, text="Сортировка отчета", padx=10, pady=5)
        sort_frame.pack(fill=tk.X, pady=5)
        
        row1 = tk.Frame(sort_frame)
        row1.pack()
        tk.Radiobutton(row1, text="1) По уровню критичности", variable=self.sort_var, value="severity").pack(side=tk.LEFT, padx=10, pady=2)
        tk.Radiobutton(row1, text="2) По количеству срабатываний", variable=self.sort_var, value="count").pack(side=tk.LEFT, padx=10, pady=2)
        tk.Radiobutton(row1, text="3) По названию правила", variable=self.sort_var, value="title").pack(side=tk.LEFT, padx=10, pady=2)
        
        row2 = tk.Frame(sort_frame)
        row2.pack()
        tk.Radiobutton(row2, text="4) По компьютеру", variable=self.sort_var, value="computer").pack(side=tk.LEFT, padx=10, pady=2)
        tk.Radiobutton(row2, text="5) По каналу событий", variable=self.sort_var, value="channel").pack(side=tk.LEFT, padx=10, pady=2)
        tk.Radiobutton(row2, text="6) По EventID", variable=self.sort_var, value="eventid").pack(side=tk.LEFT, padx=10, pady=2)
        
        button_frame = tk.Frame(control_frame)
        button_frame.pack(pady=10)
        
        self.run_button = tk.Button(button_frame, text="ЗАПУСТИТЬ АНАЛИЗ", command=self.run_analysis,
                                    bg="green", fg="white", font=("Arial", 10, "bold"), padx=20, pady=5)
        self.run_button.pack(side=tk.LEFT, padx=10)
        
        self.view_report_button = tk.Button(button_frame, text="Открыть отчет", command=self.open_report,
                                            state=tk.DISABLED, padx=20, pady=5)
        self.view_report_button.pack(side=tk.LEFT, padx=10)
        
        output_frame = tk.LabelFrame(self.root, text="4. Вывод анализа", padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.output = scrolledtext.ScrolledText(output_frame, width=100, height=25,
                                                  font=("Consolas", 9), wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)
        
        self.status_bar = tk.Label(self.root, text="Готов", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def toggle_input_type(self):
        self.input_path.set("")
        self.path_entry.delete(0, tk.END)
        
    def browse_input(self):
        if self.input_type.get() == "file":
            filename = filedialog.askopenfilename(
                title="Выберите файл Windows Event Log",
                filetypes=[("Windows Event Log", "*.evtx"), ("Все файлы", "*.*")]
            )
            if filename:
                self.input_path.set(filename)
                self.log(f"Выбран файл: {filename}")
        else:
            directory = filedialog.askdirectory(
                title="Выберите папку с EVTX файлами"
            )
            if directory:
                self.input_path.set(directory)
                self.log(f"Выбрана папка: {directory}")
                
    def add_rules_dialog(self):
        filename = filedialog.askopenfilename(
            title="Выберите файл правил Sigma",
            filetypes=[("JSON rules", "*.json"), ("Все файлы", "*.*")]
        )
        if filename:
            self.add_rules_file(filename)
            
    def add_rules_file(self, filepath):
        if filepath not in self.rules_files:
            if os.path.exists(filepath):
                self.rules_files.append(filepath)
                self.rules_listbox.insert(tk.END, filepath)
                self.log(f"Добавлен файл правил: {filepath}")
            else:
                self.log(f"Файл правил не найден: {filepath}", "ПРЕДУПРЕЖДЕНИЕ")
                
    def remove_selected_rules(self):
        selected = self.rules_listbox.curselection()
        for i in reversed(selected):
            filepath = self.rules_listbox.get(i)
            self.rules_files.remove(filepath)
            self.rules_listbox.delete(i)
            self.log(f"Удален файл правил: {filepath}")
            
    def view_all_rules(self):
        if not self.rules_files:
            self.log("Нет загруженных файлов правил", "ПРЕДУПРЕЖДЕНИЕ")
            return
            
        self.log("ВСЕ ПРАВИЛА ОБНАРУЖЕНИЯ")
        
        for rules_file in self.rules_files:
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                self.log(f"\nФайл: {os.path.basename(rules_file)} ({len(rules)} правил)")
                for i, rule in enumerate(rules[:20], 1):
                    level = rule.get('level', rule.get('rule_level', 'N/A')).upper()
                    title = rule.get('title', 'N/A')
                    self.log(f"  {i:3}. [{level:12}] {title}")
                if len(rules) > 20:
                    self.log(f"  ... и ещё {len(rules) - 20} правил")
            except Exception as e:
                self.log(f"Ошибка чтения {rules_file}: {e}", "ОШИБКА")
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
        self.output.see(tk.END)
        self.root.update()
        
    def run_analysis(self):
        if self.is_running:
            self.log("Анализ уже выполняется...", "ПРЕДУПРЕЖДЕНИЕ")
            return
            
        if not self.input_path.get():
            messagebox.showerror("Ошибка", "Выберите EVTX файл или папку!")
            return
            
        if not os.path.exists(self.input_path.get()):
            messagebox.showerror("Ошибка", f"Путь не найден: {self.input_path.get()}")
            return
            
        if not self.rules_files:
            messagebox.showerror("Ошибка", "Добавьте хотя бы один файл правил!")
            return
            
        thread = threading.Thread(target=self._run_analysis_thread, daemon=True)
        thread.start()
        
    def _run_analysis_thread(self):
        self.is_running = True
        self.run_button.config(state=tk.DISABLED, text="ВЫПОЛНЕНИЕ...")
        self.view_report_button.config(state=tk.DISABLED)
        self.status_bar.config(text="Выполнение анализа...")
        
        self.log("ЗАПУСК АНАЛИЗА")
        self.log(f"Источник: {self.input_path.get()}")
        self.log(f"Файлы правил ({len(self.rules_files)}):")
        for rf in self.rules_files:
            self.log(f"  - {rf}")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_json = f"zircolite_{timestamp}.json"
            
            self.log("")
            self.log("[1/2] Запуск Zircolite...")
            
            cmd = [sys.executable, "zircolite.py", "--evtx", self.input_path.get(), "--outfile", self.output_json]
            
            for rules_file in self.rules_files:
                cmd.extend(["--ruleset", rules_file])
            
            if self.input_type.get() == "directory":
                cmd.append("--fileext")
                cmd.append("evtx")
            
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1
            )
            
            for line in process.stdout:
                self.output.insert(tk.END, line)
                self.output.see(tk.END)
                self.root.update()
            
            process.wait()
            
            if process.returncode != 0:
                self.log(f"Zircolite завершился с ошибками (код: {process.returncode})", "ПРЕДУПРЕЖДЕНИЕ")
            else:
                self.log("Zircolite успешно завершен")
                
            if not os.path.exists(self.output_json):
                self.log("ОШИБКА: Файл с результатами не создан!", "ОШИБКА")
                return
            
            self.log("")
            self.log("[2/2] Формирование отчета...")
            
            sort_by = self.sort_var.get()
            sort_names = {
                "severity": "по уровню критичности",
                "count": "по количеству срабатываний", 
                "title": "по названию правила",
                "computer": "по компьютеру",
                "channel": "по каналу событий",
                "eventid": "по EventID"
            }
            self.log(f"Сортировка отчета: {sort_names.get(sort_by, sort_by)}")
            
            report_generator_found = False
            
            for gen_name in ["report_generator", "report_generator_3_sections", "report_generatort"]:
                try:
                    gen_module = __import__(gen_name)
                    generate_report_func = getattr(gen_module, 'generate_report')
                    self.last_report = f"security_report_{timestamp}.txt"
                    generate_report_func(self.output_json, self.last_report, sort_by)
                    self.log(f"Отчет создан: {self.last_report}")
                    report_generator_found = True
                    break
                except ImportError:
                    continue
                except Exception as e:
                    self.log(f"Ошибка с {gen_name}: {e}", "ПРЕДУПРЕЖДЕНИЕ")
                    continue
            
            if not report_generator_found:
                self.log("ОШИБКА: Не найден модуль report_generator!", "ОШИБКА")
                return
            
            self.log("")
            self.log("ОБНАРУЖЕННЫЕ ПРИЗНАКИ КОМПРОМЕТАЦИИ")
            try:
                with open(self.output_json, 'r', encoding='utf-8') as f:
                    results = json.load(f)
                
                ioc_count = 0
                for rule in results:
                    level = rule.get('rule_level', '').lower()
                    if level in ['critical', 'high', 'medium'] and rule.get('count', 0) > 0:
                        ioc_count += 1
                        level_ru = {"critical": "КРИТИЧНЫЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ"}.get(level, level.upper())
                        self.log(f"[{level_ru}] {rule.get('title', 'N/A')} - {rule.get('count', 0)} совпадений")
                
                if ioc_count == 0:
                    self.log("Признаки компрометации не обнаружены")
            except Exception as e:
                self.log(f"Не удалось прочитать результаты: {e}")
            
            self.log("")
            self.log("АНАЛИЗ ЗАВЕРШЕН")
            
            self.view_report_button.config(state=tk.NORMAL)
            self.status_bar.config(text="Анализ завершен")
            
        except Exception as e:
            self.log(f"Ошибка: {str(e)}", "ОШИБКА")
            self.status_bar.config(text="Ошибка")
            
        finally:
            self.is_running = False
            self.run_button.config(state=tk.NORMAL, text="ЗАПУСТИТЬ АНАЛИЗ")
            self.output.see(tk.END)
            
    def open_report(self):
        if self.last_report and os.path.exists(self.last_report):
            os.startfile(self.last_report)
            self.log(f"Открыт отчет: {self.last_report}")
        else:
            self.log("Отчет не найден. Сначала выполните анализ.", "ПРЕДУПРЕЖДЕНИЕ")


def main():
    root = tk.Tk()
    app = SecurityAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
