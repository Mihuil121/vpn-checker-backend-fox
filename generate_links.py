#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор локальных ссылок на VPN конфигурации
Создает файл со всеми ссылками для локального сервера
"""

import os
from pathlib import Path

# Настройки
BASE_DIR = "checked"
OUTPUT_FILE = "local_links.txt"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000


def generate_links(host=DEFAULT_HOST, port=DEFAULT_PORT):
    """Генерация списка локальных ссылок"""
    base_path = Path(BASE_DIR)
    
    if not base_path.exists():
        print(f"❌ Ошибка: директория '{BASE_DIR}' не найдена!")
        return
    
    links = []
    links.append("=" * 60)
    links.append("🔗 ЛОКАЛЬНЫЕ ССЫЛКИ НА VPN КОНФИГУРАЦИИ")
    links.append("=" * 60)
    links.append(f"🌐 Базовый URL: http://{host}:{port}")
    links.append(f"📂 Директория: {BASE_DIR}")
    links.append("")
    
    # Собираем все файлы по категориям
    files_by_category = {}
    
    for folder in base_path.iterdir():
        if folder.is_dir():
            category = folder.name
            files_by_category[category] = []
            
            for file in folder.iterdir():
                if file.is_file() and file.suffix == '.txt':
                    files_by_category[category].append(file.name)
    
    # Генерируем ссылки
    for category in sorted(files_by_category.keys()):
        links.append("")
        links.append(f"=== 📁 {category} ===")
        links.append("")
        
        for file in sorted(files_by_category[category]):
            file_path = f"{category}/{file}"
            url = f"http://{host}:{port}/{file_path}"
            links.append(url)
    
    links.append("")
    links.append("=" * 60)
    links.append("💡 Для использования:")
    links.append(f"   1. Запустите сервер: python server.py -p {port}")
    links.append(f"   2. Используйте ссылки выше в ваших VPN клиентах")
    links.append("=" * 60)
    
    # Сохраняем в файл
    content = "\n".join(links)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    
    print("✅ Файл с ссылками создан:", OUTPUT_FILE)
    print(f"📊 Найдено категорий: {len(files_by_category)}")
    
    total_files = sum(len(files) for files in files_by_category.values())
    print(f"📄 Всего файлов: {total_files}")
    print()
    print("🔗 Примеры ссылок:")
    print()
    
    # Показываем несколько примеров
    count = 0
    for category in sorted(files_by_category.keys()):
        if count >= 3:
            break
        for file in sorted(files_by_category[category])[:2]:
            file_path = f"{category}/{file}"
            url = f"http://{host}:{port}/{file_path}"
            print(f"   {url}")
            count += 1
            if count >= 3:
                break
    
    print()
    print(f"📝 Все ссылки сохранены в файл: {OUTPUT_FILE}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Генератор локальных ссылок на VPN конфигурации')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                        help=f'Порт сервера (по умолчанию: {DEFAULT_PORT})')
    parser.add_argument('--host', type=str, default=DEFAULT_HOST,
                        help=f'Хост (по умолчанию: {DEFAULT_HOST})')
    
    args = parser.parse_args()
    
    generate_links(host=args.host, port=args.port)


