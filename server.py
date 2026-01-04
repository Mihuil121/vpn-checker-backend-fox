#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Локальный HTTP-сервер для раздачи VPN конфигураций
Генерирует ссылки вида: http://localhost:PORT/RU_Best/ru_universal.txt
"""

import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Настройки
BASE_DIR = "checked"
DEFAULT_PORT = 8000
HOST = "0.0.0.0"  # 0.0.0.0 = доступен извне, localhost = только локально


class VPNFileHandler(SimpleHTTPRequestHandler):
    """Обработчик запросов с поддержкой CORS и правильных заголовков"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)
    
    def end_headers(self):
        # Добавляем CORS заголовки для доступа из браузера
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()
    
    def send_error_utf8(self, code, message):
        """Отправка ошибки с UTF-8 кодировкой"""
        self.send_response(code)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        error_html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Error {code}</title>
</head>
<body>
    <h1>Error {code}</h1>
    <p>{message}</p>
</body>
</html>"""
        self.wfile.write(error_html.encode('utf-8'))
    
    def do_GET(self):
        """Обработка GET запросов"""
        # Убираем начальный слеш
        path = self.path.lstrip('/')
        
        # Игнорируем favicon.ico
        if path == 'favicon.ico':
            self.send_response(404)
            self.end_headers()
            return
        
        # Если корневой путь, показываем список файлов
        if path == '' or path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            html = self.generate_index_page()
            self.wfile.write(html.encode('utf-8'))
            return
        
        # Пытаемся найти файл
        file_path = Path(BASE_DIR) / path
        
        if file_path.exists() and file_path.is_file():
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error_utf8(500, f"Ошибка чтения файла: {e}")
        else:
            self.send_error_utf8(404, "Файл не найден")
    
    def do_OPTIONS(self):
        """Обработка OPTIONS для CORS"""
        self.send_response(200)
        self.end_headers()
    
    def generate_index_page(self):
        """Генерация HTML страницы со списком всех файлов"""
        html = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Configs Server</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; }}
        h2 {{ color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        .file-list {{ list-style: none; padding: 0; }}
        .file-item {{ margin: 10px 0; padding: 10px; background: #f9f9f9; border-radius: 4px; }}
        .file-link {{ color: #0066cc; text-decoration: none; font-weight: bold; }}
        .file-link:hover {{ text-decoration: underline; }}
        .file-path {{ color: #666; font-family: monospace; font-size: 0.9em; }}
        .copy-btn {{ margin-left: 10px; padding: 4px 8px; background: #28a745; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 0.85em; }}
        .copy-btn:hover {{ background: #218838; }}
        .info {{ background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡 VPN Configs Server</h1>
        <div class="info">
            <strong>Сервер работает на:</strong> <code>http://{host}:{port}</code><br>
            <strong>Базовая директория:</strong> <code>{base_dir}</code>
        </div>
"""
        
        # Находим все файлы
        files_by_category = {}
        base_path = Path(BASE_DIR)
        
        if base_path.exists():
            for folder in base_path.iterdir():
                if folder.is_dir():
                    category = folder.name
                    files_by_category[category] = []
                    
                    for file in folder.iterdir():
                        if file.is_file() and file.suffix == '.txt':
                            files_by_category[category].append(file.name)
        
        # Генерируем список файлов
        file_list_html = ""
        for category, files in sorted(files_by_category.items()):
            file_list_html += f'        <div class="section">\n'
            file_list_html += f'            <h2>📁 {category}</h2>\n'
            file_list_html += f'            <ul class="file-list">\n'
            
            for file in sorted(files):
                file_path = f"{category}/{file}"
                url = f"http://{self.server.server_name or 'localhost'}:{self.server.server_port}/{file_path}"
                file_list_html += f'                <li class="file-item">\n'
                file_list_html += f'                    <a href="/{file_path}" class="file-link">{file}</a>\n'
                file_list_html += f'                    <button class="copy-btn" onclick="copyLink(\'{url}\')">📋 Копировать ссылку</button>\n'
                file_list_html += f'                    <div class="file-path">{url}</div>\n'
                file_list_html += f'                </li>\n'
            
            file_list_html += f'            </ul>\n'
            file_list_html += f'        </div>\n'
        
        html += file_list_html
        
        html += """        <script>
            function copyLink(url) {{
                navigator.clipboard.writeText(url).then(function() {{
                    alert('Ссылка скопирована: ' + url);
                }}, function(err) {{
                    prompt('Скопируйте ссылку вручную:', url);
                }});
            }}
        </script>
    </div>
</body>
</html>"""
        
        host = self.server.server_name or 'localhost'
        port = self.server.server_port
        return html.format(host=host, port=port, base_dir=BASE_DIR)


def run_server(port=DEFAULT_PORT, host=HOST):
    """Запуск HTTP-сервера"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, VPNFileHandler)
    
    print("=" * 60)
    print("🚀 VPN Configs HTTP Server")
    print("=" * 60)
    print(f"📍 Сервер запущен на: http://localhost:{port}")
    print(f"📂 Базовая директория: {BASE_DIR}")
    print(f"🌐 Доступ извне: http://{host}:{port}")
    print("\n💡 Откройте браузер и перейдите по адресу выше")
    print("   Для остановки нажмите Ctrl+C")
    print("=" * 60)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n⚠️  Сервер остановлен")
        httpd.shutdown()
        sys.exit(0)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Локальный HTTP-сервер для VPN конфигураций')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                        help=f'Порт сервера (по умолчанию: {DEFAULT_PORT})')
    parser.add_argument('--host', type=str, default=HOST,
                        help=f'Хост (по умолчанию: {HOST})')
    
    args = parser.parse_args()
    
    # Проверяем существование директории
    if not os.path.exists(BASE_DIR):
        print(f"❌ Ошибка: директория '{BASE_DIR}' не найдена!")
        print(f"   Убедитесь, что вы запускаете скрипт из корня проекта")
        sys.exit(1)
    
    run_server(port=args.port, host=args.host)

