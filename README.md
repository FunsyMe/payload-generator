<div align="center">

# **<img src="https://github.com/user-attachments/assets/7b6506b2-5cbb-47e6-baf6-be1c6db51724" height=28 /> <a href="https://github.com/FunsyMe/">FunsyMe</a><a href="https://github.com/FunsyMe/payload-generator">/payload-generator</a> <img src="https://github.com/user-attachments/assets/7b6506b2-5cbb-47e6-baf6-be1c6db51724" height=28 />**
</div>

> [!TIP]
> Данная утилита является форком к [payloadGen v0.9.1 by Ori](https://ntc.party/t/goodcheck-%D0%B1%D0%BB%D0%BE%D0%BA%D1%87%D0%B5%D0%BA-%D0%B4%D0%BB%D1%8F-gdpi-zapret-byedpi-%D0%B0%D0%BA%D1%82%D1%83%D0%B0%D0%BB%D1%8C%D0%BD%D0%B0%D1%8F-%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F-%D0%B2-%D0%BF%D1%80%D0%BE%D1%84%D0%B8%D0%BB%D0%B5/10880/1442).
> Вы можете связаться с оригинальным разработчиком утилиты тут: https://ntc.party/u/ori/

# ⚙️ ИСПОЛЬЗОВАНИЕ
1. Скачайте или скомпилируйте утилиту
    - Скачайте готовый исполняемый файл со страницы релизов
    - Скомпилируйте исполняемый файл вручную с помощью `go`
2. Запустите исполняемый файл

# 🛠️ ВОЗМОЖНОСТИ
- поддержка разных протоколов
  - `TLS CLIENT-HELLO` 
    - `TLS 1.2` - стандартный TLS 1.2
    - `TLS 1.3` - стандартный TLS 1.3
    - `TLS 1.3 → 1.2` - TLS 1.3 с фоллбэком TLS 1.2
  - `QUIC INITIAL`
- имитация браузеров (TLS CLIENT-HELLO, QUIC INITIAL)
- дробление фейков
- маскировка под определенный SNI
- возможность экспортирования в `.bin` файл

# ⚖️ ЛИЦЕНЗИЯ
Утилита распространяется на условиях [GNU](https://github.com/FunsyMe/payload-generator/blob/main/LICENSE) лицензии 
