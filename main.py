"""
SCmess — E2E-зашифрованный мессенджер
Клиент: Kivy + Python
Крипто: RSA-4096 + AES-256-GCM (сервер видит только зашифрованные блобы)
Протокол: WebSocket JSON
"""

import os, io, json, base64, threading, hashlib, time, sqlite3, re
from datetime import datetime

from kivy.config import Config
Config.set("graphics", "maxfps", "120")
Config.set("kivy", "allow_screensaver", "0")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kivy.app import App
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.uix.screenmanager import ScreenManager, Screen, NoTransition, SlideTransition
from kivy.uix.modalview import ModalView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.clock import Clock
from kivy.utils import platform
from kivy.properties import (
    ObjectProperty, StringProperty, BooleanProperty,
    ListProperty, DictProperty, NumericProperty,
)
from kivy.metrics import dp
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line, Ellipse

if platform == "android":
    try:
        from android import activity as _android_activity
        from jnius import autoclass as _autoclass, cast as _cast
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
# ТЕМА
# ─────────────────────────────────────────────────────────────
DEFAULT_THEME = {
    "bg_color":      [0.00, 0.00, 0.00, 1],
    "btn_bg":        [0.10, 0.10, 0.13, 1],
    "btn_border":    [0.25, 0.45, 0.85, 1],
    "btn_text":      [1,    1,    1,    1],
    "accent":        [0.25, 0.45, 0.85, 1],
    "input_bg":      [0.07, 0.07, 0.10, 1],
    "input_fg":      [0.92, 0.92, 0.95, 1],
    "title_color":   [0.30, 0.60, 1.00, 1],
    "label_muted":   [0.50, 0.50, 0.60, 1],
    "danger_bg":     [0.70, 0.15, 0.15, 1],
    "success_bg":    [0.15, 0.55, 0.25, 1],
    "log_bg":        [0.04, 0.04, 0.06, 1],
    "bubble_out":    [0.15, 0.28, 0.55, 1],   # мои сообщения
    "bubble_in":     [0.11, 0.11, 0.15, 1],   # входящие
    "online_dot":    [0.20, 0.85, 0.40, 1],
    "offline_dot":   [0.40, 0.40, 0.50, 1],
    "chat_list_sep": [0.10, 0.10, 0.14, 1],
}

SETTINGS_FILE = None

# ─────────────────────────────────────────────────────────────
# KV — разметка всех экранов
# ─────────────────────────────────────────────────────────────
KV = """
#:import dp kivy.metrics.dp

# ── Базовые виджеты ─────────────────────────────────────────

<StyledButton@Button>:
    background_normal: ''
    background_color: 0,0,0,0
    color: app.theme['btn_text']
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: app.theme['btn_border']
        RoundedRectangle:
            pos: self.x, self.y
            size: self.width, self.height
            radius: [8]
        Color:
            rgba: app.theme['btn_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [7]

<DangerButton@Button>:
    background_normal: ''
    background_color: 0,0,0,0
    color: 1,1,1,1
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: 1,0.3,0.3,0.8
        RoundedRectangle:
            pos: self.x, self.y
            size: self.width, self.height
            radius: [8]
        Color:
            rgba: app.theme['danger_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [7]

<StyledInput@TextInput>:
    background_color: app.theme['input_bg']
    foreground_color: app.theme['input_fg']
    cursor_color: app.theme['accent']
    font_size: '15sp'
    padding: [12,10,12,10]
    hint_text_color: 0.40,0.40,0.55,1
    use_bubble: False
    use_handles: False

<SectionLabel@Label>:
    font_size: '12sp'
    color: app.theme['label_muted']
    size_hint_y: None
    height: dp(22)
    halign: 'left'
    text_size: self.width, None

# ── Экраны ──────────────────────────────────────────────────

# ЭКРАН: Загрузка / выбор аккаунта
<LaunchScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(30), dp(60), dp(30), dp(40)]
        spacing: dp(16)
        Widget:
            size_hint_y: 0.15
        Label:
            text: 'SCmess'
            font_size: '42sp'
            bold: True
            color: app.theme['title_color']
            size_hint_y: None
            height: dp(60)
        Label:
            text: 'E2E зашифрованный мессенджер'
            font_size: '14sp'
            color: app.theme['label_muted']
            size_hint_y: None
            height: dp(28)
        Widget:
            size_hint_y: 0.1
        BoxLayout:
            id: accounts_box
            orientation: 'vertical'
            spacing: dp(8)
            size_hint_y: None
            height: self.minimum_height
        Widget:
            size_hint_y: None
            height: dp(16)
        StyledButton:
            text: '+ Создать аккаунт'
            size_hint_y: None
            height: dp(52)
            on_release: root.open_create_account()
        Widget:
            size_hint_y: 0.2

# ЭКРАН: Создание аккаунта
<CreateAccountScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(24), dp(24), dp(24), dp(20)]
        spacing: dp(12)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Button:
                text: '← Назад'
                size_hint_x: None
                width: dp(90)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '15sp'
                on_release: root.manager.current = 'launch'
            Label:
                text: 'Новый аккаунт'
                font_size: '20sp'
                bold: True
                color: app.theme['title_color']
        SectionLabel:
            text: 'Имя пользователя (видно другим):'
        StyledInput:
            id: username_inp
            hint_text: '@username'
            size_hint_y: None
            height: dp(48)
            multiline: False
        SectionLabel:
            text: 'Размер RSA-ключа:'
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            ToggleKeySize:
                id: key_2048
                text: '2048 бит'
                group: 'keysize'
                state: 'normal'
                on_release: root.select_keysize(2048)
            ToggleKeySize:
                id: key_4096
                text: '4096 бит (рекомендуется)'
                group: 'keysize'
                state: 'down'
                on_release: root.select_keysize(4096)
        SectionLabel:
            text: 'Авторизация: по приватному ключу (ключ хранится только у вас)'
            color: app.theme['accent']
        Widget:
            size_hint_y: None
            height: dp(8)
        StyledButton:
            text: 'Создать аккаунт'
            size_hint_y: None
            height: dp(52)
            on_release: root.do_create()
        Label:
            id: status_lbl
            text: ''
            color: app.theme['label_muted']
            font_size: '13sp'
            size_hint_y: None
            height: dp(32)
            halign: 'center'
            text_size: self.width, None
        Widget:

<ToggleKeySize@Button>:
    background_normal: ''
    background_color: 0,0,0,0
    color: app.theme['btn_text']
    font_size: '13sp'
    group: ''
    state: 'normal'
    canvas.before:
        Color:
            rgba: app.theme['accent'] if self.state=='down' else app.theme['btn_bg']
        RoundedRectangle:
            pos: self.x, self.y
            size: self.width, self.height
            radius: [7]

# ЭКРАН: Настройки подключения
<ServerScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(24), dp(24), dp(24), dp(20)]
        spacing: dp(12)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Button:
                text: '← Назад'
                size_hint_x: None
                width: dp(90)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '15sp'
                on_release: root.go_back()
            Label:
                text: 'Сервер'
                font_size: '20sp'
                bold: True
                color: app.theme['title_color']
        # Статус
        BoxLayout:
            size_hint_y: None
            height: dp(42)
            spacing: dp(10)
            padding: [dp(12),dp(8),dp(12),dp(8)]
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [8]
            Label:
                id: conn_status
                text: 'Нет подключения'
                color: app.theme['label_muted']
                font_size: '13sp'
                halign: 'left'
                text_size: self.width, None
        SectionLabel:
            text: 'IP или домен сервера:'
        StyledInput:
            id: host_inp
            hint_text: '192.168.1.100  или  example.com'
            size_hint_y: None
            height: dp(48)
            multiline: False
        SectionLabel:
            text: 'Порт:'
        StyledInput:
            id: port_inp
            hint_text: '8765'
            input_filter: 'int'
            size_hint_y: None
            height: dp(48)
            multiline: False
        StyledButton:
            text: 'Подключиться'
            size_hint_y: None
            height: dp(52)
            on_release: root.do_connect()
        StyledButton:
            text: 'Отключиться'
            size_hint_y: None
            height: dp(44)
            on_release: root.do_disconnect()
        Widget:
            size_hint_y: None
            height: dp(8)
        SectionLabel:
            text: 'Что хранит сервер:'
            color: app.theme['accent']
        Label:
            text: '• Имя пользователя и публичный ключ\\n• Зашифрованные сообщения (нечитаемые)\\n• Метаданные: время, отправитель, получатель\\n\\nСервер НЕ видит содержимое сообщений.'
            font_size: '12sp'
            color: app.theme['label_muted']
            size_hint_y: None
            height: dp(110)
            halign: 'left'
            valign: 'top'
            text_size: self.width, None
        Widget:

# ЭКРАН: Список чатов (главный)
<ChatsScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        # Шапка
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            padding: [dp(16), dp(8), dp(8), dp(8)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            Label:
                text: 'SCmess'
                font_size: '22sp'
                bold: True
                color: app.theme['title_color']
                size_hint_x: 1
                halign: 'left'
                text_size: self.width, None
            # Иконка статуса сети
            Label:
                id: net_badge
                text: '●'
                font_size: '14sp'
                color: app.theme['offline_dot']
                size_hint_x: None
                width: dp(24)
            Button:
                text: '✎'
                size_hint_x: None
                width: dp(44)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '22sp'
                on_release: root.new_chat_dialog()
            Button:
                text: '⋮'
                size_hint_x: None
                width: dp(40)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['btn_text']
                font_size: '22sp'
                on_release: root.open_menu()
        # Поиск
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            padding: [dp(12), dp(6), dp(12), dp(6)]
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            TextInput:
                id: search_inp
                hint_text: '🔍  Поиск'
                background_color: 0,0,0,0
                foreground_color: app.theme['input_fg']
                hint_text_color: 0.4,0.4,0.5,1
                font_size: '15sp'
                use_bubble: False
                use_handles: False
                multiline: False
                on_text: root.on_search(self.text)
        # Список чатов
        ScrollView:
            id: chats_scroll
            BoxLayout:
                id: chats_list
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
        # Нижняя панель
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            Button:
                text: '💬'
                font_size: '22sp'
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
            Button:
                text: '🔑'
                font_size: '22sp'
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['label_muted']
                on_release: root.manager.current = 'keys'
            Button:
                text: '⚙'
                font_size: '22sp'
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['label_muted']
                on_release: root.manager.current = 'server'

# ЭКРАН: Открытый чат
<ChatScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        # Шапка чата
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            padding: [dp(8), dp(8), dp(8), dp(8)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            Button:
                text: '←'
                size_hint_x: None
                width: dp(40)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '22sp'
                on_release: root.go_back()
            # Аватар
            Widget:
                id: avatar_widget
                size_hint_x: None
                width: dp(40)
            BoxLayout:
                orientation: 'vertical'
                Label:
                    id: peer_name_lbl
                    text: ''
                    font_size: '16sp'
                    bold: True
                    color: app.theme['btn_text']
                    halign: 'left'
                    text_size: self.width, None
                Label:
                    id: peer_status_lbl
                    text: ''
                    font_size: '11sp'
                    color: app.theme['label_muted']
                    halign: 'left'
                    text_size: self.width, None
            Button:
                text: '⋮'
                size_hint_x: None
                width: dp(36)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['btn_text']
                font_size: '20sp'
                on_release: root.open_chat_menu()
        # Сообщения
        ScrollView:
            id: msg_scroll
            do_scroll_x: False
            BoxLayout:
                id: msg_list
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                padding: [dp(8), dp(8), dp(8), dp(8)]
                spacing: dp(6)
        # Поле ввода
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            padding: [dp(8), dp(6), dp(8), dp(6)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            TextInput:
                id: msg_inp
                hint_text: 'Сообщение...'
                background_color: app.theme['input_bg']
                foreground_color: app.theme['input_fg']
                hint_text_color: 0.4,0.4,0.5,1
                font_size: '15sp'
                use_bubble: False
                use_handles: False
                multiline: False
                cursor_color: app.theme['accent']
                padding: [12,10,12,10]
                on_text_validate: root.send_message()
            Button:
                text: '➤'
                size_hint_x: None
                width: dp(44)
                background_normal: ''
                background_color: app.theme['accent']
                color: 1,1,1,1
                font_size: '20sp'
                bold: True
                on_release: root.send_message()

# ЭКРАН: Управление ключами
<KeysScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(16), dp(16), dp(16), dp(12)]
        spacing: dp(10)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Button:
                text: '← Назад'
                size_hint_x: None
                width: dp(90)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '15sp'
                on_release: root.manager.current = 'chats'
            Label:
                text: 'Ключи'
                font_size: '20sp'
                bold: True
                color: app.theme['title_color']
        Label:
            id: my_key_label
            text: 'Мой аккаунт: загружается...'
            font_size: '13sp'
            color: app.theme['accent']
            size_hint_y: None
            height: dp(28)
            halign: 'left'
            text_size: self.width, None
        StyledButton:
            text: 'Скопировать мой публичный ключ'
            size_hint_y: None
            height: dp(48)
            on_release: root.copy_my_pubkey()
        StyledButton:
            text: 'Экспортировать ключи (резервная копия)'
            size_hint_y: None
            height: dp(44)
            on_release: root.export_keys()
        Widget:
            size_hint_y: None
            height: dp(4)
        SectionLabel:
            text: 'Контакты и их ключи:'
        ScrollView:
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [8]
            BoxLayout:
                id: contacts_list
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                padding: [dp(6), dp(6), dp(6), dp(6)]
                spacing: dp(4)
        Widget:
"""

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def show_msg(title, text):
    app = App.get_running_app()
    t = app.theme
    mv = ModalView(size_hint=(0.88, None), height=dp(200),
                   background_color=[0,0,0,0], auto_dismiss=True)
    card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(8))
    with card.canvas.before:
        Color(*t["input_bg"])
        RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
    card.bind(pos=lambda i,_: _redraw_card(i), size=lambda i,_: _redraw_card(i))

    def _redraw_card(inst):
        inst.canvas.before.clear()
        with inst.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])

    card.add_widget(Label(text=title, font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(28)))
    body = Label(text=text, font_size="14sp", color=t["input_fg"],
                 size_hint_y=None, halign="left", valign="top")
    body.bind(width=lambda i,_: setattr(i,"text_size",(i.width,None)),
              texture_size=lambda i,ts: setattr(i,"height",max(ts[1],dp(18))))
    card.add_widget(body)
    ok = Button(text="OK", size_hint_y=None, height=dp(40),
                background_normal="", background_color=[0,0,0,0],
                color=t["accent"], bold=True, font_size="15sp")
    ok.bind(on_release=mv.dismiss)
    card.add_widget(ok)
    mv.add_widget(card)

    def _fix(dt):
        bh = body.texture_size[1] if body.texture else dp(20)
        mv.height = dp(16) + dp(28) + dp(8) + bh + dp(8) + dp(40) + dp(16)
    Clock.schedule_once(_fix, 0)
    mv.open()


def show_confirm(title, text, on_yes, yes_label="Да", no_label="Отмена"):
    app = App.get_running_app()
    t = app.theme
    mv = ModalView(size_hint=(0.85, None), height=dp(180),
                   background_color=[0,0,0,0], auto_dismiss=True)
    card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
    with card.canvas.before:
        Color(*t["input_bg"])
        RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
    card.bind(pos=lambda i,_: _r(i), size=lambda i,_: _r(i))
    def _r(inst):
        inst.canvas.before.clear()
        with inst.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])
    card.add_widget(Label(text=title, font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(28)))
    card.add_widget(Label(text=text, font_size="13sp", color=t["input_fg"],
                          size_hint_y=None, height=dp(48),
                          halign="center", valign="middle",
                          text_size=(Window.width*0.75, None)))
    row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(12))
    yes_btn = Button(text=yes_label, background_normal="",
                     background_color=t["accent"], color=[1,1,1,1],
                     bold=True)
    no_btn = Button(text=no_label, background_normal="",
                    background_color=t["btn_bg"], color=t["btn_text"])
    def _yes(_):
        mv.dismiss()
        on_yes()
    yes_btn.bind(on_release=_yes)
    no_btn.bind(on_release=mv.dismiss)
    row.add_widget(yes_btn); row.add_widget(no_btn)
    card.add_widget(row)
    mv.add_widget(card)
    mv.open()


def make_avatar(name: str, size=dp(40)):
    """Виджет-аватар с инициалами и цветом из хеша имени."""
    colors = [
        [0.20, 0.40, 0.80],[0.70, 0.20, 0.50],[0.15, 0.60, 0.40],
        [0.60, 0.35, 0.10],[0.40, 0.15, 0.75],[0.10, 0.50, 0.65],
    ]
    h = int(hashlib.md5(name.encode()).hexdigest()[:4], 16)
    color = colors[h % len(colors)]
    initials = "".join(w[0].upper() for w in name.split() if w)[:2] or "?"

    w = Widget(size_hint=(None, None), size=(size, size))
    with w.canvas:
        Color(*color)
        Ellipse(pos=w.pos, size=w.size)
    lbl = Label(text=initials, font_size="14sp", bold=True, color=[1,1,1,1],
                size=w.size, pos=w.pos)
    w.add_widget(lbl)

    def _upd(inst, val):
        inst.canvas.clear()
        with inst.canvas:
            Color(*color)
            Ellipse(pos=inst.pos, size=inst.size)
        lbl.pos = inst.pos
        lbl.size = inst.size
    w.bind(pos=_upd, size=_upd)
    return w


# ─────────────────────────────────────────────────────────────
# КРИПТО БЭКЕНД (оригинальный, слегка расширенный)
# ─────────────────────────────────────────────────────────────

class CryptoBackend:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.keys_file = os.path.join(data_dir, "keys.json")
        self.keys_dir  = os.path.join(data_dir, "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        if not os.path.exists(self.keys_file):
            with open(self.keys_file, "w") as f:
                json.dump([], f)

    # ── Пользователи ────────────────────────────────────────
    def load_users(self):
        try:
            with open(self.keys_file) as f:
                return json.load(f)
        except Exception:
            return []

    def save_users(self, data):
        with open(self.keys_file, "w") as f:
            json.dump(data, f, indent=2)

    def get_my_account(self):
        """Возвращает первого пользователя у которого есть и pub и priv ключ."""
        for u in self.load_users():
            if u.get("public_key_path") and u.get("private_key_path"):
                return u
        return None

    def get_contact(self, username):
        for u in self.load_users():
            if u["username"] == username:
                return u
        return None

    def add_contact(self, username, pubkey_pem: str):
        """Добавить/обновить контакт с публичным ключом (PEM-строка)."""
        data = self.load_users()
        user = next((u for u in data if u["username"] == username), None)
        if not user:
            user = {"username": username}
            data.append(user)
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        path = os.path.join(self.keys_dir, f"pub_{username}_{ts}.pem")
        with open(path, "w") as f:
            f.write(pubkey_pem)
        user["public_key_path"] = path
        self.save_users(data)
        return user

    def generate_key_pair(self, username, key_size=4096):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        priv_f = os.path.join(self.keys_dir, f"RSA_{username}_priv_{ts}.pem")
        pub_f  = os.path.join(self.keys_dir, f"RSA_{username}_pub_{ts}.pem")
        pk = rsa.generate_private_key(65537, key_size, default_backend())
        with open(priv_f, "wb") as f:
            f.write(pk.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        pub_pem = pk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(pub_f, "wb") as f:
            f.write(pub_pem)
        data = self.load_users()
        # Удалим старый аккаунт с тем же именем если есть
        data = [u for u in data if u["username"] != username]
        data.insert(0, {"username": username,
                         "public_key_path": pub_f,
                         "private_key_path": priv_f})
        self.save_users(data)
        return pub_pem.decode()

    def delete_user(self, username):
        users = self.load_users()
        new_users = []
        for u in users:
            if u["username"] == username:
                for k in ["public_key_path","private_key_path"]:
                    p = u.get(k)
                    if p and os.path.exists(p):
                        try: os.remove(p)
                        except: pass
            else:
                new_users.append(u)
        self.save_users(new_users)

    # ── Крипто ──────────────────────────────────────────────
    @staticmethod
    def _oaep():
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)

    def encrypt_for(self, pub_key_path: str, plaintext: str) -> dict:
        """RSA+AES-256-GCM. Возвращает dict для JSON-сериализации."""
        aes_key = os.urandom(32)
        iv      = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv),
                     default_backend()).encryptor()
        ct = enc.update(plaintext.encode("utf-8")) + enc.finalize()
        with open(pub_key_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        enc_key = pub.encrypt(aes_key, self._oaep())
        return {
            "v":          2,
            "aes_key":    base64.b64encode(enc_key).decode(),
            "iv":         base64.b64encode(iv).decode(),
            "tag":        base64.b64encode(enc.tag).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }

    def decrypt_payload(self, priv_key_path: str, payload: dict) -> str:
        enc_key = base64.b64decode(payload["aes_key"])
        iv      = base64.b64decode(payload["iv"])
        tag     = base64.b64decode(payload["tag"])
        ct      = base64.b64decode(payload["ciphertext"])
        with open(priv_key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), None, default_backend())
        aes_key = priv.decrypt(enc_key, self._oaep())
        dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag),
                     default_backend()).decryptor()
        return (dec.update(ct) + dec.finalize()).decode("utf-8")

    def pubkey_pem(self, pub_key_path: str) -> str:
        with open(pub_key_path) as f:
            return f.read()

    def pubkey_fingerprint(self, pub_key_path: str) -> str:
        with open(pub_key_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        der = pub.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
        h = hashlib.sha256(der).hexdigest()[:16].upper()
        return ":".join(h[i:i+2] for i in range(0,16,2))


# ─────────────────────────────────────────────────────────────
# ЛОКАЛЬНАЯ БД СООБЩЕНИЙ (SQLite)
# ─────────────────────────────────────────────────────────────

class MessageDB:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "messages.db")
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer TEXT NOT NULL,
                direction TEXT NOT NULL,  -- 'out' | 'in'
                text TEXT NOT NULL,
                ts INTEGER NOT NULL,
                status TEXT DEFAULT 'sent',  -- sent|delivered|read
                server_id TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS chats (
                peer TEXT PRIMARY KEY,
                last_msg TEXT,
                last_ts INTEGER,
                unread INTEGER DEFAULT 0
            )""")

    def add_message(self, peer, direction, text, ts=None, status="sent", server_id=None):
        ts = ts or int(time.time()*1000)
        with self._conn() as c:
            c.execute("INSERT INTO messages (peer,direction,text,ts,status,server_id) "
                      "VALUES (?,?,?,?,?,?)",
                      (peer, direction, text, ts, status, server_id))
            c.execute("INSERT OR REPLACE INTO chats (peer,last_msg,last_ts,unread) "
                      "VALUES (?,?,?, COALESCE((SELECT unread FROM chats WHERE peer=?),0)"
                      " + CASE ? WHEN 'in' THEN 1 ELSE 0 END)",
                      (peer, text[:60], ts, peer, direction))
        return ts

    def get_messages(self, peer, limit=200):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM messages WHERE peer=? ORDER BY ts ASC LIMIT ?",
                             (peer, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_chats(self):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM chats ORDER BY last_ts DESC").fetchall()
        return [dict(r) for r in rows]

    def mark_read(self, peer):
        with self._conn() as c:
            c.execute("UPDATE chats SET unread=0 WHERE peer=?", (peer,))

    def update_status(self, server_id, status):
        with self._conn() as c:
            c.execute("UPDATE messages SET status=? WHERE server_id=?",
                      (status, server_id))

    def delete_chat(self, peer):
        with self._conn() as c:
            c.execute("DELETE FROM messages WHERE peer=?", (peer,))
            c.execute("DELETE FROM chats WHERE peer=?", (peer,))


# ─────────────────────────────────────────────────────────────
# WS КЛИЕНТ (без внешних зависимостей — используем socket напрямую)
# ─────────────────────────────────────────────────────────────

import socket
import struct

class WSClient:
    """
    Минималистичный WebSocket-клиент без внешних библиотек.
    Реализует WS handshake + framing (RFC 6455).
    """
    def __init__(self):
        self._sock = None
        self._lock = threading.Lock()
        self.connected = False
        self._recv_thread = None
        self.on_message = None   # callback(dict)
        self.on_connect = None
        self.on_disconnect = None

    def connect(self, host, port, path="/"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, int(port)))
            # WS Handshake
            key = base64.b64encode(os.urandom(16)).decode()
            hs = (f"GET {path} HTTP/1.1\r\n"
                  f"Host: {host}:{port}\r\n"
                  f"Upgrade: websocket\r\n"
                  f"Connection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\n"
                  f"Sec-WebSocket-Version: 13\r\n\r\n")
            s.sendall(hs.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += s.recv(1)
            if b"101" not in resp:
                raise ConnectionError("WS handshake failed")
            s.settimeout(None)
            self._sock = s
            self.connected = True
            if self.on_connect:
                Clock.schedule_once(lambda dt: self.on_connect(), 0)
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            return True
        except Exception as e:
            self.connected = False
            raise e

    def _recv_loop(self):
        try:
            while self.connected:
                frame = self._read_frame()
                if frame is None:
                    break
                try:
                    msg = json.loads(frame)
                    if self.on_message:
                        Clock.schedule_once(lambda dt, m=msg: self.on_message(m), 0)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            self.connected = False
            if self.on_disconnect:
                Clock.schedule_once(lambda dt: self.on_disconnect(), 0)

    def _read_frame(self):
        def recv_exact(n):
            buf = b""
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    return None
                buf += chunk
            return buf

        header = recv_exact(2)
        if not header: return None
        b1, b2 = header
        opcode = b1 & 0x0F
        if opcode == 8: return None  # close
        masked = (b2 & 0x80) != 0
        length = b2 & 0x7F
        if length == 126:
            ext = recv_exact(2)
            if not ext: return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = recv_exact(8)
            if not ext: return None
            length = struct.unpack("!Q", ext)[0]
        mask = recv_exact(4) if masked else None
        data = recv_exact(length)
        if data is None: return None
        if masked:
            data = bytes(b ^ mask[i%4] for i,b in enumerate(data))
        return data.decode("utf-8", errors="replace")

    def send(self, data: dict):
        if not self.connected or not self._sock:
            return False
        try:
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            length = len(payload)
            # Client always masks
            mask = os.urandom(4)
            masked_payload = bytes(b ^ mask[i%4] for i,b in enumerate(payload))
            if length <= 125:
                header = bytes([0x81, 0x80 | length]) + mask
            elif length <= 65535:
                header = bytes([0x81, 0xFE]) + struct.pack("!H", length) + mask
            else:
                header = bytes([0x81, 0xFF]) + struct.pack("!Q", length) + mask
            with self._lock:
                self._sock.sendall(header + masked_payload)
            return True
        except Exception:
            self.connected = False
            return False

    def disconnect(self):
        self.connected = False
        try:
            if self._sock:
                self._sock.close()
        except: pass
        self._sock = None


# ─────────────────────────────────────────────────────────────
# СЕТЕВОЙ МЕНЕДЖЕР (слой бизнес-логики поверх WS)
# ─────────────────────────────────────────────────────────────

class NetworkManager:
    def __init__(self):
        self.ws = WSClient()
        self.ws.on_message    = self._on_message
        self.ws.on_connect    = self._on_connect
        self.ws.on_disconnect = self._on_disconnect
        self.host = ""
        self.port = 8765
        self._pending_requests = {}  # req_id → callback
        self._req_counter = 0

        # Callbacks для приложения
        self.on_status_change = None       # (bool connected)
        self.on_incoming_message = None    # (peer, text, ts, server_id)
        self.on_contact_request = None     # (from_user, pubkey_pem)
        self.on_request_accepted = None    # (peer, pubkey_pem)
        self.on_message_status = None      # (server_id, status)

    # ── Подключение ─────────────────────────────────────────
    def connect(self, host, port, username, priv_key_path, pub_key_pem,
                on_done=None):
        """Подключается и регистрирует/авторизует аккаунт."""
        self.host = host
        self.port = port
        self._username = username
        self._priv_key_path = priv_key_path
        self._pub_key_pem = pub_key_pem
        self._on_done = on_done

        def _thread():
            try:
                self.ws.connect(host, port)
            except Exception as e:
                if on_done:
                    Clock.schedule_once(lambda dt: on_done(False, str(e)), 0)
        threading.Thread(target=_thread, daemon=True).start()

    def _on_connect(self):
        # После WS-соединения — авторизуемся
        self.ws.send({
            "type":    "auth",
            "username": self._username,
            "pubkey":  self._pub_key_pem,
        })

    def _on_disconnect(self):
        if self.on_status_change:
            self.on_status_change(False)

    def disconnect(self):
        self.ws.disconnect()

    # ── Входящие сообщения ──────────────────────────────────
    def _on_message(self, msg: dict):
        t = msg.get("type")

        if t == "auth_ok":
            if self.on_status_change:
                self.on_status_change(True)
            if self._on_done:
                self._on_done(True, None)
            # Запрашиваем непрочитанные
            self.ws.send({"type": "get_pending"})

        elif t == "auth_error":
            if self._on_done:
                self._on_done(False, msg.get("reason", "Ошибка авторизации"))

        elif t == "message":
            self._handle_incoming(msg)

        elif t == "contact_request":
            if self.on_contact_request:
                self.on_contact_request(msg["from"], msg["pubkey"])

        elif t == "contact_accepted":
            if self.on_request_accepted:
                self.on_request_accepted(msg["peer"], msg["pubkey"])

        elif t == "message_status":
            if self.on_message_status:
                self.on_message_status(msg["server_id"], msg["status"])

        elif t == "user_info":
            rid = msg.get("req_id")
            if rid and rid in self._pending_requests:
                cb = self._pending_requests.pop(rid)
                cb(msg)

        elif t == "error":
            rid = msg.get("req_id")
            if rid and rid in self._pending_requests:
                cb = self._pending_requests.pop(rid)
                cb({"type":"error","reason": msg.get("reason","")})

    def _handle_incoming(self, msg):
        """Расшифровываем входящее сообщение и сохраняем в БД."""
        app = App.get_running_app()
        try:
            account = app.backend.get_my_account()
            if not account:
                return
            payload = msg["payload"]
            text = app.backend.decrypt_payload(account["private_key_path"], payload)
            peer = msg["from"]
            ts   = msg.get("ts", int(time.time()*1000))
            sid  = msg.get("server_id")
            app.db.add_message(peer, "in", text, ts=ts, status="delivered", server_id=sid)
            # Подтверждаем доставку
            self.ws.send({"type":"ack","server_id": sid})
            if self.on_incoming_message:
                self.on_incoming_message(peer, text, ts, sid)
        except Exception as e:
            print(f"[WS] decrypt error: {e}")

    # ── Отправка сообщения ──────────────────────────────────
    def send_message(self, to: str, text: str, pub_key_path: str):
        """Шифрует и отправляет сообщение."""
        app = App.get_running_app()
        try:
            payload = app.backend.encrypt_for(pub_key_path, text)
            ts = int(time.time()*1000)
            self.ws.send({
                "type":    "message",
                "to":      to,
                "payload": payload,
                "ts":      ts,
            })
            return ts
        except Exception as e:
            print(f"[WS] send error: {e}")
            return None

    # ── Запрос контакта ─────────────────────────────────────
    def request_contact(self, username: str):
        self.ws.send({"type": "contact_request", "to": username})

    def accept_contact(self, username: str, pub_key_pem: str):
        self.ws.send({"type": "contact_accept", "to": username,
                      "pubkey": pub_key_pem})

    def reject_contact(self, username: str):
        self.ws.send({"type": "contact_reject", "to": username})

    # ── Поиск пользователя ──────────────────────────────────
    def find_user(self, username: str, callback):
        rid = self._next_req_id()
        self._pending_requests[rid] = callback
        self.ws.send({"type": "find_user", "username": username, "req_id": rid})

    def _next_req_id(self):
        self._req_counter += 1
        return f"req_{self._req_counter}"


# ─────────────────────────────────────────────────────────────
# ЭКРАНЫ
# ─────────────────────────────────────────────────────────────

class LaunchScreen(Screen):
    def on_enter(self):
        self._build()

    def _build(self):
        box = self.ids.accounts_box
        box.clear_widgets()
        app = App.get_running_app()
        t = app.theme
        accounts = [u for u in app.backend.load_users()
                    if u.get("private_key_path") and u.get("public_key_path")]
        if not accounts:
            box.add_widget(Label(
                text="Аккаунтов пока нет.\nСоздайте первый!",
                font_size="14sp", color=t["label_muted"],
                size_hint_y=None, height=dp(48),
                halign="center", text_size=(Window.width*0.8, None)))
            return
        for acc in accounts:
            btn = Button(
                text=f"@{acc['username']}",
                size_hint_y=None, height=dp(56),
                background_normal="", background_color=t["btn_bg"],
                color=t["btn_text"], font_size="17sp", bold=True)
            btn.bind(on_release=lambda _, a=acc: self._select_account(a))
            box.add_widget(btn)

    def _select_account(self, account):
        app = App.get_running_app()
        app.my_account = account
        app.root.current = "chats"

    def open_create_account(self):
        self.manager.current = "create_account"


class CreateAccountScreen(Screen):
    _keysize = 4096

    def select_keysize(self, size):
        self._keysize = size

    def do_create(self):
        username = self.ids.username_inp.text.strip().lstrip("@")
        if not username or not re.match(r"^[a-zA-Z0-9_]{3,32}$", username):
            self.ids.status_lbl.text = "Имя: 3-32 символа, латиница/цифры/_"
            self.ids.status_lbl.color = [1,0.3,0.3,1]
            return
        self.ids.status_lbl.text = f"Генерируем {self._keysize}-бит ключи..."
        self.ids.status_lbl.color = App.get_running_app().theme["label_muted"]

        def _gen():
            try:
                app = App.get_running_app()
                app.backend.generate_key_pair(username, self._keysize)
                def _done(dt):
                    app.my_account = app.backend.get_my_account()
                    self.manager.current = "chats"
                Clock.schedule_once(_done, 0)
            except Exception as e:
                def _err(dt):
                    self.ids.status_lbl.text = f"Ошибка: {e}"
                    self.ids.status_lbl.color = [1,0.3,0.3,1]
                Clock.schedule_once(_err, 0)
        threading.Thread(target=_gen, daemon=True).start()


class ServerScreen(Screen):
    def go_back(self):
        self.manager.current = "chats"

    def on_enter(self):
        self._update_status()
        app = App.get_running_app()
        self.ids.host_inp.text = app.net.host or ""
        self.ids.port_inp.text = str(app.net.port)

    def _update_status(self):
        app = App.get_running_app()
        lbl = self.ids.conn_status
        if app.net.ws.connected:
            acc = app.my_account
            name = f"@{acc['username']}" if acc else ""
            lbl.text = f"✓ Подключено {name} → {app.net.host}:{app.net.port}"
            lbl.color = App.get_running_app().theme["success_bg"]
        else:
            lbl.text = "Нет подключения"
            lbl.color = App.get_running_app().theme["label_muted"]

    def do_connect(self):
        host = self.ids.host_inp.text.strip()
        port = self.ids.port_inp.text.strip() or "8765"
        app  = App.get_running_app()
        acc  = app.my_account
        if not acc:
            show_msg("Ошибка", "Сначала создайте или выберите аккаунт")
            return
        if not host:
            show_msg("Ошибка", "Введите адрес сервера")
            return
        self.ids.conn_status.text = "Подключение..."
        self.ids.conn_status.color = app.theme["label_muted"]
        pub_pem = app.backend.pubkey_pem(acc["public_key_path"])

        def _done(ok, err):
            self._update_status()
            if not ok:
                show_msg("Ошибка подключения", err or "Неизвестная ошибка")
            else:
                app.save_server_settings(host, int(port))
                # Обновить badge в чатах
                chats_screen = app.root.get_screen("chats")
                chats_screen.update_net_badge()

        app.net.connect(host, int(port), acc["username"],
                        acc["private_key_path"], pub_pem, on_done=_done)

    def do_disconnect(self):
        App.get_running_app().net.disconnect()
        self._update_status()


class ChatsScreen(Screen):
    def on_enter(self):
        self.refresh()
        self.update_net_badge()

    def refresh(self):
        box   = self.ids.chats_list
        box.clear_widgets()
        app   = App.get_running_app()
        t     = app.theme
        chats = app.db.get_chats()
        if not chats:
            box.add_widget(Label(
                text="Нет чатов.\nНажмите ✎ чтобы написать кому-то.",
                font_size="14sp", color=t["label_muted"],
                size_hint_y=None, height=dp(80),
                halign="center",
                text_size=(Window.width*0.8, None)))
            return
        for chat in chats:
            self._add_chat_row(box, chat, t)

    def _add_chat_row(self, parent, chat, t):
        peer     = chat["peer"]
        last_msg = chat.get("last_msg") or ""
        unread   = chat.get("unread", 0)
        last_ts  = chat.get("last_ts")
        time_str = ""
        if last_ts:
            dt = datetime.fromtimestamp(last_ts / 1000)
            now = datetime.now()
            if dt.date() == now.date():
                time_str = dt.strftime("%H:%M")
            else:
                time_str = dt.strftime("%d.%m")

        row = BoxLayout(size_hint_y=None, height=dp(68),
                        padding=[dp(12),dp(8),dp(12),dp(8)], spacing=dp(12))
        with row.canvas.before:
            Color(*t["bg_color"])
            Rectangle(pos=row.pos, size=row.size)
        row.bind(pos=lambda i,_: _upd_row(i), size=lambda i,_: _upd_row(i))
        def _upd_row(inst):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*t["bg_color"])
                Rectangle(pos=inst.pos, size=inst.size)

        avatar = make_avatar(peer, dp(44))
        row.add_widget(avatar)

        info = BoxLayout(orientation="vertical", spacing=dp(2))
        top  = BoxLayout(size_hint_y=None, height=dp(22))
        top.add_widget(Label(text=f"@{peer}", font_size="15sp", bold=True,
                             color=t["btn_text"], halign="left",
                             text_size=(Window.width*0.55, None)))
        top.add_widget(Label(text=time_str, font_size="11sp",
                             color=t["label_muted"], size_hint_x=None,
                             width=dp(46), halign="right",
                             text_size=(dp(46), None)))
        info.add_widget(top)

        bot = BoxLayout(size_hint_y=None, height=dp(20))
        preview_text = (last_msg[:35]+"…") if len(last_msg)>35 else last_msg
        bot.add_widget(Label(text=preview_text, font_size="13sp",
                             color=t["label_muted"], halign="left",
                             text_size=(Window.width*0.58, None)))
        if unread > 0:
            badge = Label(text=str(unread), font_size="11sp",
                          color=[1,1,1,1], size_hint_x=None, width=dp(22),
                          halign="center", bold=True)
            with badge.canvas.before:
                Color(*t["accent"])
                Ellipse(pos=badge.pos, size=(dp(22),dp(22)))
            badge.bind(pos=lambda i,_: _upd_badge(i),
                       size=lambda i,_: _upd_badge(i))
            def _upd_badge(inst):
                inst.canvas.before.clear()
                with inst.canvas.before:
                    Color(*t["accent"])
                    Ellipse(pos=inst.pos, size=(dp(22),dp(22)))
            bot.add_widget(badge)
        info.add_widget(bot)
        row.add_widget(info)

        # Разделитель
        sep = Widget(size_hint_y=None, height=dp(1))
        with sep.canvas:
            Color(*t["chat_list_sep"])
            Rectangle(pos=sep.pos, size=sep.size)
        sep.bind(pos=lambda i,_: _upd_sep(i), size=lambda i,_: _upd_sep(i))
        def _upd_sep(inst):
            inst.canvas.clear()
            with inst.canvas:
                Color(*t["chat_list_sep"])
                Rectangle(pos=inst.pos, size=inst.size)

        container = BoxLayout(orientation="vertical", size_hint_y=None,
                              height=dp(69))
        container.add_widget(row)
        container.add_widget(sep)

        # Нажатие — открыть чат
        btn = Button(size=container.size, pos=container.pos,
                     background_normal="", background_color=[0,0,0,0])
        btn.bind(on_release=lambda _, p=peer: self.open_chat(p))
        container.bind(pos=lambda i,_: setattr(btn,'pos',i.pos),
                       size=lambda i,_: setattr(btn,'size',i.size))
        container.add_widget(btn)

        parent.add_widget(container)

    def update_net_badge(self):
        app = App.get_running_app()
        badge = self.ids.net_badge
        if app.net.ws.connected:
            badge.color = app.theme["online_dot"]
        else:
            badge.color = app.theme["offline_dot"]

    def open_chat(self, peer):
        app = App.get_running_app()
        app.db.mark_read(peer)
        chat_screen = app.root.get_screen("chat")
        chat_screen.load_chat(peer)
        app.root.current = "chat"

    def on_search(self, query):
        # Простая фильтрация по имени
        box   = self.ids.chats_list
        box.clear_widgets()
        app   = App.get_running_app()
        t     = app.theme
        chats = app.db.get_chats()
        if query:
            chats = [c for c in chats if query.lower() in c["peer"].lower()]
        if not chats:
            return
        for chat in chats:
            self._add_chat_row(box, chat, t)

    def new_chat_dialog(self):
        """Диалог: написать по @username"""
        app = App.get_running_app()
        t   = app.theme
        mv  = ModalView(size_hint=(0.88, None), height=dp(280),
                        background_color=[0,0,0,0])
        card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
        with card.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
        card.bind(pos=lambda i,_: _r(i), size=lambda i,_: _r(i))
        def _r(inst):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*t["input_bg"])
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])

        card.add_widget(Label(text="Новый чат", font_size="17sp", bold=True,
                              color=t["title_color"], size_hint_y=None, height=dp(30)))
        inp = TextInput(hint_text="@username",
                        background_color=t["input_bg"],
                        foreground_color=t["input_fg"],
                        font_size="15sp", size_hint_y=None, height=dp(48),
                        use_bubble=False, use_handles=False,
                        multiline=False, padding=[12,10,12,10],
                        cursor_color=t["accent"])
        status = Label(text="", font_size="12sp", color=t["label_muted"],
                       size_hint_y=None, height=dp(24),
                       halign="left", text_size=(Window.width*0.75, None))
        card.add_widget(inp)
        card.add_widget(status)

        row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
        find_btn = Button(text="Найти / написать",
                          background_normal="",
                          background_color=t["accent"],
                          color=[1,1,1,1], bold=True)
        cancel_btn = Button(text="Отмена",
                            background_normal="",
                            background_color=t["btn_bg"],
                            color=t["btn_text"])
        cancel_btn.bind(on_release=mv.dismiss)
        row.add_widget(find_btn); row.add_widget(cancel_btn)
        card.add_widget(row)
        mv.add_widget(card)

        def _find(_):
            username = inp.text.strip().lstrip("@")
            if not username:
                return
            # Проверяем локально
            contact = app.backend.get_contact(username)
            if contact and contact.get("public_key_path"):
                mv.dismiss()
                self.open_chat(username)
                return
            # Ищем на сервере
            if not app.net.ws.connected:
                status.text = "Нет соединения с сервером"
                status.color = [1,0.3,0.3,1]
                return
            status.text = "Поиск на сервере..."
            status.color = t["label_muted"]

            def _on_found(result):
                if result.get("type") == "error" or "pubkey" not in result:
                    status.text = f"Пользователь @{username} не найден"
                    status.color = [1,0.3,0.3,1]
                    return
                pubkey = result["pubkey"]
                status.text = f"Найден! Отправляем запрос..."
                status.color = t["success_bg"]
                # Сохраняем ключ контакта
                app.backend.add_contact(username, pubkey)
                # Отправляем запрос на контакт
                my_pubpem = app.backend.pubkey_pem(app.my_account["public_key_path"])
                app.net.accept_contact(username, my_pubpem)
                mv.dismiss()
                # Создаём чат (запись в БД появится при первом сообщении)
                self.open_chat(username)

            app.net.find_user(username, _on_found)

        find_btn.bind(on_release=_find)
        mv.open()

    def open_menu(self):
        app = App.get_running_app()
        t   = app.theme
        acc = app.my_account
        name = f"@{acc['username']}" if acc else "Нет аккаунта"
        mv = ModalView(size_hint=(0.82, None), height=dp(280),
                       background_color=[0,0,0,0])
        card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
        with card.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
        card.bind(pos=lambda i,_: _r(i), size=lambda i,_: _r(i))
        def _r(inst):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*t["input_bg"])
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])

        card.add_widget(Label(text=name, font_size="18sp", bold=True,
                              color=t["title_color"], size_hint_y=None, height=dp(34)))
        if acc:
            fp = app.backend.pubkey_fingerprint(acc["public_key_path"])
            card.add_widget(Label(text=f"FP: {fp}", font_size="11sp",
                                  color=t["label_muted"], size_hint_y=None, height=dp(22),
                                  halign="left", text_size=(Window.width*0.75, None)))
        for label, action in [
            ("🔌 Сервер",     lambda: (mv.dismiss(), setattr(self.manager,'current','server'))),
            ("🔑 Ключи",      lambda: (mv.dismiss(), setattr(self.manager,'current','keys'))),
            ("← Сменить акк", lambda: (mv.dismiss(), self._switch_account())),
        ]:
            b = Button(text=label, size_hint_y=None, height=dp(44),
                       background_normal="", background_color=t["btn_bg"],
                       color=t["btn_text"], halign="left", font_size="14sp")
            b.bind(on_release=lambda _, a=action: a())
            card.add_widget(b)
        close = Button(text="Закрыть", size_hint_y=None, height=dp(40),
                       background_normal="", background_color=[0,0,0,0],
                       color=t["accent"])
        close.bind(on_release=mv.dismiss)
        card.add_widget(close)
        mv.add_widget(card)
        mv.open()

    def _switch_account(self):
        App.get_running_app().my_account = None
        self.manager.current = "launch"


class ChatScreen(Screen):
    _peer = ""

    def load_chat(self, peer):
        self._peer = peer
        self.ids.peer_name_lbl.text = f"@{peer}"
        self.ids.peer_status_lbl.text = ""
        self._build_messages()
        # Прокрутить вниз
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.1)

    def _build_messages(self):
        box = self.ids.msg_list
        box.clear_widgets()
        app  = App.get_running_app()
        msgs = app.db.get_messages(self._peer)
        for m in msgs:
            self._add_bubble(m["direction"], m["text"],
                             m["ts"], m.get("status","sent"))

    def _add_bubble(self, direction, text, ts, status="sent"):
        app = App.get_running_app()
        t   = app.theme
        is_out = (direction == "out")

        dt = datetime.fromtimestamp(ts/1000)
        time_str = dt.strftime("%H:%M")
        status_icon = {"sent":"✓","delivered":"✓✓","read":"✓✓"}.get(status,"")

        # Пузырь
        bubble_color = t["bubble_out"] if is_out else t["bubble_in"]
        max_w = Window.width * 0.72

        # Расчёт высоты текста
        from kivy.core.text import Label as CoreLabel
        cl = CoreLabel(text=text, font_size=dp(15),
                       text_size=(max_w - dp(20), None))
        cl.refresh()
        text_h = cl.texture.size[1] if cl.texture else dp(20)
        bubble_h = max(text_h + dp(36), dp(44))

        outer = BoxLayout(size_hint_y=None, height=bubble_h + dp(4))

        if is_out:
            outer.add_widget(Widget())  # spacer left

        bubble = BoxLayout(size_hint=(None, None),
                           size=(min(cl.texture.size[0] + dp(24) if cl.texture else max_w,
                                     max_w),
                                 bubble_h),
                           padding=[dp(10), dp(6), dp(10), dp(6)])

        with bubble.canvas.before:
            Color(*bubble_color)
            radius = [12,12,2,12] if is_out else [12,12,12,2]
            RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=radius)
        bubble.bind(pos=lambda i,_: _upd(i), size=lambda i,_: _upd(i))
        def _upd(inst, _bubble_color=bubble_color, _is_out=is_out):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*_bubble_color)
                r = [12,12,2,12] if _is_out else [12,12,12,2]
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=r)

        content = BoxLayout(orientation="vertical")
        msg_lbl = Label(text=text, font_size="15sp", color=t["input_fg"],
                        halign="left" if not is_out else "right",
                        valign="top", size_hint_y=1,
                        text_size=(max_w - dp(20), None))
        content.add_widget(msg_lbl)

        foot = BoxLayout(size_hint_y=None, height=dp(16))
        foot.add_widget(Widget())
        time_lbl = Label(text=f"{time_str}  {status_icon}",
                         font_size="10sp",
                         color=[0.5,0.5,0.6,1] if not is_out else [0.6,0.7,0.9,1],
                         size_hint_x=None,
                         width=dp(60), halign="right",
                         text_size=(dp(60), None))
        foot.add_widget(time_lbl)
        content.add_widget(foot)
        bubble.add_widget(content)
        outer.add_widget(bubble)

        if not is_out:
            outer.add_widget(Widget())  # spacer right

        self.ids.msg_list.add_widget(outer)

    def _scroll_bottom(self):
        sv = self.ids.msg_scroll
        sv.scroll_y = 0

    def send_message(self):
        text = self.ids.msg_inp.text.strip()
        if not text:
            return
        self.ids.msg_inp.text = ""
        app  = App.get_running_app()
        peer = self._peer

        # Проверяем ключ контакта
        contact = app.backend.get_contact(peer)
        if not contact or not contact.get("public_key_path"):
            show_msg("Нет ключа", f"Публичный ключ @{peer} недоступен.\n"
                                   "Дождитесь принятия запроса контакта.")
            return

        ts = int(time.time()*1000)
        sid = f"local_{ts}"

        # Сохраняем локально сразу
        app.db.add_message(peer, "out", text, ts=ts, status="sent", server_id=sid)
        self._add_bubble("out", text, ts, "sent")
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)

        # Отправляем если есть соединение
        if app.net.ws.connected:
            def _send():
                real_ts = app.net.send_message(peer, text, contact["public_key_path"])
            threading.Thread(target=_send, daemon=True).start()
        # Иначе — сообщение останется как "sent" и отправится при следующем подключении
        # (TODO: очередь офлайн-сообщений)

        # Обновить список чатов
        chats = self.manager.get_screen("chats")
        Clock.schedule_once(lambda dt: chats.refresh(), 0.1)

    def go_back(self):
        self.manager.current = "chats"
        chats = self.manager.get_screen("chats")
        chats.refresh()

    def open_chat_menu(self):
        app  = App.get_running_app()
        t    = app.theme
        peer = self._peer
        mv   = ModalView(size_hint=(0.80, None), height=dp(240),
                         background_color=[0,0,0,0])
        card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
        with card.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
        card.bind(pos=lambda i,_: _r(i), size=lambda i,_: _r(i))
        def _r(inst):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*t["input_bg"])
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])
        card.add_widget(Label(text=f"@{peer}", font_size="16sp", bold=True,
                              color=t["title_color"], size_hint_y=None, height=dp(30)))

        contact = app.backend.get_contact(peer)
        if contact and contact.get("public_key_path"):
            fp = app.backend.pubkey_fingerprint(contact["public_key_path"])
            card.add_widget(Label(text=f"FP: {fp}", font_size="11sp",
                                  color=t["label_muted"], size_hint_y=None, height=dp(20),
                                  halign="left", text_size=(Window.width*0.72, None)))

        copy_btn = Button(text="Копировать ключ контакта",
                          size_hint_y=None, height=dp(44),
                          background_normal="", background_color=t["btn_bg"],
                          color=t["btn_text"])
        def _copy(_):
            if contact and contact.get("public_key_path"):
                Clipboard.copy(app.backend.pubkey_pem(contact["public_key_path"]))
                show_msg("Скопировано","Публичный ключ в буфере")
            mv.dismiss()
        copy_btn.bind(on_release=_copy)
        card.add_widget(copy_btn)

        del_btn = Button(text="🗑 Удалить чат", size_hint_y=None, height=dp(44),
                         background_normal="", background_color=t["danger_bg"],
                         color=[1,1,1,1])
        def _del(_):
            mv.dismiss()
            def _confirm():
                app.db.delete_chat(peer)
                self.go_back()
            show_confirm("Удалить чат?", f"История с @{peer} будет удалена.", _confirm)
        del_btn.bind(on_release=_del)
        card.add_widget(del_btn)

        close = Button(text="Закрыть", size_hint_y=None, height=dp(36),
                       background_normal="", background_color=[0,0,0,0],
                       color=t["accent"])
        close.bind(on_release=mv.dismiss)
        card.add_widget(close)
        mv.add_widget(card)
        mv.open()

    def receive_message(self, peer, text, ts, sid):
        """Вызывается NetworkManager при входящем сообщении."""
        if peer == self._peer:
            self._add_bubble("in", text, ts, "delivered")
            Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)


class KeysScreen(Screen):
    def on_enter(self):
        app = App.get_running_app()
        acc = app.my_account
        lbl = self.ids.my_key_label
        if acc:
            fp = app.backend.pubkey_fingerprint(acc["public_key_path"])
            lbl.text = f"Аккаунт: @{acc['username']}  FP: {fp}"
        else:
            lbl.text = "Аккаунт не выбран"
        self._refresh_contacts()

    def copy_my_pubkey(self):
        app = App.get_running_app()
        acc = app.my_account
        if not acc:
            show_msg("Ошибка", "Нет аккаунта")
            return
        pem = app.backend.pubkey_pem(acc["public_key_path"])
        Clipboard.copy(pem)
        show_msg("Скопировано", "Публичный ключ скопирован в буфер.\n"
                                "Отправьте его другу для безопасного общения.")

    def export_keys(self):
        app = App.get_running_app()
        acc = app.my_account
        if not acc:
            show_msg("Ошибка", "Нет аккаунта")
            return
        pub = app.backend.pubkey_pem(acc["public_key_path"])
        with open(acc["private_key_path"]) as f:
            priv = f.read()
        export = json.dumps({"username": acc["username"],
                              "public_key": pub,
                              "private_key": priv}, indent=2)
        Clipboard.copy(export)
        show_msg("Экспорт", "Ключи скопированы в буфер (JSON).\n"
                            "Храните приватный ключ в безопасном месте!")

    def _refresh_contacts(self):
        box = self.ids.contacts_list
        box.clear_widgets()
        app = App.get_running_app()
        t   = app.theme
        contacts = [u for u in app.backend.load_users()
                    if u.get("public_key_path") and not u.get("private_key_path")]
        if not contacts:
            box.add_widget(Label(text="Нет контактов", font_size="13sp",
                                 color=t["label_muted"],
                                 size_hint_y=None, height=dp(40)))
            return
        for c in contacts:
            row = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(8),
                            padding=[dp(8),dp(4),dp(4),dp(4)])
            fp = app.backend.pubkey_fingerprint(c["public_key_path"])
            info = BoxLayout(orientation="vertical")
            info.add_widget(Label(text=f"@{c['username']}", font_size="14sp",
                                  bold=True, color=t["btn_text"], halign="left",
                                  text_size=(Window.width*0.55, None)))
            info.add_widget(Label(text=f"FP: {fp}", font_size="10sp",
                                  color=t["label_muted"], halign="left",
                                  text_size=(Window.width*0.55, None)))
            row.add_widget(info)
            del_btn = Button(text="✕", size_hint_x=None, width=dp(38),
                             background_normal="",
                             background_color=t["danger_bg"], color=[1,1,1,1])
            del_btn.bind(on_release=lambda _, u=c:
                         show_confirm("Удалить контакт?",
                                      f"@{u['username']} будет удалён.",
                                      lambda: self._del_contact(u["username"])))
            row.add_widget(del_btn)
            box.add_widget(row)

    def _del_contact(self, username):
        App.get_running_app().backend.delete_user(username)
        self._refresh_contacts()


# ─────────────────────────────────────────────────────────────
# УВЕДОМЛЕНИЕ О ЗАПРОСЕ КОНТАКТА
# ─────────────────────────────────────────────────────────────

def show_contact_request(from_user, pubkey_pem):
    """Показывает баннер «Принять / Отклонить»."""
    app = App.get_running_app()
    t   = app.theme
    mv  = ModalView(size_hint=(0.90, None), height=dp(220),
                    background_color=[0,0,0,0], auto_dismiss=False)
    card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
    with card.canvas.before:
        Color(*t["input_bg"])
        RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
    card.bind(pos=lambda i,_: _r(i), size=lambda i,_: _r(i))
    def _r(inst):
        inst.canvas.before.clear()
        with inst.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])

    card.add_widget(Label(text="Запрос на контакт", font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(28)))
    card.add_widget(Label(text=f"@{from_user} хочет написать вам.\n"
                               "Принять — он получит ваш публичный ключ.",
                          font_size="13sp", color=t["input_fg"],
                          size_hint_y=None, height=dp(50),
                          halign="center",
                          text_size=(Window.width*0.78, None)))

    # Fingerprint входящего ключа
    try:
        tmp_path = os.path.join(app.backend.keys_dir, f"_tmp_{from_user}.pem")
        with open(tmp_path, "w") as f:
            f.write(pubkey_pem)
        fp = app.backend.pubkey_fingerprint(tmp_path)
        os.remove(tmp_path)
        card.add_widget(Label(text=f"FP: {fp}", font_size="10sp",
                              color=t["label_muted"], size_hint_y=None, height=dp(18),
                              halign="center", text_size=(Window.width*0.78, None)))
    except:
        pass

    row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(12))
    acc_btn = Button(text="✓ Принять", background_normal="",
                     background_color=t["success_bg"], color=[1,1,1,1], bold=True)
    rej_btn = Button(text="✗ Отклонить", background_normal="",
                     background_color=t["danger_bg"],  color=[1,1,1,1])

    def _accept(_):
        mv.dismiss()
        # Сохраняем ключ контакта
        app.backend.add_contact(from_user, pubkey_pem)
        # Отправляем свой ключ в ответ
        my_pub = app.backend.pubkey_pem(app.my_account["public_key_path"])
        app.net.accept_contact(from_user, my_pub)
        show_msg("Принято", f"@{from_user} добавлен в контакты!")

    def _reject(_):
        mv.dismiss()
        app.net.reject_contact(from_user)

    acc_btn.bind(on_release=_accept)
    rej_btn.bind(on_release=_reject)
    row.add_widget(acc_btn); row.add_widget(rej_btn)
    card.add_widget(row)
    mv.add_widget(card)
    mv.open()


# ─────────────────────────────────────────────────────────────
# ПРИЛОЖЕНИЕ
# ─────────────────────────────────────────────────────────────

class SCMessApp(App):
    theme = DictProperty(DEFAULT_THEME.copy())

    def build(self):
        self.my_account = None
        self.backend    = CryptoBackend(self.user_data_dir)
        self.db         = MessageDB(self.user_data_dir)
        self.net        = NetworkManager()

        global SETTINGS_FILE
        SETTINGS_FILE = os.path.join(self.user_data_dir, "settings.json")
        self._load_settings()

        # Колбэки сетевого слоя
        self.net.on_status_change    = self._on_net_status
        self.net.on_incoming_message = self._on_incoming
        self.net.on_contact_request  = self._on_contact_request
        self.net.on_request_accepted = self._on_request_accepted

        Builder.load_string(KV)

        sm = ScreenManager(transition=NoTransition())
        sm.add_widget(LaunchScreen(name="launch"))
        sm.add_widget(CreateAccountScreen(name="create_account"))
        sm.add_widget(ChatsScreen(name="chats"))
        sm.add_widget(ChatScreen(name="chat"))
        sm.add_widget(ServerScreen(name="server"))
        sm.add_widget(KeysScreen(name="keys"))
        return sm

    def on_start(self):
        Window.clearcolor = tuple(self.theme["bg_color"])
        # Авто-подключение если есть сохранённые настройки
        acc = self.backend.get_my_account()
        if acc and self._saved_host:
            self.my_account = acc
            pub_pem = self.backend.pubkey_pem(acc["public_key_path"])
            self.net.connect(self._saved_host, self._saved_port,
                             acc["username"], acc["private_key_path"], pub_pem)

    # ── Настройки ───────────────────────────────────────────
    def _load_settings(self):
        self._saved_host = ""
        self._saved_port = 8765
        try:
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE) as f:
                    d = json.load(f)
                self._saved_host = d.get("server_host", "")
                self._saved_port = d.get("server_port", 8765)
        except:
            pass

    def save_server_settings(self, host, port):
        self._saved_host = host
        self._saved_port = port
        try:
            d = {}
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                try:
                    with open(SETTINGS_FILE) as f:
                        d = json.load(f)
                except: pass
            d["server_host"] = host
            d["server_port"] = port
            with open(SETTINGS_FILE, "w") as f:
                json.dump(d, f)
        except: pass

    # ── Сетевые колбэки ─────────────────────────────────────
    def _on_net_status(self, connected):
        try:
            chats = self.root.get_screen("chats")
            chats.update_net_badge()
            srv = self.root.get_screen("server")
            srv._update_status()
        except: pass

    def _on_incoming(self, peer, text, ts, sid):
        try:
            chat = self.root.get_screen("chat")
            chat.receive_message(peer, text, ts, sid)
            chats = self.root.get_screen("chats")
            chats.refresh()
        except: pass

    def _on_contact_request(self, from_user, pubkey_pem):
        Clock.schedule_once(
            lambda dt: show_contact_request(from_user, pubkey_pem), 0)

    def _on_request_accepted(self, peer, pubkey_pem):
        self.backend.add_contact(peer, pubkey_pem)
        Clock.schedule_once(
            lambda dt: show_msg("Контакт принят",
                                f"@{peer} принял ваш запрос!\nМожете писать."), 0)


if __name__ == "__main__":
    SCMessApp().run()
