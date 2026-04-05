"""
SCmess — E2E-зашифрованный мессенджер
Клиент: Kivy + Python
Крипто: RSA-4096 + AES-256-GCM
Протокол: WebSocket JSON
"""

import os, io, json, base64, threading, hashlib, time, sqlite3, re, logging
from collections import deque
from datetime import datetime

from kivy.config import Config
Config.set("graphics", "maxfps", "120")
Config.set("kivy", "allow_screensaver", "0")
Config.set("kivy", "keyboard_mode", "system")

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
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.uix.image import Image as KivyImage
from kivy.clock import Clock
from kivy.utils import platform
from kivy.properties import (
    ObjectProperty, StringProperty, BooleanProperty,
    ListProperty, DictProperty, NumericProperty,
)
from kivy.metrics import dp
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line, Ellipse

log = logging.getLogger("scmess.client")

HAS_PIL = False
try:
    from PIL import Image as PILImage, ImageOps
    HAS_PIL = True
except ImportError:
    pass

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
    "bg_color":      [0.04, 0.04, 0.07, 1],
    "btn_bg":        [0.10, 0.10, 0.14, 1],
    "btn_border":    [0.22, 0.42, 0.90, 1],
    "btn_text":      [1,    1,    1,    1],
    "accent":        [0.22, 0.42, 0.90, 1],
    "input_bg":      [0.08, 0.08, 0.12, 1],
    "input_fg":      [0.92, 0.92, 0.95, 1],
    "title_color":   [0.30, 0.62, 1.00, 1],
    "label_muted":   [0.50, 0.50, 0.62, 1],
    "danger_bg":     [0.72, 0.14, 0.14, 1],
    "success_bg":    [0.14, 0.56, 0.25, 1],
    "log_bg":        [0.05, 0.05, 0.08, 1],
    "bubble_out":    [0.14, 0.27, 0.58, 1],
    "bubble_in":     [0.12, 0.12, 0.17, 1],
    "online_dot":    [0.20, 0.88, 0.42, 1],
    "offline_dot":   [0.38, 0.38, 0.50, 1],
    "chat_list_sep": [0.10, 0.10, 0.15, 1],
    "header_bg":     [0.07, 0.07, 0.11, 1],
}

SETTINGS_FILE = None

# ─────────────────────────────────────────────────────────────
# KV
# ─────────────────────────────────────────────────────────────
KV = """
#:import dp kivy.metrics.dp

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
            radius: [9]
        Color:
            rgba: app.theme['btn_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [8]

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
            radius: [9]
        Color:
            rgba: app.theme['danger_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [8]

<StyledInput@TextInput>:
    background_color: app.theme['input_bg']
    foreground_color: app.theme['input_fg']
    cursor_color: app.theme['accent']
    font_size: '15sp'
    padding: [14,11,14,11]
    hint_text_color: 0.38,0.38,0.52,1
    use_bubble: False
    use_handles: False

<SectionLabel@Label>:
    font_size: '12sp'
    color: app.theme['label_muted']
    size_hint_y: None
    height: dp(22)
    halign: 'left'
    text_size: self.width, None

# ═══════════════════════ LAUNCH ════════════════════════════

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
            size_hint_y: 0.12
        Label:
            text: 'SCmess'
            font_size: '44sp'
            bold: True
            color: app.theme['title_color']
            size_hint_y: None
            height: dp(64)
        Label:
            text: 'E2E зашифрованный мессенджер'
            font_size: '13sp'
            color: app.theme['label_muted']
            size_hint_y: None
            height: dp(26)
        Widget:
            size_hint_y: 0.06
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
            text: 'Создать аккаунт'
            size_hint_y: None
            height: dp(52)
            on_release: root.open_create_account()
        StyledButton:
            text: 'Настроить PIN-код'
            size_hint_y: None
            height: dp(44)
            on_release: root.setup_pin()
        Widget:
            size_hint_y: 0.2

# ═══════════════════════ PIN ═══════════════════════════════

<PinScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(30), dp(80), dp(30), dp(40)]
        spacing: dp(20)
        Widget:
            size_hint_y: 0.2
        Label:
            text: 'SCmess'
            font_size: '38sp'
            bold: True
            color: app.theme['title_color']
            size_hint_y: None
            height: dp(56)
        Label:
            id: pin_prompt
            text: 'Введите PIN-код'
            font_size: '16sp'
            color: app.theme['label_muted']
            size_hint_y: None
            height: dp(30)
        StyledInput:
            id: pin_inp
            hint_text: 'PIN-код (4-8 цифр)'
            size_hint_y: None
            height: dp(52)
            multiline: False
            password: True
            input_filter: 'int'
            on_text_validate: root.check_pin()
        Label:
            id: pin_status
            text: ''
            font_size: '13sp'
            color: 1,0.3,0.3,1
            size_hint_y: None
            height: dp(24)
        StyledButton:
            text: 'Войти'
            size_hint_y: None
            height: dp(52)
            on_release: root.check_pin()
        Widget:
            size_hint_y: 0.3

# ═══════════════════════ CREATE ACCOUNT ════════════════════

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
            height: dp(48)
            Button:
                text: 'Назад'
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
            height: dp(50)
            multiline: False
        SectionLabel:
            text: 'Размер RSA-ключа:'
        BoxLayout:
            size_hint_y: None
            height: dp(46)
            spacing: dp(8)
            ToggleKeySize:
                id: key_2048
                text: '2048 бит'
                group: 'keysize'
                state: 'normal'
                on_release: root.select_keysize(2048)
            ToggleKeySize:
                id: key_4096
                text: '4096 бит (рекомендовано)'
                group: 'keysize'
                state: 'down'
                on_release: root.select_keysize(4096)
        SectionLabel:
            text: 'Ключи хранятся только у вас — сервер не может читать сообщения'
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
            radius: [8]

# ═══════════════════════ SERVER ════════════════════════════

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
            height: dp(48)
            Button:
                text: 'Назад'
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
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            padding: [dp(14),dp(10),dp(14),dp(10)]
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [10]
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
            height: dp(50)
            multiline: False
        SectionLabel:
            text: 'Порт:'
        StyledInput:
            id: port_inp
            hint_text: '8765'
            input_filter: 'int'
            size_hint_y: None
            height: dp(50)
            multiline: False
        StyledButton:
            text: 'Подключиться'
            size_hint_y: None
            height: dp(52)
            on_release: root.do_connect()
        StyledButton:
            text: 'Отключиться'
            size_hint_y: None
            height: dp(46)
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

# ═══════════════════════ CHATS (main) ══════════════════════

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
            height: dp(58)
            padding: [dp(16), dp(10), dp(10), dp(10)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: app.theme['header_bg']
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
            # Статус подключения
            Widget:
                id: net_dot
                size_hint: None, None
                size: dp(10), dp(10)
                canvas:
                    Color:
                        rgba: app.theme['offline_dot']
                    Ellipse:
                        pos: self.x, self.y
                        size: self.size
            Button:
                text: '+'
                size_hint_x: None
                width: dp(46)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '30sp'
                bold: True
                on_release: root.new_chat_dialog()
            Button:
                id: menu_btn
                text: '⋮'
                size_hint_x: None
                width: dp(38)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['btn_text']
                font_size: '22sp'
                bold: True
                on_release: root.open_menu()
        # Поиск
        BoxLayout:
            size_hint_y: None
            height: dp(42)
            padding: [dp(14), dp(6), dp(14), dp(6)]
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            TextInput:
                id: search_inp
                hint_text: '🔍  Поиск...'
                background_color: 0,0,0,0
                foreground_color: app.theme['input_fg']
                hint_text_color: 0.38,0.38,0.52,1
                font_size: '14sp'
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

# ═══════════════════════ CHAT ══════════════════════════════

<ChatScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        id: chat_root
        orientation: 'vertical'
        # Шапка
        BoxLayout:
            size_hint_y: None
            height: dp(58)
            padding: [dp(6), dp(8), dp(8), dp(8)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: app.theme['header_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            Button:
                text: 'Назад'
                size_hint_x: None
                width: dp(40)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '24sp'
                on_release: root.go_back()
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
                font_size: '22sp'
                bold: True
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
            id: input_box
            size_hint_y: None
            height: dp(58)
            padding: [dp(8), dp(6), dp(8), dp(6)]
            spacing: dp(6)
            canvas.before:
                Color:
                    rgba: app.theme['header_bg']
                Rectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
            Button:
                text: '📎'
                size_hint_x: None
                width: dp(46)
                background_normal: ''
                background_color: 0,0,0,0
                color: app.theme['accent']
                font_size: '22sp'
                on_release: root.attach_media()
            TextInput:
                id: msg_inp
                hint_text: 'Сообщение...'
                background_color: app.theme['input_bg']
                foreground_color: app.theme['input_fg']
                hint_text_color: 0.38,0.38,0.52,1
                font_size: '15sp'
                use_bubble: False
                use_handles: False
                multiline: False
                cursor_color: app.theme['accent']
                padding: [14,10,14,10]
                on_text_validate: root.send_message()
                on_focus: root.on_input_focus(self.focus)
            Button:
                text: '▶'
                size_hint_x: None
                width: dp(46)
                background_normal: ''
                background_color: app.theme['accent']
                color: 1,1,1,1
                font_size: '20sp'
                bold: True
                on_release: root.send_message()

# ═══════════════════════ KEYS ══════════════════════════════

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
            height: dp(48)
            Button:
                text: 'Назад'
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
        StyledButton:
            text: 'Импортировать ключи'
            size_hint_y: None
            height: dp(44)
            on_release: root.import_keys()
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
                    radius: [10]
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

def _make_card(t):
    """Создает карточку с фоном и скруглёнными углами."""
    card = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
    def _draw(inst, *_):
        inst.canvas.before.clear()
        with inst.canvas.before:
            Color(*t["input_bg"])
            RoundedRectangle(pos=inst.pos, size=inst.size, radius=[14])
    _draw(card)
    card.bind(pos=_draw, size=_draw)
    return card


def show_msg(title, text):
    app = App.get_running_app()
    t = app.theme
    mv = ModalView(size_hint=(0.88, None), height=dp(200),
                   background_color=[0,0,0,0], auto_dismiss=True)
    card = _make_card(t)
    card.add_widget(Label(text=title, font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(30)))
    body = Label(text=text, font_size="14sp", color=t["input_fg"],
                 size_hint_y=None, halign="left", valign="top")
    body.bind(width=lambda i, _: setattr(i, "text_size", (i.width, None)),
              texture_size=lambda i, ts: setattr(i, "height", max(ts[1], dp(20))))
    card.add_widget(body)
    ok = Button(text="OK", size_hint_y=None, height=dp(42),
                background_normal="", background_color=[0,0,0,0],
                color=t["accent"], bold=True, font_size="15sp")
    ok.bind(on_release=mv.dismiss)
    card.add_widget(ok)
    mv.add_widget(card)
    def _fix(dt):
        bh = body.texture_size[1] if body.texture else dp(20)
        mv.height = dp(16+30+10+8) + bh + dp(8+42+16)
    Clock.schedule_once(_fix, 0)
    mv.open()


def show_confirm(title, text, on_yes, yes_label="Да", no_label="Отмена"):
    app = App.get_running_app()
    t = app.theme
    mv = ModalView(size_hint=(0.85, None), height=dp(190),
                   background_color=[0,0,0,0], auto_dismiss=True)
    card = _make_card(t)
    card.add_widget(Label(text=title, font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(30)))
    card.add_widget(Label(text=text, font_size="13sp", color=t["input_fg"],
                          size_hint_y=None, height=dp(44),
                          halign="center", valign="middle",
                          text_size=(Window.width * 0.74, None)))
    row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(12))
    yes_btn = Button(text=yes_label, background_normal="",
                     background_color=t["accent"], color=[1,1,1,1], bold=True)
    no_btn  = Button(text=no_label,  background_normal="",
                     background_color=t["btn_bg"], color=t["btn_text"])
    def _yes(_): mv.dismiss(); on_yes()
    yes_btn.bind(on_release=_yes)
    no_btn.bind(on_release=mv.dismiss)
    row.add_widget(yes_btn); row.add_widget(no_btn)
    card.add_widget(row)
    mv.add_widget(card)
    mv.open()


def make_avatar(name: str, size=dp(40), image_b64=None):
    """Аватар: с картинкой или инициалами."""
    COLORS = [
        [0.20, 0.40, 0.82], [0.72, 0.20, 0.52], [0.14, 0.62, 0.40],
        [0.62, 0.34, 0.10], [0.40, 0.14, 0.76], [0.10, 0.50, 0.66],
        [0.80, 0.40, 0.10], [0.10, 0.55, 0.80],
    ]
    if image_b64:
        try:
            data = base64.b64decode(image_b64)
            app = App.get_running_app()
            tmp = os.path.join(app.user_data_dir, f"ava_{hashlib.md5(image_b64[:32].encode()).hexdigest()}.jpg")
            if not os.path.exists(tmp):
                with open(tmp, "wb") as f:
                    f.write(data)
            w = Widget(size_hint=(None, None), size=(size, size))
            img = KivyImage(source=tmp, size_hint=(None, None), size=(size, size),
                            allow_stretch=True, keep_ratio=False)
            with w.canvas.after:
                pass
            def _upd(inst, val):
                img.pos = inst.pos
                img.size = inst.size
            w.bind(pos=_upd, size=_upd)
            w.add_widget(img)
            # Круглая маска
            with w.canvas.after:
                pass
            return w
        except Exception:
            pass

    h = int(hashlib.md5(name.encode()).hexdigest()[:4], 16)
    color = COLORS[h % len(COLORS)]
    initials = "".join(ch[0].upper() for ch in name.split() if ch)[:2] or "?"

    w = Widget(size_hint=(None, None), size=(size, size))
    lbl = Label(text=initials, font_size=str(int(size * 0.38)) + "sp",
                bold=True, color=[1, 1, 1, 1],
                size=w.size, pos=w.pos)
    w.add_widget(lbl)

    def _upd(inst, *_):
        inst.canvas.clear()
        with inst.canvas:
            Color(*color)
            Ellipse(pos=inst.pos, size=inst.size)
        lbl.pos = inst.pos
        lbl.size = inst.size
    _upd(w)
    w.bind(pos=_upd, size=_upd)
    return w


def show_toast(text, duration=2.0):
    """Лёгкое toast-уведомление снизу экрана."""
    app = App.get_running_app()
    t = app.theme
    mv = ModalView(size_hint=(None, None), size=(dp(260), dp(42)),
                   background_color=[0,0,0,0], auto_dismiss=False)
    mv.pos_hint = {"center_x": 0.5, "y": 0.06}
    card = BoxLayout(padding=[dp(16), dp(8), dp(16), dp(8)])
    with card.canvas.before:
        Color(0.12, 0.12, 0.18, 0.92)
        RoundedRectangle(pos=card.pos, size=card.size, radius=[20])
    card.bind(pos=lambda i, *_: _rd(i), size=lambda i, *_: _rd(i))
    def _rd(inst):
        inst.canvas.before.clear()
        with inst.canvas.before:
            Color(0.12, 0.12, 0.18, 0.92)
            RoundedRectangle(pos=inst.pos, size=inst.size, radius=[20])
    card.add_widget(Label(text=text, font_size="13sp", color=[1,1,1,1],
                          halign="center"))
    mv.add_widget(card)
    mv.open()
    Clock.schedule_once(lambda dt: mv.dismiss(), duration)


# ─────────────────────────────────────────────────────────────
# КРИПТО
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
        for u in self.load_users():
            if u.get("public_key_path") and u.get("private_key_path"):
                return u
        return None

    def get_contact(self, username):
        for u in self.load_users():
            if u["username"] == username:
                return u
        return None

    def add_contact(self, username, pubkey_pem: str, avatar=None, status=None):
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
        if avatar:   user["avatar"] = avatar
        if status:   user["status"] = status
        self.save_users(data)
        return user

    def update_my_profile(self, username, avatar=None, status=None):
        data = self.load_users()
        for u in data:
            if u["username"] == username and u.get("private_key_path"):
                if avatar  is not None: u["avatar"]  = avatar
                if status  is not None: u["status"]  = status
                self.save_users(data)
                return True
        return False

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
        data = [u for u in data if u["username"] != username]
        data.insert(0, {"username": username,
                        "public_key_path": pub_f,
                        "private_key_path": priv_f,
                        "avatar": None,
                        "status": "Hey, I'm using SCmess!"})
        self.save_users(data)
        return pub_pem.decode()

    def delete_user(self, username):
        users = self.load_users()
        new_users = []
        for u in users:
            if u["username"] == username:
                for k in ["public_key_path", "private_key_path"]:
                    p = u.get(k)
                    if p and os.path.exists(p):
                        try: os.remove(p)
                        except: pass
            else:
                new_users.append(u)
        self.save_users(new_users)

    @staticmethod
    def _oaep():
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)

    def encrypt_for(self, pub_key_path: str, plaintext: str) -> dict:
        aes_key = os.urandom(32)
        iv      = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv),
                     default_backend()).encryptor()
        ct = enc.update(plaintext.encode("utf-8")) + enc.finalize()
        with open(pub_key_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        enc_key = pub.encrypt(aes_key, self._oaep())
        return {"v": 2,
                "aes_key":    base64.b64encode(enc_key).decode(),
                "iv":         base64.b64encode(iv).decode(),
                "tag":        base64.b64encode(enc.tag).decode(),
                "ciphertext": base64.b64encode(ct).decode()}

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
        return ":".join(h[i:i+2] for i in range(0, 16, 2))

    def encrypt_file(self, file_data, pub_key_path):
        aes_key = os.urandom(32); iv = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv),
                     default_backend()).encryptor()
        ct = enc.update(file_data) + enc.finalize()
        with open(pub_key_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        enc_key = pub.encrypt(aes_key, self._oaep())
        return {"v": 3, "type": "file",
                "aes_key": base64.b64encode(enc_key).decode(),
                "iv":      base64.b64encode(iv).decode(),
                "tag":     base64.b64encode(enc.tag).decode(),
                "data":    base64.b64encode(ct).decode()}

    def decrypt_file(self, payload, priv_key_path):
        enc_key = base64.b64decode(payload["aes_key"])
        iv      = base64.b64decode(payload["iv"])
        tag     = base64.b64decode(payload["tag"])
        ct      = base64.b64decode(payload["data"])
        with open(priv_key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), None, default_backend())
        aes_key = priv.decrypt(enc_key, self._oaep())
        dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag),
                     default_backend()).decryptor()
        return dec.update(ct) + dec.finalize()

    # ── Изображения ─────────────────────────────────────────
    def compress_image(self, image_path_or_data, max_dim=1280, quality=82):
        """Умное сжатие: сохраняет пропорции, качество, режет только слишком большие."""
        try:
            if isinstance(image_path_or_data, (bytes, bytearray)):
                src = io.BytesIO(image_path_or_data)
            else:
                src = image_path_or_data

            if HAS_PIL:
                img = PILImage.open(src)
                # Сохраняем EXIF-ориентацию
                try:
                    img = ImageOps.exif_transpose(img)
                except Exception:
                    pass
                # RGB
                if img.mode not in ("RGB", "L"):
                    bg = PILImage.new("RGB", img.size, (255, 255, 255))
                    if img.mode == "RGBA":
                        bg.paste(img, mask=img.split()[3])
                    else:
                        bg.paste(img.convert("RGB"))
                    img = bg
                elif img.mode == "L":
                    img = img.convert("RGB")
                # Уменьшаем только если нужно
                w, h = img.size
                if max(w, h) > max_dim:
                    img.thumbnail((max_dim, max_dim), PILImage.Resampling.LANCZOS)
                out = io.BytesIO()
                img.save(out, format="JPEG", quality=quality, optimize=True)
                return out.getvalue(), img.size
            else:
                # Android без PIL
                return self._compress_android(image_path_or_data, max_dim, quality)
        except Exception as e:
            print(f"[Image] compress error: {e}")
            if isinstance(image_path_or_data, str):
                with open(image_path_or_data, "rb") as f:
                    data = f.read()
                return data, (0, 0)
            return image_path_or_data, (0, 0)

    def _compress_android(self, image_path, max_dim, quality):
        try:
            BitmapFactory = _autoclass("android.graphics.BitmapFactory")
            ByteArrayOutputStream = _autoclass("java.io.ByteArrayOutputStream")
            CompressFormat = _autoclass("android.graphics.Bitmap$CompressFormat")
            opts = _autoclass("android.graphics.BitmapFactory$Options")()
            opts.inJustDecodeBounds = True
            BitmapFactory.decodeFile(image_path, opts)
            w, h = opts.outWidth, opts.outHeight
            s = 1
            while max(w // s, h // s) > max_dim:
                s *= 2
            opts.inJustDecodeBounds = False
            opts.inSampleSize = s
            bmp = BitmapFactory.decodeFile(image_path, opts)
            if not bmp:
                raise Exception("decodeFile failed")
            stream = ByteArrayOutputStream()
            bmp.compress(CompressFormat.JPEG, quality, stream)
            data = bytes(stream.toByteArray())
            bmp.recycle()
            stream.close()
            return data, (opts.outWidth // s, opts.outHeight // s)
        except Exception as e:
            print(f"[Image] Android compress error: {e}")
            with open(image_path, "rb") as f:
                return f.read(), (0, 0)

    def make_thumb(self, data_or_path, size=240):
        """Thumbnail в base64 для превью в чате."""
        try:
            if HAS_PIL:
                if isinstance(data_or_path, (bytes, bytearray)):
                    img = PILImage.open(io.BytesIO(data_or_path))
                else:
                    img = PILImage.open(data_or_path)
                try:
                    img = ImageOps.exif_transpose(img)
                except Exception:
                    pass
                if img.mode != "RGB":
                    img = img.convert("RGB")
                img.thumbnail((size, size), PILImage.Resampling.LANCZOS)
                out = io.BytesIO()
                img.save(out, format="JPEG", quality=72, optimize=True)
                return base64.b64encode(out.getvalue()).decode(), img.size
        except Exception as e:
            print(f"[Image] thumb error: {e}")
        return None, (0, 0)


# ─────────────────────────────────────────────────────────────
# БД
# ─────────────────────────────────────────────────────────────

class MessageDB:
    def __init__(self, data_dir, username=None):
        if username:
            self.path = os.path.join(data_dir, f"messages_{username}.db")
        else:
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
                direction TEXT NOT NULL,
                text TEXT NOT NULL,
                ts INTEGER NOT NULL,
                status TEXT DEFAULT 'sent',
                server_id TEXT,
                is_group INTEGER DEFAULT 0,
                group_id TEXT,
                media_type TEXT,
                media_path TEXT,
                media_thumb TEXT,
                img_w INTEGER DEFAULT 0,
                img_h INTEGER DEFAULT 0
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS chats (
                peer TEXT PRIMARY KEY,
                last_msg TEXT,
                last_ts INTEGER,
                unread INTEGER DEFAULT 0,
                is_group INTEGER DEFAULT 0,
                group_name TEXT,
                group_members TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                group_name TEXT NOT NULL,
                members TEXT NOT NULL,
                created_ts INTEGER
            )""")
            # Добавляем колонки если не было
            for col in ["img_w INTEGER DEFAULT 0", "img_h INTEGER DEFAULT 0"]:
                try:
                    c.execute(f"ALTER TABLE messages ADD COLUMN {col}")
                except Exception:
                    pass

    def add_message(self, peer, direction, text, ts=None, status="sent",
                    server_id=None, is_group=False, group_id=None,
                    media_type=None, media_path=None, media_thumb=None,
                    img_w=0, img_h=0):
        ts = ts or int(time.time() * 1000)
        with self._conn() as c:
            c.execute(
                "INSERT INTO messages (peer,direction,text,ts,status,server_id,"
                "is_group,group_id,media_type,media_path,media_thumb,img_w,img_h) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (peer, direction, text, ts, status, server_id,
                 1 if is_group else 0, group_id, media_type, media_path,
                 media_thumb, img_w, img_h))
            preview = "Фото" if media_type == "image" else text
            c.execute(
                "INSERT OR REPLACE INTO chats (peer,last_msg,last_ts,unread,is_group) "
                "VALUES (?,?,?, COALESCE((SELECT unread FROM chats WHERE peer=?),0)"
                " + CASE ? WHEN 'in' THEN 1 ELSE 0 END, ?)",
                (peer, preview[:60], ts, peer, direction, 1 if is_group else 0))
        return ts

    def get_messages(self, peer, limit=200):
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM messages WHERE peer=? ORDER BY ts ASC LIMIT ?",
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

    def create_group(self, group_name, members):
        group_id = f"grp_{int(time.time()*1000)}"
        with self._conn() as c:
            c.execute(
                "INSERT INTO groups (group_id,group_name,members,created_ts) VALUES (?,?,?,?)",
                (group_id, group_name, json.dumps(members), int(time.time()*1000)))
            c.execute(
                "INSERT INTO chats (peer,last_msg,last_ts,unread,is_group,group_name,group_members) "
                "VALUES (?,?,?,0,1,?,?)",
                (group_id, "Группа создана", int(time.time()*1000),
                 group_name, json.dumps(members)))
        return group_id

    def get_group(self, group_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM groups WHERE group_id=?",
                            (group_id,)).fetchone()
        if row:
            r = dict(row)
            r["members"] = json.loads(r["members"])
            return r
        return None

    def get_groups(self):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM groups ORDER BY created_ts DESC").fetchall()
        out = []
        for r in rows:
            g = dict(r)
            g["members"] = json.loads(g["members"])
            out.append(g)
        return out


# ─────────────────────────────────────────────────────────────
# WS КЛИЕНТ (без внешних зависимостей)
# ─────────────────────────────────────────────────────────────

import socket, struct

class WSClient:
    PING_INTERVAL  = 25   # сек, пинг сервера
    RECONNECT_BASE = 2    # сек, базовая задержка переподключения
    RECONNECT_MAX  = 30   # сек, максимальная задержка

    def __init__(self):
        self._sock  = None
        self._lock  = threading.Lock()
        self.connected = False
        self._recv_thread = None
        self._ping_thread = None
        self.on_message    = None
        self.on_connect    = None
        self.on_disconnect = None
        self._reconnect_enabled = True
        self._last_host = None
        self._last_port = None
        self._last_path = "/"
        self._reconnect_delay = self.RECONNECT_BASE

    def connect(self, host, port, path="/"):
        self._last_host = host
        self._last_port = port
        self._last_path = path
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
            s.connect((host, int(port)))
            # WS Handshake
            key = base64.b64encode(os.urandom(16)).decode()
            hs  = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {host}:{port}\r\n"
                   f"Upgrade: websocket\r\n"
                   f"Connection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\n"
                   f"Sec-WebSocket-Version: 13\r\n\r\n")
            s.sendall(hs.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1)
                if not chunk:
                    raise ConnectionError("No response from server")
                resp += chunk
            if b"101" not in resp:
                raise ConnectionError("WS handshake failed")
            s.settimeout(None)
            self._sock = s
            self.connected = True
            self._reconnect_delay = self.RECONNECT_BASE   # сброс после успеха
            if self.on_connect:
                Clock.schedule_once(lambda dt: self.on_connect(), 0)
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            self._ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
            self._ping_thread.start()
            return True
        except Exception as e:
            self.connected = False
            if self._reconnect_enabled and self._last_host:
                self._schedule_reconnect()
            raise e

    def _recv_loop(self):
        try:
            while self.connected:
                opcode, frame = self._read_frame()
                if opcode is None:
                    break
                if opcode == 8:   # close
                    break
                if opcode == 9:   # ping — отвечаем pong
                    self._send_raw(0x8A, frame or b"")
                    continue
                if opcode == 10:  # pong — игнорируем
                    continue
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
            was_conn = self.connected
            self.connected = False
            if self.on_disconnect:
                Clock.schedule_once(lambda dt: self.on_disconnect(), 0)
            if was_conn and self._reconnect_enabled and self._last_host:
                self._schedule_reconnect()

    def _ping_loop(self):
        """Отправляем пинг каждые PING_INTERVAL секунд."""
        while self.connected:
            time.sleep(self.PING_INTERVAL)
            if not self.connected:
                break
            try:
                self._send_raw(0x89, b"ping")  # WS ping
            except Exception:
                break

    def _send_raw(self, opcode_byte, data: bytes):
        length = len(data)
        if length <= 125:
            header = bytes([opcode_byte, length])
        elif length <= 65535:
            header = bytes([opcode_byte, 126]) + struct.pack("!H", length)
        else:
            header = bytes([opcode_byte, 127]) + struct.pack("!Q", length)
        with self._lock:
            if self._sock:
                self._sock.sendall(header + data)

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
        if not header:
            return None, None
        b1, b2   = header
        opcode   = b1 & 0x0F
        masked   = (b2 & 0x80) != 0
        length   = b2 & 0x7F
        if length == 126:
            ext = recv_exact(2)
            if not ext: return None, None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = recv_exact(8)
            if not ext: return None, None
            length = struct.unpack("!Q", ext)[0]
        mask = recv_exact(4) if masked else None
        data = recv_exact(length)
        if data is None:
            return None, None
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode in (9, 10):   # ping / pong — возвращаем raw bytes
            return opcode, data
        if opcode == 8:
            return 8, None
        return opcode, data.decode("utf-8", errors="replace")

    def send(self, data: dict):
        if not self.connected or not self._sock:
            return False
        try:
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            length  = len(payload)
            mask    = os.urandom(4)
            masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
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
            if self._reconnect_enabled and self._last_host:
                self._schedule_reconnect()
            return False

    def _schedule_reconnect(self):
        delay = self._reconnect_delay
        self._reconnect_delay = min(self._reconnect_delay * 2, self.RECONNECT_MAX)
        def _try():
            time.sleep(delay)
            if not self.connected and self._reconnect_enabled and self._last_host:
                try:
                    self.connect(self._last_host, self._last_port, self._last_path)
                except Exception:
                    if self._reconnect_enabled:
                        self._schedule_reconnect()
        threading.Thread(target=_try, daemon=True).start()

    def disconnect(self):
        self._reconnect_enabled = False
        self.connected = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None


# ─────────────────────────────────────────────────────────────
# СЕТЕВОЙ МЕНЕДЖЕР
# ─────────────────────────────────────────────────────────────

class NetworkManager:
    def __init__(self):
        self.ws = WSClient()
        self.ws.on_message    = self._on_message
        self.ws.on_connect    = self._on_connect
        self.ws.on_disconnect = self._on_disconnect
        self.host = ""
        self.port = 8765
        self._pending_requests = {}
        self._req_counter = 0
        self._username   = ""
        self._priv_key_path = ""
        self._pub_key_pem   = ""
        self._on_done = None
        self._offline_queue = deque(maxlen=300)

        self.on_status_change    = None
        self.on_incoming_message = None
        self.on_incoming_image   = None
        self.on_contact_request  = None
        self.on_request_accepted = None
        self.on_message_status   = None
        self.on_user_status      = None

    def connect(self, host, port, username, priv_key_path, pub_key_pem, on_done=None):
        self.host = host
        self.port = port
        self._username      = username
        self._priv_key_path = priv_key_path
        self._pub_key_pem   = pub_key_pem
        self._on_done       = on_done
        self.ws._reconnect_enabled = True
        def _thread():
            try:
                self.ws.connect(host, port)
            except Exception as e:
                if on_done:
                    Clock.schedule_once(lambda dt: on_done(False, str(e)), 0)
        threading.Thread(target=_thread, daemon=True).start()

    def _on_connect(self):
        self.ws.send({"type": "auth",
                      "username": self._username,
                      "pubkey":   self._pub_key_pem})

    def _on_disconnect(self):
        if self.on_status_change:
            self.on_status_change(False)

    def disconnect(self):
        self.ws.disconnect()

    def _on_message(self, msg: dict):
        t = msg.get("type")

        if t == "auth_ok":
            if self.on_status_change:
                self.on_status_change(True)
            if self._on_done:
                self._on_done(True, None)
            self.ws.send({"type": "get_pending"})
            self._flush_offline_queue()

        elif t == "auth_error":
            if self._on_done:
                self._on_done(False, msg.get("reason", "Ошибка авторизации"))

        elif t == "message":
            self._handle_incoming_text(msg)

        elif t == "image_message":
            self._handle_incoming_image(msg)

        elif t == "contact_request":
            if self.on_contact_request:
                self.on_contact_request(msg["from"], msg["pubkey"])

        elif t == "contact_accepted":
            if self.on_request_accepted:
                self.on_request_accepted(msg["peer"], msg["pubkey"])

        elif t == "message_status":
            if self.on_message_status:
                self.on_message_status(msg["server_id"], msg["status"])

        elif t == "user_status":
            if self.on_user_status:
                self.on_user_status(msg.get("username"), msg.get("online", False))

        elif t == "user_info":
            rid = msg.get("req_id")
            if rid and rid in self._pending_requests:
                self._pending_requests.pop(rid)(msg)

        elif t == "error":
            rid = msg.get("req_id")
            if rid and rid in self._pending_requests:
                self._pending_requests.pop(rid)({"type": "error",
                                                  "reason": msg.get("reason", "")})

    def _handle_incoming_text(self, msg):
        app = App.get_running_app()
        try:
            account = app.my_account
            if not account:
                return
            payload = msg["payload"]
            # Пробуем расшифровать — может быть групповое или обычное
            if isinstance(payload, dict) and payload.get("type") == "group_message_gcm":
                text = app.backend.decrypt_group(payload)
            else:
                text = app.backend.decrypt_payload(account["private_key_path"], payload)
            peer = msg["from"]
            ts   = msg.get("ts", int(time.time() * 1000))
            sid  = msg.get("server_id")
            group_id = msg.get("group_id")
            # Для групповых — peer = group_id
            peer_key = group_id if group_id else peer
            is_group = bool(group_id)
            app.db.add_message(peer_key, "in", text, ts=ts, status="delivered",
                               server_id=sid, is_group=is_group, group_id=group_id)
            self.ws.send({"type": "ack", "server_id": sid})
            if self.on_incoming_message:
                self.on_incoming_message(peer_key, peer, text, ts, sid)
        except Exception as e:
            print(f"[WS] decrypt error: {e}")

    def _handle_incoming_image(self, msg):
        app = App.get_running_app()
        try:
            account = app.my_account
            if not account:
                return
            file_data = app.backend.decrypt_file(msg["payload"],
                                                  account["private_key_path"])
            peer = msg["from"]
            ts   = msg.get("ts", int(time.time() * 1000))
            sid  = msg.get("server_id")
            # Сохраняем файл
            media_dir = os.path.join(app.user_data_dir, "media")
            os.makedirs(media_dir, exist_ok=True)
            img_path = os.path.join(media_dir, f"img_in_{ts}.jpg")
            with open(img_path, "wb") as f:
                f.write(file_data)
            thumb_b64, sz = app.backend.make_thumb(file_data)
            app.db.add_message(peer, "in", "Фото", ts=ts, status="delivered",
                               server_id=sid, media_type="image",
                               media_path=img_path, media_thumb=thumb_b64,
                               img_w=sz[0], img_h=sz[1])
            self.ws.send({"type": "ack", "server_id": sid})
            if self.on_incoming_image:
                self.on_incoming_image(peer, img_path, thumb_b64, ts, sid)
        except Exception as e:
            print(f"[WS] image decrypt error: {e}")

    def send_message(self, to: str, text: str, pub_key_path: str):
        app = App.get_running_app()
        try:
            payload = app.backend.encrypt_for(pub_key_path, text)
            ts = int(time.time() * 1000)
            self._send_or_queue({"type": "message", "to": to, "payload": payload, "ts": ts})
            return ts
        except Exception as e:
            print(f"[WS] send error: {e}")
            return None

    def send_image(self, to: str, file_data: bytes, pub_key_path: str):
        app = App.get_running_app()
        try:
            payload = app.backend.encrypt_file(file_data, pub_key_path)
            ts = int(time.time() * 1000)
            self._send_or_queue({"type": "image_message", "to": to,
                                 "payload": payload, "ts": ts})
            return ts
        except Exception as e:
            print(f"[WS] send image error: {e}")
            return None

    def send_group_message(self, to: str, text: str, pub_key_path: str, group_id: str, ts: int):
        app = App.get_running_app()
        try:
            payload = app.backend.encrypt_for(pub_key_path, text)
            self._send_or_queue({
                "type": "message", "to": to, "payload": payload,
                "ts": ts, "group_id": group_id,
            })
            return True
        except Exception as e:
            print(f"[WS] group send error: {e}")
            return False

    def _send_or_queue(self, msg: dict):
        sent = self.ws.send(msg)
        if not sent:
            self._offline_queue.append(msg)
        return sent

    def _flush_offline_queue(self):
        if not self.ws.connected or not self._offline_queue:
            return
        items = list(self._offline_queue)
        self._offline_queue.clear()
        for m in items:
            if not self.ws.send(m):
                self._offline_queue.appendleft(m)
                break

    def request_contact(self, username: str):
        self.ws.send({"type": "contact_request", "to": username})

    def accept_contact(self, username: str, pub_key_pem: str):
        self.ws.send({"type": "contact_accept", "to": username, "pubkey": pub_key_pem})

    def reject_contact(self, username: str):
        self.ws.send({"type": "contact_reject", "to": username})

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
        t   = app.theme
        accounts = [u for u in app.backend.load_users()
                    if u.get("private_key_path") and u.get("public_key_path")]
        if not accounts:
            box.add_widget(Label(
                text="Аккаунтов пока нет.\nСоздайте первый!",
                font_size="14sp", color=t["label_muted"],
                size_hint_y=None, height=dp(56),
                halign="center", text_size=(Window.width * 0.8, None)))
            return
        for acc in accounts:
            st = acc.get("status", "").strip()
            title = f"@{acc['username']}"
            text = f"{title}\n{st}" if st else title
            outer = Button(
                text=text,
                size_hint=(1, None),
                height=dp(72),
                background_normal="",
                background_color=t["btn_bg"],
                color=t["btn_text"],
                halign="left",
                valign="middle",
                text_size=(Window.width * 0.86, None),
                padding=(dp(16), dp(10)),
            )
            outer.bind(on_release=lambda _, a=acc: self._select_account(a))
            box.add_widget(outer)

    def _select_account(self, account):
        app = App.get_running_app()
        prev = app.my_account
        if prev and prev.get("username") != account.get("username"):
            if app.net.ws.connected:
                app.net.disconnect()
        app.my_account = account
        # Изолируем БД по пользователю
        app.db = MessageDB(app.user_data_dir, account["username"])
        app.root.current = "chats"

    def open_create_account(self):
        self.manager.current = "create_account"

    def setup_pin(self):
        app = App.get_running_app()
        t   = app.theme
        mv  = ModalView(size_hint=(0.88, None), height=dp(290),
                        background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text="Настройка PIN-кода", font_size="17sp", bold=True,
                             color=t["title_color"], size_hint_y=None, height=dp(30)))
        inp = TextInput(hint_text="Введите PIN (4-8 цифр)",
                       background_color=t["log_bg"], foreground_color=t["input_fg"],
                       font_size="16sp", size_hint_y=None, height=dp(50),
                       use_bubble=False, use_handles=False, multiline=False,
                       padding=[14,11,14,11], cursor_color=t["accent"],
                       password=True, input_filter="int")
        status = Label(text="Оставьте пустым для отключения PIN",
                      font_size="12sp", color=t["label_muted"],
                      size_hint_y=None, height=dp(24), halign="center",
                      text_size=(Window.width * 0.78, None))
        card.add_widget(inp); card.add_widget(status)
        row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        save_btn   = Button(text="Сохранить", background_normal="",
                            background_color=t["accent"], color=[1,1,1,1], bold=True)
        cancel_btn = Button(text="Отмена", background_normal="",
                            background_color=t["btn_bg"], color=t["btn_text"])
        cancel_btn.bind(on_release=mv.dismiss)
        row.add_widget(save_btn); row.add_widget(cancel_btn)
        card.add_widget(row)
        mv.add_widget(card)

        def _save(_):
            pin = inp.text.strip()
            if pin and not (4 <= len(pin) <= 8):
                status.text = "PIN должен быть 4-8 цифр"
                status.color = [1, 0.3, 0.3, 1]
                return
            app._save_pin(hashlib.sha256(pin.encode()).hexdigest() if pin else None)
            mv.dismiss()
            show_toast("PIN сохранён" if pin else "PIN отключён")

        save_btn.bind(on_release=_save)
        mv.open()


class PinScreen(Screen):
    def on_enter(self):
        self.ids.pin_inp.text    = ""
        self.ids.pin_status.text = ""
        Clock.schedule_once(lambda dt: setattr(self.ids.pin_inp, "focus", True), 0.1)

    def check_pin(self):
        app = App.get_running_app()
        pin = self.ids.pin_inp.text.strip()
        if not pin:
            self.ids.pin_status.text = "Введите PIN-код"
            return
        if hashlib.sha256(pin.encode()).hexdigest() == app._load_pin():
            app.root.current = "launch"
        else:
            self.ids.pin_status.text = "Неверный PIN-код"
            self.ids.pin_inp.text = ""


class CreateAccountScreen(Screen):
    _keysize = 4096

    def select_keysize(self, size):
        self._keysize = size

    def do_create(self):
        username = self.ids.username_inp.text.strip().lstrip("@")
        if not username or not re.match(r"^[a-zA-Z0-9_]{3,32}$", username):
            self.ids.status_lbl.text  = "Имя: 3-32 символа, латиница/цифры/_"
            self.ids.status_lbl.color = [1, 0.3, 0.3, 1]
            return
        self.ids.status_lbl.text  = f"Генерируем {self._keysize}-бит ключи..."
        self.ids.status_lbl.color = App.get_running_app().theme["label_muted"]

        def _gen():
            try:
                app = App.get_running_app()
                app.backend.generate_key_pair(username, self._keysize)
                def _done(dt):
                    app.my_account = app.backend.get_my_account()
                    app.db = MessageDB(app.user_data_dir, username)
                    self.manager.current = "chats"
                Clock.schedule_once(_done, 0)
            except Exception as e:
                Clock.schedule_once(
                    lambda dt: (setattr(self.ids.status_lbl, "text", f"Ошибка: {e}"),
                                setattr(self.ids.status_lbl, "color", [1, 0.3, 0.3, 1])), 0)
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
            acc  = app.my_account
            name = f"@{acc['username']}" if acc else ""
            lbl.text  = f"Подключено {name} ({app.net.host}:{app.net.port})"
            lbl.color = app.theme["success_bg"]
        else:
            lbl.text  = "Нет подключения"
            lbl.color = app.theme["label_muted"]

    def do_connect(self):
        host = self.ids.host_inp.text.strip()
        port_raw = self.ids.port_inp.text.strip() or "8765"
        app  = App.get_running_app()
        acc  = app.my_account
        if not acc:
            show_msg("Ошибка", "Сначала создайте или выберите аккаунт")
            return
        if not host:
            show_msg("Ошибка", "Введите адрес сервера")
            return
        try:
            port = int(port_raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            show_msg("Ошибка", "Порт должен быть числом 1..65535")
            return
        self.ids.conn_status.text  = "Подключение..."
        self.ids.conn_status.color = app.theme["label_muted"]
        pub_pem = app.backend.pubkey_pem(acc["public_key_path"])

        def _done(ok, err):
            self._update_status()
            if ok:
                app.save_server_settings(host, port)
                try:
                    app.root.get_screen("chats").update_net_badge()
                except Exception:
                    pass
            else:
                show_msg("Ошибка подключения", err or "Недоступен")

        try:
            app.net.connect(host, port, acc["username"],
                            acc["private_key_path"], pub_pem, on_done=_done)
        except Exception as e:
            self._update_status()
            show_msg("Ошибка подключения", str(e))

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
                text="Нет чатов.\nНажмите кнопку 'Новый чат', чтобы начать переписку.",
                font_size="14sp", color=t["label_muted"],
                size_hint_y=None, height=dp(90),
                halign="center",
                text_size=(Window.width * 0.78, None)))
            return
        for chat in chats:
            self._add_chat_row(box, chat, t)

    def _add_chat_row(self, parent, chat, t):
        from kivy.uix.behaviors import ButtonBehavior

        class TapBox(ButtonBehavior, BoxLayout):
            pass

        peer     = chat["peer"]
        last_msg = chat.get("last_msg") or ""
        unread   = chat.get("unread", 0)
        last_ts  = chat.get("last_ts")
        is_group = bool(chat.get("is_group", 0))
        time_str = ""
        if last_ts:
            dt  = datetime.fromtimestamp(last_ts / 1000)
            now = datetime.now()
            time_str = dt.strftime("%H:%M") if dt.date() == now.date() else dt.strftime("%d.%m")

        outer = TapBox(orientation="vertical", size_hint_y=None, height=dp(70))
        outer.bind(on_release=lambda _, p=peer, g=is_group: self.open_chat(p, g))

        row = BoxLayout(size_hint_y=None, height=dp(69),
                        padding=[dp(12), dp(8), dp(12), dp(8)], spacing=dp(12))
        with row.canvas.before:
            Color(*t["bg_color"])
            Rectangle(pos=row.pos, size=row.size)
        row.bind(pos=lambda i, *_: _upd_row(i), size=lambda i, *_: _upd_row(i))
        def _upd_row(inst):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*t["bg_color"])
                Rectangle(pos=inst.pos, size=inst.size)

        # Аватар
        if is_group:
            name_for_ava = chat.get("group_name") or peer
        else:
            acc = App.get_running_app().backend.get_contact(peer)
            name_for_ava = peer
            ava_b64 = acc.get("avatar") if acc else None
        ava = make_avatar(name_for_ava, dp(46), None if is_group else (acc.get("avatar") if acc else None))
        row.add_widget(ava)

        info = BoxLayout(orientation="vertical", spacing=dp(3))
        top  = BoxLayout(size_hint_y=None, height=dp(22))
        display_name = (chat.get("group_name") or peer) if is_group else f"@{peer}"
        top.add_widget(Label(text=display_name, font_size="15sp", bold=True,
                             color=t["btn_text"], halign="left",
                             text_size=(Window.width * 0.54, None)))
        top.add_widget(Label(text=time_str, font_size="11sp",
                             color=t["label_muted"], size_hint_x=None,
                             width=dp(46), halign="right",
                             text_size=(dp(46), None)))
        info.add_widget(top)

        bot = BoxLayout(size_hint_y=None, height=dp(20))
        preview = (last_msg[:36] + "...") if len(last_msg) > 36 else last_msg
        bot.add_widget(Label(text=preview, font_size="13sp",
                             color=t["label_muted"], halign="left",
                             text_size=(Window.width * 0.56, None)))
        if unread > 0:
            badge_txt = str(unread) if unread < 100 else "99+"
            badge = Label(text=badge_txt, font_size="11sp", color=[1,1,1,1],
                          size_hint_x=None, width=dp(24), halign="center", bold=True)
            with badge.canvas.before:
                Color(*t["accent"])
                Ellipse(pos=badge.pos, size=(dp(22), dp(22)))
            badge.bind(pos=lambda i, *_: _ub(i), size=lambda i, *_: _ub(i))
            def _ub(inst):
                inst.canvas.before.clear()
                with inst.canvas.before:
                    Color(*t["accent"])
                    Ellipse(pos=inst.pos, size=(dp(22), dp(22)))
            bot.add_widget(badge)
        info.add_widget(bot)
        row.add_widget(info)

        sep = Widget(size_hint_y=None, height=dp(1))
        with sep.canvas:
            Color(*t["chat_list_sep"])
            Rectangle(pos=sep.pos, size=sep.size)
        sep.bind(pos=lambda i, *_: _us(i), size=lambda i, *_: _us(i))
        def _us(inst):
            inst.canvas.clear()
            with inst.canvas:
                Color(*t["chat_list_sep"])
                Rectangle(pos=inst.pos, size=inst.size)

        outer.add_widget(row)
        outer.add_widget(sep)
        parent.add_widget(outer)

    def update_net_badge(self):
        app = App.get_running_app()
        try:
            dot = self.ids.net_dot
            dot.canvas.clear()
            color = app.theme["online_dot"] if app.net.ws.connected else app.theme["offline_dot"]
            with dot.canvas:
                Color(*color)
                Ellipse(pos=dot.pos, size=dot.size)
        except Exception:
            pass

    def open_chat(self, peer, is_group=False):
        app = App.get_running_app()
        app.db.mark_read(peer)
        chat_screen = app.root.get_screen("chat")
        chat_screen.load_chat(peer, is_group)
        app.root.current = "chat"

    def on_search(self, query):
        box   = self.ids.chats_list
        box.clear_widgets()
        app   = App.get_running_app()
        t     = app.theme
        chats = app.db.get_chats()
        if query:
            q = query.lower()
            chats = [c for c in chats
                     if q in c["peer"].lower()
                     or q in (c.get("group_name") or "").lower()]
        for chat in chats:
            self._add_chat_row(box, chat, t)

    def new_chat_dialog(self):
        app = App.get_running_app()
        t   = app.theme
        mv  = ModalView(size_hint=(0.90, None), height=dp(330),
                        background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text="Новый чат", font_size="18sp", bold=True,
                              color=t["title_color"], size_hint_y=None, height=dp(32)))
        inp = TextInput(hint_text="@username",
                        background_color=t["input_bg"], foreground_color=t["input_fg"],
                        font_size="15sp", size_hint_y=None, height=dp(50),
                        use_bubble=False, use_handles=False, multiline=False,
                        padding=[14, 11, 14, 11], cursor_color=t["accent"])
        status = Label(text="", font_size="12sp", color=t["label_muted"],
                       size_hint_y=None, height=dp(22), halign="left",
                       text_size=(Window.width * 0.76, None))
        card.add_widget(inp); card.add_widget(status)

        find_btn  = Button(text="Найти / написать", background_normal="",
                           background_color=t["accent"], color=[1,1,1,1], bold=True,
                           size_hint_y=None, height=dp(50))
        group_btn = Button(text="Создать группу", background_normal="",
                           background_color=t["success_bg"], color=[1,1,1,1], bold=True,
                           size_hint_y=None, height=dp(46))
        cancel_btn = Button(text="Отмена", background_normal="",
                            background_color=t["btn_bg"], color=t["btn_text"],
                            size_hint_y=None, height=dp(46))
        cancel_btn.bind(on_release=mv.dismiss)
        card.add_widget(find_btn); card.add_widget(group_btn); card.add_widget(cancel_btn)
        mv.add_widget(card)

        def _find(_):
            username = inp.text.strip().lstrip("@")
            if not username:
                return
            contact = app.backend.get_contact(username)
            if contact and contact.get("public_key_path"):
                mv.dismiss(); self.open_chat(username)
                return
            if not app.net.ws.connected:
                status.text  = "Нет соединения с сервером"
                status.color = [1, 0.3, 0.3, 1]
                return
            status.text  = "Поиск на сервере..."
            status.color = t["label_muted"]

            def _found(result):
                if result.get("type") == "error" or "pubkey" not in result:
                    status.text  = f"@{username} не найден"
                    status.color = [1, 0.3, 0.3, 1]
                    return
                app.backend.add_contact(username, result["pubkey"])
                my_pub = app.backend.pubkey_pem(app.my_account["public_key_path"])
                app.net.accept_contact(username, my_pub)
                mv.dismiss()
                self.open_chat(username)

            app.net.find_user(username, _found)

        find_btn.bind(on_release=_find)
        group_btn.bind(on_release=lambda _: (mv.dismiss(), self.create_group_dialog()))
        mv.open()

    def open_menu(self):
        """3-точечное меню — чистое, без квадратов."""
        app = App.get_running_app()
        t   = app.theme
        acc = app.my_account
        mv  = ModalView(size_hint=(None, None), size=(dp(240), dp(10)),
                        background_color=[0,0,0,0], auto_dismiss=True)
        mv.pos_hint = {"right": 0.98, "top": 0.94}

        card = BoxLayout(orientation="vertical", padding=dp(6), spacing=dp(2))
        def _draw_card(*_):
            card.canvas.before.clear()
            with card.canvas.before:
                Color(0.10, 0.10, 0.15, 0.98)
                RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
        card.bind(pos=_draw_card, size=_draw_card)
        _draw_card()

        # Шапка с именем и статусом
        if acc:
            name_row = BoxLayout(size_hint_y=None, height=dp(36), spacing=dp(8),
                                 padding=[dp(10), dp(6), dp(10), dp(2)])
            ava = make_avatar(acc["username"], dp(28), acc.get("avatar"))
            name_row.add_widget(ava)
            name_col = BoxLayout(orientation="vertical")
            name_col.add_widget(Label(text=f"@{acc['username']}", font_size="14sp",
                                      bold=True, color=t["btn_text"], halign="left",
                                      text_size=(dp(160), None)))
            st = acc.get("status", "")
            if st:
                name_col.add_widget(Label(text=st, font_size="11sp",
                                          color=t["label_muted"], halign="left",
                                          text_size=(dp(160), None)))
            name_row.add_widget(name_col)
            card.add_widget(name_row)
            # Статус подключения
            is_conn = app.net.ws.connected
            conn_row = BoxLayout(size_hint_y=None, height=dp(26),
                                 padding=[dp(14), 0, dp(8), 0], spacing=dp(6))
            dot_lbl = Label(
                text="ON", font_size="10sp",
                color=t["online_dot"] if is_conn else t["offline_dot"],
                size_hint_x=None, width=dp(14))
            conn_lbl = Label(
                text=f"{'Подключено' if is_conn else 'Нет связи'}"
                     + (f"  {app.net.host}" if is_conn else ""),
                font_size="11sp", color=t["label_muted"], halign="left",
                text_size=(dp(200), None))
            conn_row.add_widget(dot_lbl); conn_row.add_widget(conn_lbl)
            card.add_widget(conn_row)
            # Разделитель
            sep = Widget(size_hint_y=None, height=dp(1))
            with sep.canvas:
                Color(*t["chat_list_sep"])
                Rectangle(pos=sep.pos, size=sep.size)
            sep.bind(pos=lambda i,*_: _upd_sep(i), size=lambda i,*_: _upd_sep(i))
            def _upd_sep(inst):
                inst.canvas.clear()
                with inst.canvas:
                    Color(*t["chat_list_sep"])
                    Rectangle(pos=inst.pos, size=inst.size)
            card.add_widget(sep)

        items = [
            ("Редактировать профиль",  lambda: (mv.dismiss(), self._edit_profile())),
            ("Сервер",                lambda: (mv.dismiss(), setattr(self.manager, "current", "server"))),
            ("Ключи",                 lambda: (mv.dismiss(), setattr(self.manager, "current", "keys"))),
            ("Сменить аккаунт",       lambda: (mv.dismiss(), self._switch_account())),
        ]
        for label, action in items:
            btn = Button(text=label, size_hint_y=None, height=dp(46),
                         background_normal="", background_color=[0,0,0,0],
                         color=t["btn_text"], halign="left", padding_x=dp(12),
                         font_size="14sp")
            btn.bind(on_release=lambda _, a=action: a())
            card.add_widget(btn)

        total_h = (dp(36) if acc else 0) + dp(26 + 1 + 6) + len(items) * dp(46) + dp(12)
        mv.height = total_h
        mv.size = (dp(240), total_h)
        mv.add_widget(card)
        mv.open()

    def _switch_account(self):
        App.get_running_app().my_account = None
        self.manager.current = "launch"

    def _edit_profile(self):
        app = App.get_running_app()
        t   = app.theme
        acc = app.my_account
        if not acc:
            return
        mv   = ModalView(size_hint=(0.92, None), height=dp(400),
                         background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text="Редактировать профиль", font_size="17sp", bold=True,
                             color=t["title_color"], size_hint_y=None, height=dp(32)))

        # Аватарка — кнопка выбора
        ava_row = BoxLayout(size_hint_y=None, height=dp(72), spacing=dp(14),
                            padding=[0, dp(4), 0, dp(4)])
        ava_widget = [make_avatar(acc["username"], dp(60), acc.get("avatar"))]
        ava_row.add_widget(ava_widget[0])

        ava_info = BoxLayout(orientation="vertical")
        ava_info.add_widget(Label(text="Аватарка", font_size="14sp",
                                  color=t["btn_text"], halign="left",
                                  text_size=(Window.width*0.6, None),
                                  size_hint_y=None, height=dp(22)))
        pick_btn = Button(text="Выбрать фото", background_normal="",
                          background_color=t["btn_bg"], color=t["accent"],
                          font_size="13sp", size_hint_y=None, height=dp(36))
        ava_info.add_widget(pick_btn)
        ava_row.add_widget(ava_info)
        card.add_widget(ava_row)

        new_avatar = [acc.get("avatar")]

        def _pick(_):
            _open_avatar_gallery(lambda b64: _on_avatar_picked(b64))

        def _on_avatar_picked(b64):
            new_avatar[0] = b64
            # Обновляем превью
            ava_row.remove_widget(ava_widget[0])
            ava_widget[0] = make_avatar(acc["username"], dp(60), b64)
            ava_row.add_widget(ava_widget[0], index=len(ava_row.children))

        pick_btn.bind(on_release=_pick)

        # Статус
        card.add_widget(Label(text="Статус:", font_size="13sp",
                             color=t["label_muted"], size_hint_y=None, height=dp(22),
                             halign="left", text_size=(Window.width*0.8, None)))
        status_inp = TextInput(text=acc.get("status", ""),
                              background_color=t["log_bg"],
                              foreground_color=t["input_fg"],
                              font_size="14sp", size_hint_y=None, height=dp(76),
                              use_bubble=False, use_handles=False,
                              multiline=True, padding=[14, 10, 14, 10],
                              cursor_color=t["accent"])
        card.add_widget(status_inp)

        info_lbl = Label(text="", font_size="12sp", color=t["label_muted"],
                        size_hint_y=None, height=dp(20))
        card.add_widget(info_lbl)

        row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        save_btn   = Button(text="Сохранить", background_normal="",
                            background_color=t["accent"], color=[1,1,1,1], bold=True)
        cancel_btn = Button(text="Отмена", background_normal="",
                            background_color=t["btn_bg"], color=t["btn_text"])
        cancel_btn.bind(on_release=mv.dismiss)
        row.add_widget(save_btn); row.add_widget(cancel_btn)
        card.add_widget(row)
        mv.add_widget(card)

        def _save(_):
            new_status = status_inp.text.strip()
            if app.backend.update_my_profile(acc["username"],
                                             avatar=new_avatar[0],
                                             status=new_status):
                acc["status"] = new_status
                acc["avatar"] = new_avatar[0]
                mv.dismiss()
                show_toast("Профиль сохранён")
            else:
                info_lbl.text = "Не удалось сохранить"
                info_lbl.color = [1, 0.3, 0.3, 1]

        save_btn.bind(on_release=_save)
        mv.open()

    def create_group_dialog(self):
        app = App.get_running_app()
        t   = app.theme
        mv  = ModalView(size_hint=(0.92, None), height=dp(500),
                        background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text="Создать группу", font_size="17sp", bold=True,
                             color=t["title_color"], size_hint_y=None, height=dp(32)))
        name_inp = TextInput(hint_text="Название группы",
                            background_color=t["log_bg"], foreground_color=t["input_fg"],
                            font_size="15sp", size_hint_y=None, height=dp(50),
                            use_bubble=False, use_handles=False, multiline=False,
                            padding=[14, 11, 14, 11], cursor_color=t["accent"])
        card.add_widget(name_inp)
        card.add_widget(Label(text="Выберите участников:", font_size="13sp",
                             color=t["label_muted"], size_hint_y=None, height=dp(26),
                             halign="left", text_size=(Window.width*0.8, None)))
        scroll = ScrollView(size_hint_y=None, height=dp(250))
        cbox   = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(4))
        cbox.bind(minimum_height=cbox.setter("height"))
        contacts = [u for u in app.backend.load_users()
                    if u.get("public_key_path") and not u.get("private_key_path")]
        selected = {}
        if not contacts:
            cbox.add_widget(Label(text="Нет контактов", font_size="13sp",
                                  color=t["label_muted"],
                                  size_hint_y=None, height=dp(40)))
        else:
            for c in contacts:
                uname = c["username"]
                selected[uname] = False
                row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(10),
                               padding=[dp(6), dp(4), dp(6), dp(4)])
                chk = Button(text="[ ]", size_hint_x=None, width=dp(38),
                             background_normal="", background_color=t["btn_bg"],
                             color=t["label_muted"], font_size="18sp")
                def _make_toggle(btn, un):
                    def toggle(_):
                        selected[un] = not selected[un]
                        btn.text             = "[x]" if selected[un] else "[ ]"
                        btn.color            = t["accent"] if selected[un] else t["label_muted"]
                        btn.background_color = (t["btn_border"] if selected[un] else t["btn_bg"])
                    return toggle
                chk.bind(on_release=_make_toggle(chk, uname))
                row.add_widget(chk)
                row.add_widget(Label(text=f"@{uname}", font_size="14sp",
                                    color=t["btn_text"], halign="left",
                                    text_size=(Window.width*0.58, None)))
                cbox.add_widget(row)
        scroll.add_widget(cbox)
        card.add_widget(scroll)
        status = Label(text="", font_size="12sp", color=t["label_muted"],
                      size_hint_y=None, height=dp(20))
        card.add_widget(status)
        row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        create_btn = Button(text="Создать", background_normal="",
                           background_color=t["accent"], color=[1,1,1,1], bold=True)
        cancel_btn = Button(text="Отмена", background_normal="",
                           background_color=t["btn_bg"], color=t["btn_text"])
        cancel_btn.bind(on_release=mv.dismiss)
        row.add_widget(create_btn); row.add_widget(cancel_btn)
        card.add_widget(row)
        mv.add_widget(card)

        def _create(_):
            gname = name_inp.text.strip()
            if not gname:
                status.text = "Введите название"; status.color = [1,0.3,0.3,1]; return
            members = [u for u, s in selected.items() if s]
            if not members:
                status.text = "Выберите участников"; status.color = [1,0.3,0.3,1]; return
            gid = app.db.create_group(gname, members)
            mv.dismiss()
            self.open_chat(gid, is_group=True)
            show_toast(f"Группа «{gname}» создана")

        create_btn.bind(on_release=_create)
        mv.open()


# ─────────────────────────────────────────────────────────────
# ВЫБОР АВАТАРКИ / КАРТИНКИ — общий хелпер
# ─────────────────────────────────────────────────────────────

def _open_avatar_gallery(on_picked):
    """Открывает галерею для выбора аватарки (результат — base64 jpg)."""
    if platform != "android":
        show_msg("Недоступно", "Выбор аватарки работает на Android")
        return
    _request_image_pick(lambda path: _avatar_from_path(path, on_picked))


def _avatar_from_path(path, callback):
    try:
        app = App.get_running_app()
        compressed, _ = app.backend.compress_image(path, max_dim=256, quality=80)
        b64 = base64.b64encode(compressed).decode()
        Clock.schedule_once(lambda dt: callback(b64), 0)
    except Exception as e:
        Clock.schedule_once(lambda dt: show_msg("Ошибка", str(e)), 0)


def _request_image_pick(on_path):
    """Запрашивает выбор одного изображения из галереи Android."""
    try:
        from android.permissions import request_permissions, Permission
        from android import activity
        from jnius import autoclass

        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        BuildVersion   = autoclass("android.os.Build$VERSION")

        permissions = []
        if BuildVersion.SDK_INT >= 33:
            permissions.append("android.permission.READ_MEDIA_IMAGES")
        else:
            permissions.append(Permission.READ_EXTERNAL_STORAGE)

        def _do_pick():
            Intent         = autoclass("android.content.Intent")
            intent = Intent()
            intent.setType("image/*")
            intent.setAction(Intent.ACTION_GET_CONTENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)

            def _on_result(req_code, result_code, intent_data):
                if req_code != 2020:
                    return
                activity.unbind(on_activity_result=_on_result)
                if result_code != -1:
                    return
                if not intent_data:
                    return
                try:
                    uri   = intent_data.getData()
                    if not uri:
                        return
                    path  = _uri_to_path(uri)
                    if path:
                        Clock.schedule_once(lambda dt: on_path(path), 0)
                except Exception as e:
                    Clock.schedule_once(lambda dt: show_msg("Ошибка", str(e)), 0)

            activity.bind(on_activity_result=_on_result)
            PythonActivity.mActivity.startActivityForResult(
                Intent.createChooser(intent, "Выбрать фото"), 2020)

        def _on_perm(perms, grants):
            if all(grants):
                _do_pick()
            else:
                Clock.schedule_once(
                    lambda dt: show_msg("Ошибка", "Нет разрешения для галереи"), 0)

        # На Android безопаснее единообразно запрашивать разрешение,
        # чем полагаться на check_permission для разных API уровней.
        request_permissions(permissions, _on_perm)
    except Exception as e:
        Clock.schedule_once(lambda dt: show_msg("Ошибка", str(e)), 0)


def _uri_to_path(uri):
    """Конвертирует Android URI в локальный путь через ContentResolver."""
    try:
        from jnius import autoclass
        app = App.get_running_app()
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        resolver = PythonActivity.mActivity.getContentResolver()
        stream   = resolver.openInputStream(uri)
        if stream is None:
            return None
        tmp_path   = os.path.join(app.user_data_dir,
                                  f"_pick_{int(time.time()*1000)}.jpg")
        with open(tmp_path, "wb") as f:
            while True:
                b = stream.read()
                if b == -1:
                    break
                f.write(bytes((b & 0xFF,)))
        stream.close()
        return tmp_path
    except Exception as e:
        log.exception("[URI] to path error: %s", e)
        return None


def _query_recent_images(limit=40):
    """Возвращает список путей к последним фото в галерее Android."""
    try:
        from jnius import autoclass
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        MediaStore     = autoclass("android.provider.MediaStore$Images$Media")
        activity       = PythonActivity.mActivity
        resolver       = activity.getContentResolver()
        cursor = resolver.query(
            MediaStore.EXTERNAL_CONTENT_URI,
            None, None, None,
            "date_added DESC")
        paths = []
        if cursor and cursor.moveToFirst():
            idx = cursor.getColumnIndex("_data")
            while len(paths) < limit:
                path = cursor.getString(idx)
                if path and os.path.exists(path):
                    paths.append(path)
                if not cursor.moveToNext():
                    break
            cursor.close()
        return paths
    except Exception as e:
        print(f"[Gallery] query error: {e}")
        return []


# ─────────────────────────────────────────────────────────────
# ГАЛЕРЕЯ — НИЖНИЙ ЛИСТ (как в Telegram/WhatsApp)
# ─────────────────────────────────────────────────────────────

def show_image_gallery(on_selected):
    """
    Красивый нижний лист с последними фото из галереи.
    on_selected(path: str) — вызывается при выборе.
    """
    # Упрощенный стабильный вариант: системный picker.
    # Это убирает краши, связанные с MediaStore превью на разных Android API.
    _request_image_pick(on_selected)


# ─────────────────────────────────────────────────────────────
# ЭКРАН ЧАТА
# ─────────────────────────────────────────────────────────────

class ChatScreen(Screen):
    _peer     = ""
    _is_group = False

    def on_enter(self):
        Window.bind(keyboard_height=self._on_keyboard_height)

    def on_leave(self):
        try:
            Window.unbind(keyboard_height=self._on_keyboard_height)
        except Exception:
            pass

    def _on_keyboard_height(self, window, height):
        """Поднимаем весь чат над клавиатурой."""
        try:
            self.ids.chat_root.padding = [0, 0, 0, height]
            if height > 0:
                Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.1)
        except Exception:
            pass

    def on_input_focus(self, focused):
        if focused:
            Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.3)

    def load_chat(self, peer, is_group=False):
        self._peer     = peer
        self._is_group = is_group
        app = App.get_running_app()

        # Аватар в шапке
        ava_cont = self.ids.avatar_widget
        ava_cont.canvas.clear()
        for c in list(ava_cont.children):
            ava_cont.remove_widget(c)

        if is_group:
            group = app.db.get_group(peer)
            if group:
                self.ids.peer_name_lbl.text   = group["group_name"]
                self.ids.peer_status_lbl.text = f"{len(group['members'])} участников"
            else:
                self.ids.peer_name_lbl.text   = "Группа"
                self.ids.peer_status_lbl.text = ""
            ava = make_avatar(self.ids.peer_name_lbl.text, dp(38))
        else:
            self.ids.peer_name_lbl.text   = f"@{peer}"
            self.ids.peer_status_lbl.text = ""
            contact = app.backend.get_contact(peer)
            ava_b64 = contact.get("avatar") if contact else None
            ava = make_avatar(peer, dp(38), ava_b64)

        ava.size_hint = (None, None)
        ava.size      = (dp(38), dp(38))
        ava_cont.add_widget(ava)

        self._build_messages()
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.1)

    def _build_messages(self):
        box = self.ids.msg_list
        box.clear_widgets()
        msgs = App.get_running_app().db.get_messages(self._peer)
        for m in msgs:
            if m.get("media_type") == "image":
                self._add_image_bubble(
                    m["direction"], m.get("media_path"),
                    m.get("media_thumb"), m["ts"], m.get("status", "sent"),
                    m.get("img_w", 0), m.get("img_h", 0))
            else:
                self._add_bubble(m["direction"], m["text"],
                                 m["ts"], m.get("status", "sent"))

    def _bubble_outer(self, is_out, height):
        outer = BoxLayout(size_hint_y=None, height=height + dp(4))
        if is_out:
            outer.add_widget(Widget())
        return outer

    def _add_bubble(self, direction, text, ts, status="sent"):
        app    = App.get_running_app()
        t      = app.theme
        is_out = (direction == "out")
        dt     = datetime.fromtimestamp(ts / 1000)
        tstr   = dt.strftime("%H:%M")
        icon   = {"sent": "отпр", "delivered": "дост", "read": "проч"}.get(status, "")
        bcolor = t["bubble_out"] if is_out else t["bubble_in"]
        max_w  = Window.width * 0.72

        from kivy.core.text import Label as CoreLabel
        cl = CoreLabel(text=text, font_size=dp(15),
                       text_size=(max_w - dp(24), None))
        cl.refresh()
        text_h  = cl.texture.size[1] if cl.texture else dp(20)
        bwidth  = min((cl.texture.size[0] + dp(28)) if cl.texture else max_w, max_w)
        bheight = max(text_h + dp(38), dp(44))

        outer = self._bubble_outer(is_out, bheight)
        bubble = BoxLayout(size_hint=(None, None), size=(bwidth, bheight),
                           padding=[dp(10), dp(6), dp(10), dp(6)])
        radius = [12, 12, 2, 12] if is_out else [12, 12, 12, 2]
        with bubble.canvas.before:
            Color(*bcolor)
            RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=radius)
        bubble.bind(pos=lambda i, *_: _upd(i), size=lambda i, *_: _upd(i))
        def _upd(inst, _bc=bcolor, _io=is_out):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*_bc)
                r = [12,12,2,12] if _io else [12,12,12,2]
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=r)

        content = BoxLayout(orientation="vertical")
        msg_lbl = Label(text=text, font_size="15sp", color=t["input_fg"],
                        halign="right" if is_out else "left",
                        valign="top", size_hint_y=1,
                        text_size=(max_w - dp(24), None))
        content.add_widget(msg_lbl)
        foot = BoxLayout(size_hint_y=None, height=dp(16))
        foot.add_widget(Widget())
        time_c = [0.6, 0.7, 0.9, 1] if is_out else [0.5, 0.5, 0.6, 1]
        foot.add_widget(Label(text=f"{tstr}  {icon}", font_size="10sp",
                              color=time_c, size_hint_x=None, width=dp(64),
                              halign="right", text_size=(dp(64), None)))
        content.add_widget(foot)
        bubble.add_widget(content)
        outer.add_widget(bubble)
        if not is_out:
            outer.add_widget(Widget())
        self.ids.msg_list.add_widget(outer)

    def _add_image_bubble(self, direction, image_path, thumb_b64, ts,
                          status="sent", img_w=0, img_h=0):
        app    = App.get_running_app()
        t      = app.theme
        is_out = (direction == "out")
        dt     = datetime.fromtimestamp(ts / 1000)
        tstr   = dt.strftime("%H:%M")
        icon   = {"sent": "отпр", "delivered": "дост", "read": "проч"}.get(status, "")
        bcolor = t["bubble_out"] if is_out else t["bubble_in"]

        # Вычисляем размер с сохранением пропорций
        MAX_W = min(Window.width * 0.68, dp(260))
        MAX_H = dp(220)
        if img_w > 0 and img_h > 0:
            ratio = img_w / img_h
            if ratio >= 1:
                disp_w = MAX_W
                disp_h = min(MAX_W / ratio, MAX_H)
            else:
                disp_h = MAX_H
                disp_w = min(MAX_H * ratio, MAX_W)
        else:
            disp_w = MAX_W
            disp_h = MAX_H
        bheight = disp_h + dp(28)

        outer = self._bubble_outer(is_out, bheight)
        bubble = BoxLayout(size_hint=(None, None),
                           size=(disp_w + dp(8), bheight),
                           padding=[dp(4), dp(4), dp(4), dp(2)],
                           orientation="vertical")
        radius = [12, 12, 2, 12] if is_out else [12, 12, 12, 2]
        with bubble.canvas.before:
            Color(*bcolor)
            RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=radius)
        bubble.bind(pos=lambda i, *_: _upd(i), size=lambda i, *_: _upd(i))
        def _upd(inst, _bc=bcolor, _io=is_out):
            inst.canvas.before.clear()
            with inst.canvas.before:
                Color(*_bc)
                r = [12,12,2,12] if _io else [12,12,12,2]
                RoundedRectangle(pos=inst.pos, size=inst.size, radius=r)

        # Изображение
        img_src = None
        if image_path and os.path.exists(image_path):
            img_src = image_path
        elif thumb_b64:
            try:
                thumb_data = base64.b64decode(thumb_b64)
                tmp = os.path.join(app.user_data_dir, f"th_{ts}.jpg")
                if not os.path.exists(tmp):
                    with open(tmp, "wb") as f:
                        f.write(thumb_data)
                img_src = tmp
            except Exception:
                pass

        if img_src:
            img = KivyImage(source=img_src,
                            size_hint=(None, None), size=(disp_w, disp_h),
                            allow_stretch=True, keep_ratio=True)
            bubble.add_widget(img)
        else:
            bubble.add_widget(Label(text="Фото", font_size="14sp",
                                    color=t["input_fg"],
                                    size_hint=(None, None), size=(disp_w, disp_h)))

        foot = BoxLayout(size_hint_y=None, height=dp(18))
        foot.add_widget(Widget())
        time_c = [0.6, 0.7, 0.9, 1] if is_out else [0.5, 0.5, 0.6, 1]
        foot.add_widget(Label(text=f"{tstr}  {icon}", font_size="10sp",
                              color=time_c, size_hint_x=None, width=dp(64),
                              halign="right", text_size=(dp(64), None)))
        bubble.add_widget(foot)
        outer.add_widget(bubble)
        if not is_out:
            outer.add_widget(Widget())
        self.ids.msg_list.add_widget(outer)

    def _scroll_bottom(self):
        self.ids.msg_scroll.scroll_y = 0

    def send_message(self):
        text = self.ids.msg_inp.text.strip()
        if not text:
            return
        self.ids.msg_inp.text = ""
        app  = App.get_running_app()
        peer = self._peer
        ts   = int(time.time() * 1000)
        sid  = f"local_{ts}"

        if self._is_group:
            self._send_group_message(peer, text, ts, sid)
        else:
            self._send_direct_message(peer, text, ts, sid)

        Clock.schedule_once(lambda dt: self.manager.get_screen("chats").refresh(), 0.1)

    def _send_direct_message(self, peer, text, ts, sid):
        app     = App.get_running_app()
        contact = app.backend.get_contact(peer)
        if not contact or not contact.get("public_key_path"):
            show_msg("Нет ключа",
                     f"Публичный ключ @{peer} недоступен.\n"
                     "Дождитесь принятия запроса контакта.")
            return
        app.db.add_message(peer, "out", text, ts=ts, status="sent", server_id=sid)
        self._add_bubble("out", text, ts, "sent")
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)
        if app.net.ws.connected:
            def _send():
                app.net.send_message(peer, text, contact["public_key_path"])
            threading.Thread(target=_send, daemon=True).start()

    def _send_group_message(self, group_id, text, ts, sid):
        """
        Групповое сообщение: шифруем для каждого участника отдельно
        и отправляем как обычное message с пометкой group_id.
        """
        app   = App.get_running_app()
        group = app.db.get_group(group_id)
        if not group:
            show_msg("Ошибка", "Группа не найдена")
            return

        app.db.add_message(group_id, "out", text, ts=ts, status="sent",
                           server_id=sid, is_group=True, group_id=group_id)
        self._add_bubble("out", text, ts, "sent")
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)

        if not app.net.ws.connected:
            return

        def _send():
            for member in group["members"]:
                contact = app.backend.get_contact(member)
                if not contact or not contact.get("public_key_path"):
                    continue
                try:
                    app.net.send_group_message(
                        member, text, contact["public_key_path"], group_id, ts
                    )
                except Exception as e:
                    print(f"[Group] send to {member} error: {e}")

        threading.Thread(target=_send, daemon=True).start()

    def go_back(self):
        self.manager.current = "chats"
        self.manager.get_screen("chats").refresh()

    def attach_media(self):
        """Открывает галерею выбора изображений (как Telegram/WhatsApp)."""
        if platform != "android":
            show_msg("Недоступно",
                     "Отправка фото доступна на Android.\n"
                     "На ПК можете использовать кнопку «Все файлы».")
            return
        show_image_gallery(self._on_image_chosen)

    def _on_image_chosen(self, path):
        """Путь выбранного изображения -> сжать -> зашифровать -> отправить."""
        if not path or not os.path.exists(path):
            return
        app  = App.get_running_app()
        peer = self._peer
        show_toast("Обработка фото...")

        def _process():
            try:
                compressed, size = app.backend.compress_image(path, max_dim=1280, quality=82)
                thumb_b64, _     = app.backend.make_thumb(compressed, size=280)

                media_dir = os.path.join(app.user_data_dir, "media")
                os.makedirs(media_dir, exist_ok=True)
                ts        = int(time.time() * 1000)
                local_path = os.path.join(media_dir, f"img_{ts}.jpg")
                with open(local_path, "wb") as f:
                    f.write(compressed)

                def _ui(dt):
                    if self._is_group:
                        self._send_group_image(peer, compressed, local_path,
                                               thumb_b64, size, ts)
                    else:
                        self._send_direct_image(peer, compressed, local_path,
                                                thumb_b64, size, ts)
                Clock.schedule_once(_ui, 0)
            except Exception as e:
                Clock.schedule_once(lambda dt: show_msg("Ошибка", str(e)), 0)

        threading.Thread(target=_process, daemon=True).start()

    def _send_direct_image(self, peer, compressed, local_path, thumb_b64, size, ts):
        app     = App.get_running_app()
        contact = app.backend.get_contact(peer)
        if not contact or not contact.get("public_key_path"):
            show_msg("Ошибка", "Нет ключа контакта")
            return
        sid = f"local_img_{ts}"
        app.db.add_message(peer, "out", "Фото", ts=ts, status="sent",
                           server_id=sid, media_type="image",
                           media_path=local_path, media_thumb=thumb_b64,
                           img_w=size[0], img_h=size[1])
        self._add_image_bubble("out", local_path, thumb_b64, ts, "sent",
                               size[0], size[1])
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)
        if app.net.ws.connected:
            def _send():
                app.net.send_image(peer, compressed, contact["public_key_path"])
            threading.Thread(target=_send, daemon=True).start()

    def _send_group_image(self, group_id, compressed, local_path, thumb_b64, size, ts):
        """Отправка изображения в групповой чат."""
        app   = App.get_running_app()
        group = app.db.get_group(group_id)
        if not group:
            show_msg("Ошибка", "Группа не найдена")
            return
        sid = f"local_img_{ts}"
        app.db.add_message(group_id, "out", "Фото", ts=ts, status="sent",
                           server_id=sid, is_group=True, group_id=group_id,
                           media_type="image", media_path=local_path,
                           media_thumb=thumb_b64,
                           img_w=size[0], img_h=size[1])
        self._add_image_bubble("out", local_path, thumb_b64, ts, "sent",
                               size[0], size[1])
        Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)
        if not app.net.ws.connected:
            return
        def _send():
            for member in group["members"]:
                contact = app.backend.get_contact(member)
                if not contact or not contact.get("public_key_path"):
                    continue
                try:
                    app.net.send_image(member, compressed, contact["public_key_path"])
                except Exception as e:
                    print(f"[Group img] {member}: {e}")
        threading.Thread(target=_send, daemon=True).start()

    def open_chat_menu(self):
        app  = App.get_running_app()
        t    = app.theme
        peer = self._peer
        mv   = ModalView(size_hint=(0.82, None), height=dp(240),
                         background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text=f"@{peer}", font_size="16sp", bold=True,
                              color=t["title_color"], size_hint_y=None, height=dp(32)))
        contact = app.backend.get_contact(peer)
        if contact and contact.get("public_key_path"):
            fp = app.backend.pubkey_fingerprint(contact["public_key_path"])
            card.add_widget(Label(text=f"Ключ: {fp}", font_size="11sp",
                                  color=t["label_muted"], size_hint_y=None, height=dp(22),
                                  halign="left", text_size=(Window.width*0.74, None)))
        copy_btn = Button(text="Скопировать ключ контакта",
                          size_hint_y=None, height=dp(46),
                          background_normal="", background_color=t["btn_bg"],
                          color=t["btn_text"])
        def _copy(_):
            if contact and contact.get("public_key_path"):
                Clipboard.copy(app.backend.pubkey_pem(contact["public_key_path"]))
                show_toast("Ключ скопирован")
            mv.dismiss()
        copy_btn.bind(on_release=_copy)
        card.add_widget(copy_btn)

        del_btn = Button(text="Удалить чат", size_hint_y=None, height=dp(46),
                         background_normal="", background_color=t["danger_bg"],
                         color=[1,1,1,1])
        def _del(_):
            mv.dismiss()
            show_confirm("Удалить чат?",
                         f"История с @{peer} будет удалена.",
                         lambda: (app.db.delete_chat(peer), self.go_back()))
        del_btn.bind(on_release=_del)
        card.add_widget(del_btn)

        close = Button(text="Закрыть", size_hint_y=None, height=dp(38),
                       background_normal="", background_color=[0,0,0,0],
                       color=t["accent"])
        close.bind(on_release=mv.dismiss)
        card.add_widget(close)
        mv.add_widget(card)
        mv.open()

    def receive_message(self, peer_key, sender, text, ts, sid):
        if peer_key == self._peer:
            self._add_bubble("in", text, ts, "delivered")
            Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)

    def receive_image(self, peer, path, thumb_b64, ts, sid):
        if peer == self._peer:
            self._add_image_bubble("in", path, thumb_b64, ts, "delivered")
            Clock.schedule_once(lambda dt: self._scroll_bottom(), 0.05)


# ─────────────────────────────────────────────────────────────
# ЭКРАН КЛЮЧЕЙ
# ─────────────────────────────────────────────────────────────

class KeysScreen(Screen):
    def on_enter(self):
        app = App.get_running_app()
        acc = app.my_account
        lbl = self.ids.my_key_label
        if acc:
            fp = app.backend.pubkey_fingerprint(acc["public_key_path"])
            lbl.text = f"@{acc['username']}  Ключ: {fp}"
        else:
            lbl.text = "Аккаунт не выбран"
        self._refresh_contacts()

    def copy_my_pubkey(self):
        app = App.get_running_app()
        acc = app.my_account
        if not acc:
            show_msg("Ошибка", "Нет аккаунта"); return
        Clipboard.copy(app.backend.pubkey_pem(acc["public_key_path"]))
        show_toast("Публичный ключ скопирован")

    def export_keys(self):
        app = App.get_running_app()
        acc = app.my_account
        if not acc:
            show_msg("Ошибка", "Нет аккаунта"); return
        pub  = app.backend.pubkey_pem(acc["public_key_path"])
        with open(acc["private_key_path"]) as f:
            priv = f.read()
        Clipboard.copy(json.dumps({"username": acc["username"],
                                   "public_key": pub, "private_key": priv}, indent=2))
        show_msg("Экспорт", "Ключи скопированы в буфер (JSON).\n"
                            "Важно: храните приватный ключ в безопасном месте!")

    def import_keys(self):
        app = App.get_running_app()
        t   = app.theme
        mv  = ModalView(size_hint=(0.92, None), height=dp(330),
                        background_color=[0,0,0,0])
        card = _make_card(t)
        card.add_widget(Label(text="Импорт ключей", font_size="17sp", bold=True,
                             color=t["title_color"], size_hint_y=None, height=dp(32)))
        inp = TextInput(hint_text="Вставьте JSON с ключами...",
                       background_color=t["log_bg"], foreground_color=t["input_fg"],
                       font_size="12sp", size_hint_y=None, height=dp(140),
                       use_bubble=False, use_handles=False, multiline=True,
                       padding=[8,8,8,8], cursor_color=t["accent"])
        try:
            cb = Clipboard.paste()
            if cb:
                inp.text = cb
        except Exception:
            pass
        status = Label(text="", font_size="12sp", color=t["label_muted"],
                      size_hint_y=None, height=dp(24), halign="left",
                      text_size=(Window.width*0.8, None))
        card.add_widget(inp); card.add_widget(status)
        row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        imp_btn = Button(text="Импортировать", background_normal="",
                        background_color=t["accent"], color=[1,1,1,1], bold=True)
        can_btn = Button(text="Отмена", background_normal="",
                        background_color=t["btn_bg"], color=t["btn_text"])
        can_btn.bind(on_release=mv.dismiss)
        row.add_widget(imp_btn); row.add_widget(can_btn)
        card.add_widget(row); mv.add_widget(card)

        def _import(_):
            try:
                data     = json.loads(inp.text.strip())
                username = data.get("username")
                pub_key  = data.get("public_key")
                priv_key = data.get("private_key")
                if not all([username, pub_key, priv_key]):
                    status.text = "Неверный формат JSON"; status.color = [1,0.3,0.3,1]; return
                existing = app.backend.get_contact(username)
                if existing and existing.get("private_key_path"):
                    status.text = f"@{username} уже существует"; status.color = [1,0.3,0.3,1]; return
                ts = datetime.now().strftime("%Y%m%d%H%M%S")
                pp = os.path.join(app.backend.keys_dir, f"RSA_{username}_priv_{ts}_imp.pem")
                pp2 = os.path.join(app.backend.keys_dir, f"RSA_{username}_pub_{ts}_imp.pem")
                with open(pp, "w") as f: f.write(priv_key)
                with open(pp2, "w") as f: f.write(pub_key)
                users = app.backend.load_users()
                users.insert(0, {"username": username, "public_key_path": pp2,
                                 "private_key_path": pp})
                app.backend.save_users(users)
                mv.dismiss()
                show_msg("Успешно", f"@{username} импортирован!")
            except json.JSONDecodeError:
                status.text = "Неверный JSON"; status.color = [1,0.3,0.3,1]
            except Exception as e:
                status.text = f"Ошибка: {e}"; status.color = [1,0.3,0.3,1]

        imp_btn.bind(on_release=_import); mv.open()

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
                                 size_hint_y=None, height=dp(44)))
            return
        for c in contacts:
            row = BoxLayout(size_hint_y=None, height=dp(54), spacing=dp(8),
                            padding=[dp(8), dp(4), dp(4), dp(4)])
            fp  = app.backend.pubkey_fingerprint(c["public_key_path"])
            info = BoxLayout(orientation="vertical")
            info.add_widget(Label(text=f"@{c['username']}", font_size="14sp",
                                  bold=True, color=t["btn_text"], halign="left",
                                  text_size=(Window.width*0.54, None)))
            info.add_widget(Label(text=f"Ключ: {fp}", font_size="10sp",
                                  color=t["label_muted"], halign="left",
                                  text_size=(Window.width*0.54, None)))
            row.add_widget(info)
            del_btn = Button(text="Удалить", size_hint_x=None, width=dp(72),
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
# ЗАПРОС НА КОНТАКТ
# ─────────────────────────────────────────────────────────────

def show_contact_request(from_user, pubkey_pem):
    app = App.get_running_app()
    t   = app.theme
    mv  = ModalView(size_hint=(0.92, None), height=dp(240),
                    background_color=[0,0,0,0], auto_dismiss=False)
    card = _make_card(t)
    card.add_widget(Label(text="Запрос на контакт", font_size="16sp", bold=True,
                          color=t["title_color"], size_hint_y=None, height=dp(30)))
    card.add_widget(Label(
        text=f"@{from_user} хочет написать вам.\n"
             "Принять — он получит ваш публичный ключ.",
        font_size="13sp", color=t["input_fg"],
        size_hint_y=None, height=dp(52),
        halign="center", text_size=(Window.width*0.78, None)))
    try:
        tmp = os.path.join(app.backend.keys_dir, f"_tmp_{from_user}.pem")
        with open(tmp, "w") as f:
            f.write(pubkey_pem)
        fp = app.backend.pubkey_fingerprint(tmp)
        os.remove(tmp)
        card.add_widget(Label(text=f"Ключ: {fp}", font_size="10sp",
                              color=t["label_muted"], size_hint_y=None, height=dp(20),
                              halign="center", text_size=(Window.width*0.78, None)))
    except Exception:
        pass

    row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(12))
    acc_btn = Button(text="Принять", background_normal="",
                     background_color=t["success_bg"], color=[1,1,1,1], bold=True)
    rej_btn = Button(text="Отклонить", background_normal="",
                     background_color=t["danger_bg"], color=[1,1,1,1])

    def _accept(_):
        mv.dismiss()
        app.backend.add_contact(from_user, pubkey_pem)
        my_pub = app.backend.pubkey_pem(app.my_account["public_key_path"])
        app.net.accept_contact(from_user, my_pub)
        show_toast(f"@{from_user} добавлен в контакты")

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
        acc             = self.backend.get_my_account()
        username        = acc["username"] if acc else None
        self.db         = MessageDB(self.user_data_dir, username)
        self.net        = NetworkManager()

        global SETTINGS_FILE
        SETTINGS_FILE = os.path.join(self.user_data_dir, "settings.json")
        self._load_settings()

        self.net.on_status_change    = self._on_net_status
        self.net.on_incoming_message = self._on_incoming
        self.net.on_incoming_image   = self._on_incoming_image
        self.net.on_contact_request  = self._on_contact_request
        self.net.on_request_accepted = self._on_request_accepted
        self.net.on_user_status      = self._on_user_status

        Builder.load_string(KV)

        sm = ScreenManager(transition=NoTransition())
        sm.add_widget(PinScreen(name="pin"))
        sm.add_widget(LaunchScreen(name="launch"))
        sm.add_widget(CreateAccountScreen(name="create_account"))
        sm.add_widget(ChatsScreen(name="chats"))
        sm.add_widget(ChatScreen(name="chat"))
        sm.add_widget(ServerScreen(name="server"))
        sm.add_widget(KeysScreen(name="keys"))
        return sm

    def on_start(self):
        Window.clearcolor = tuple(self.theme["bg_color"])
        # Поднимаем контент над клавиатурой (работает на Android)
        if platform == "android":
            Window.softinput_mode = "below_target"

        if self._load_pin():
            self.root.current = "pin"
        else:
            self.root.current = "launch"

        # Авто-подключение
        acc = self.backend.get_my_account()
        if acc and self._saved_host:
            self.my_account = acc
            self.db = MessageDB(self.user_data_dir, acc["username"])
            pub_pem = self.backend.pubkey_pem(acc["public_key_path"])

            def _done(ok, err):
                if not ok:
                    Clock.schedule_once(lambda dt: self._show_conn_banner(err), 0.5)

            try:
                self.net.connect(self._saved_host, self._saved_port,
                                 acc["username"], acc["private_key_path"],
                                 pub_pem, on_done=_done)
            except Exception as e:
                Clock.schedule_once(lambda dt: self._show_conn_banner(str(e)), 1)

    def _show_conn_banner(self, error):
        """Не-блокирующий баннер об ошибке подключения (без вылета)."""
        try:
            t  = self.theme
            mv = ModalView(size_hint=(None, None), size=(dp(280), dp(76)),
                           background_color=[0,0,0,0], auto_dismiss=True)
            mv.pos_hint = {"center_x": 0.5, "y": 0.12}
            card = BoxLayout(orientation="vertical",
                             padding=[dp(14), dp(10), dp(14), dp(10)])
            with card.canvas.before:
                Color(*t["danger_bg"])
                RoundedRectangle(pos=card.pos, size=card.size, radius=[12])
            card.bind(pos=lambda i, *_: _rd(i), size=lambda i, *_: _rd(i))
            def _rd(inst):
                inst.canvas.before.clear()
                with inst.canvas.before:
                    Color(*t["danger_bg"])
                    RoundedRectangle(pos=inst.pos, size=inst.size, radius=[12])
            card.add_widget(Label(text="Нет подключения к серверу",
                                  font_size="13sp", bold=True, color=[1,1,1,1],
                                  halign="center"))
            card.add_widget(Label(text=str(error)[:60],
                                  font_size="11sp", color=[1,0.8,0.8,1],
                                  halign="center",
                                  text_size=(dp(250), None)))
            mv.add_widget(card)
            mv.open()
            Clock.schedule_once(lambda dt: mv.dismiss(), 4)
        except Exception:
            pass

    # ── Настройки ────────────────────────────────────────────
    def _load_settings(self):
        self._saved_host = ""
        self._saved_port = 8765
        try:
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE) as f:
                    d = json.load(f)
                self._saved_host = d.get("server_host", "")
                self._saved_port = d.get("server_port", 8765)
        except Exception:
            pass

    def _settings_dict(self):
        try:
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def save_server_settings(self, host, port):
        self._saved_host = host
        self._saved_port = port
        try:
            d = self._settings_dict()
            d["server_host"] = host
            d["server_port"] = port
            with open(SETTINGS_FILE, "w") as f:
                json.dump(d, f)
        except Exception:
            pass

    def _save_pin(self, pin_hash):
        try:
            d = self._settings_dict()
            d["pin_hash"] = pin_hash
            with open(SETTINGS_FILE, "w") as f:
                json.dump(d, f)
        except Exception:
            pass

    def _load_pin(self):
        try:
            return self._settings_dict().get("pin_hash")
        except Exception:
            return None

    # ── Колбэки ──────────────────────────────────────────────
    def _on_net_status(self, connected):
        try:
            self.root.get_screen("chats").update_net_badge()
            self.root.get_screen("server")._update_status()
        except Exception:
            pass

    def _on_incoming(self, peer_key, sender, text, ts, sid):
        try:
            chat = self.root.get_screen("chat")
            chat.receive_message(peer_key, sender, text, ts, sid)
            self.root.get_screen("chats").refresh()
            if self.root.current != "chat" or chat._peer != peer_key:
                self._notify_new_message(sender, text)
        except Exception:
            pass

    def _on_incoming_image(self, peer, path, thumb_b64, ts, sid):
        try:
            chat = self.root.get_screen("chat")
            chat.receive_image(peer, path, thumb_b64, ts, sid)
            self.root.get_screen("chats").refresh()
            if self.root.current != "chat" or chat._peer != peer:
                self._notify_new_message(peer, "Фото")
        except Exception:
            pass

    def _on_contact_request(self, from_user, pubkey_pem):
        Clock.schedule_once(
            lambda dt: show_contact_request(from_user, pubkey_pem), 0)

    def _on_request_accepted(self, peer, pubkey_pem):
        self.backend.add_contact(peer, pubkey_pem)
        Clock.schedule_once(
            lambda dt: show_toast(f"@{peer} принял ваш запрос!"), 0)

    def _on_user_status(self, username, is_online):
        """Обновляем статус пользователя в открытом чате если нужно."""
        try:
            chat = self.root.get_screen("chat")
            if chat._peer == username:
                status = "онлайн" if is_online else "был(а) в сети"
                chat.ids.peer_status_lbl.text = status
        except Exception as e:
            log.exception("user status update failed: %s", e)

    def _notify_new_message(self, sender, text):
        title = f"SCmess: @{sender}"
        short_text = (text[:90] + "...") if len(text) > 90 else text
        try:
            if platform == "android":
                from plyer import notification
                notification.notify(title=title, message=short_text, app_name="SCmess")
            else:
                show_toast(f"@{sender}: {short_text}")
        except Exception as e:
            log.exception("notification failed: %s", e)
            show_toast(f"@{sender}: {short_text}")


if __name__ == "__main__":
    SCMessApp().run()
