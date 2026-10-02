#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VOLT ERP — Küçük ve orta ölçekli işletmeler için masaüstü ERP uygulaması.

Modüller : Gösterge paneli, Ürün/Stok, Cari hesaplar, Satış ve Alış faturaları,
           Tahsilat/Ödeme, Raporlar (CSV dışa aktarma), Kullanıcı yönetimi, İşlem kaydı
Teknoloji: Python 3, tkinter/ttk, SQLite (standart kütüphane dışında bağımlılık yok)

Kullanım:
    python volt_erp.py            # uygulamayı açar
    python volt_erp.py --demo     # örnek verilerle açar (ilk çalıştırmada)
    python volt_erp.py --test     # birim testlerini çalıştırır
    python volt_erp.py --db yol   # farklı veritabanı dosyası kullanır

Geliştirici: Enes Talha Köse (github.com/enestalhakose)
"""

import argparse
import csv
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

APP_NAME = "VOLT ERP"
VERSION = "1.0.0"
DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "volt_erp.db")

PBKDF2_ROUNDS = 120_000
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 5

# Rol -> izinler. "*" tüm izinleri verir.
ROLE_PERMS = {
    "admin": {"*"},
    "muhasebe": {"cari.yaz", "fatura.satis", "fatura.alis", "fatura.iptal", "odeme", "rapor"},
    "satis": {"cari.yaz", "fatura.satis"},
    "depo": {"urun.yaz", "stok.duzelt", "fatura.alis"},
}
ROLE_NAMES = {"admin": "Yönetici", "muhasebe": "Muhasebe", "satis": "Satış", "depo": "Depo"}
PARTY_TYPES = {"MUSTERI": "Müşteri", "TEDARIKCI": "Tedarikçi", "IKISI": "Müşteri + Tedarikçi"}


# ════════════════════════════════════════════════════════════════════
#  Yardımcılar
# ════════════════════════════════════════════════════════════════════
class ERPError(Exception):
    """Kullanıcıya gösterilecek iş kuralı hatası."""


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_money(text) -> int:
    """'1250,50' / '1250.50' / '1.250,50 ₺' -> 125050 (kuruş). Para birimi tamsayı kuruş olarak saklanır."""
    s = str(text).strip().replace("₺", "").replace("TL", "").replace(" ", "")
    if not s:
        raise ERPError("Tutar boş olamaz.")
    if "," in s:
        s = s.replace(".", "").replace(",", ".")
    try:
        d = Decimal(s)
    except InvalidOperation:
        raise ERPError(f"Geçersiz tutar: {text}")
    if d < 0:
        raise ERPError("Tutar negatif olamaz.")
    return int((d * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def fmt_money(kurus) -> str:
    kurus = int(kurus or 0)
    lira, kr = divmod(abs(kurus), 100)
    return f"{'-' if kurus < 0 else ''}{lira:,}".replace(",", ".") + f",{kr:02d} ₺"


def parse_int(text, name="Miktar", allow_zero=False, allow_negative=False) -> int:
    try:
        v = int(str(text).strip())
    except ValueError:
        raise ERPError(f"{name} tam sayı olmalı.")
    if v < 0 and not allow_negative:
        raise ERPError(f"{name} negatif olamaz.")
    if v == 0 and not allow_zero:
        raise ERPError(f"{name} sıfır olamaz.")
    return v


def calc_vat(net_kurus: int, rate: int) -> int:
    return (net_kurus * rate + 50) // 100


def fmt_date(iso: str) -> str:
    try:
        return datetime.strptime(iso[:10], "%Y-%m-%d").strftime("%d.%m.%Y")
    except (ValueError, TypeError):
        return iso or ""


def hash_password(password: str, salt: bytes = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return digest.hex(), salt.hex()


def check_password_policy(pw: str):
    if len(pw) < 8 or not any(c.isdigit() for c in pw) or not any(c.isalpha() for c in pw):
        raise ERPError("Şifre en az 8 karakter olmalı, harf ve rakam içermeli.")


def export_csv(path, headers, rows):
    """Türkçe Excel ile uyumlu (UTF-8 BOM, ';' ayraç) CSV yazar."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(headers)
        w.writerows(rows)


@dataclass
class User:
    id: int
    username: str
    role: str
    must_change: bool = False


# ════════════════════════════════════════════════════════════════════
#  İş katmanı (arayüzden bağımsız, test edilebilir)
# ════════════════════════════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    pw_hash TEXT NOT NULL, salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','muhasebe','satis','depo')),
    active INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY, sku TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT 'Adet', buy_price INTEGER NOT NULL CHECK(buy_price>=0),
    sell_price INTEGER NOT NULL CHECK(sell_price>=0), vat_rate INTEGER NOT NULL DEFAULT 20,
    stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0), min_stock INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS parties(
    id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('MUSTERI','TEDARIKCI','IKISI')),
    phone TEXT, email TEXT, tax_no TEXT, address TEXT, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS invoices(
    id INTEGER PRIMARY KEY, no TEXT UNIQUE NOT NULL, type TEXT NOT NULL CHECK(type IN ('SATIS','ALIS')),
    party_id INTEGER NOT NULL REFERENCES parties(id), date TEXT NOT NULL,
    subtotal INTEGER NOT NULL, vat_total INTEGER NOT NULL, total INTEGER NOT NULL,
    note TEXT, user_id INTEGER REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'AKTIF' CHECK(status IN ('AKTIF','IPTAL')), cancel_reason TEXT);
CREATE TABLE IF NOT EXISTS invoice_lines(
    id INTEGER PRIMARY KEY, invoice_id INTEGER NOT NULL REFERENCES invoices(id),
    product_id INTEGER NOT NULL REFERENCES products(id), qty INTEGER NOT NULL CHECK(qty>0),
    unit_price INTEGER NOT NULL, vat_rate INTEGER NOT NULL, net INTEGER NOT NULL, vat INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stock_moves(
    id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), date TEXT NOT NULL,
    qty INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT, user_id INTEGER);
CREATE TABLE IF NOT EXISTS payments(
    id INTEGER PRIMARY KEY, party_id INTEGER NOT NULL REFERENCES parties(id), date TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('TAHSILAT','ODEME')), amount INTEGER NOT NULL CHECK(amount>0),
    method TEXT, note TEXT, user_id INTEGER);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, username TEXT, action TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_inv_party ON invoices(party_id);
CREATE INDEX IF NOT EXISTS ix_pay_party ON payments(party_id);
CREATE INDEX IF NOT EXISTS ix_lines_inv ON invoice_lines(invoice_id);
"""

# Cari bakiye: pozitif = cari bize borçlu (alacağımız), negatif = biz cariye borçluyuz.
BALANCE_SQL = """
 (COALESCE((SELECT SUM(CASE type WHEN 'SATIS' THEN total ELSE -total END)
            FROM invoices WHERE party_id=p.id AND status='AKTIF'),0)
 - COALESCE((SELECT SUM(CASE kind WHEN 'TAHSILAT' THEN amount ELSE -amount END)
            FROM payments WHERE party_id=p.id),0))
"""


class ERP:
    def __init__(self, path=DEFAULT_DB):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        if not self.db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            h, s = hash_password("admin123")
            self.db.execute(
                "INSERT INTO users(username,pw_hash,salt,role,must_change,created_at) VALUES(?,?,?,?,1,?)",
                ("admin", h, s, "admin", now_str()))
            self.db.commit()

    # ── altyapı ──────────────────────────────────────────────────────
    @contextmanager
    def tx(self):
        try:
            yield self.db
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def q(self, sql, params=()):
        return self.db.execute(sql, params).fetchall()

    def q1(self, sql, params=()):
        return self.db.execute(sql, params).fetchone()

    def _audit(self, user, action, detail=""):
        self.db.execute("INSERT INTO audit(ts,username,action,detail) VALUES(?,?,?,?)",
                        (now_str(), user.username if user else "-", action, detail))

    @staticmethod
    def can(user, perm):
        perms = ROLE_PERMS.get(user.role, set())
        return "*" in perms or perm in perms

    def _require(self, user, perm):
        if not self.can(user, perm):
            raise ERPError("Bu işlem için yetkiniz yok.")

    # ── kimlik doğrulama ─────────────────────────────────────────────
    def login(self, username, password) -> User:
        row = self.q1("SELECT * FROM users WHERE username=?", (username.strip(),))
        generic = ERPError("Kullanıcı adı veya şifre hatalı.")
        if not row or not row["active"]:
            raise generic
        if row["locked_until"] and row["locked_until"] > now_str():
            raise ERPError(f"Çok fazla hatalı deneme. Hesap {row['locked_until'][11:16]} saatine kadar kilitli.")
        digest, _ = hash_password(password, bytes.fromhex(row["salt"]))
        with self.tx():
            if not hmac.compare_digest(digest, row["pw_hash"]):
                failed = row["failed"] + 1
                locked = None
                if failed >= MAX_FAILED_LOGINS:
                    locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
                    failed = 0
                self.db.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?", (failed, locked, row["id"]))
                self.db.execute("INSERT INTO audit(ts,username,action,detail) VALUES(?,?,?,?)",
                                (now_str(), row["username"], "GIRIS_HATALI", ""))
            else:
                self.db.execute("UPDATE users SET failed=0, locked_until=NULL WHERE id=?", (row["id"],))
        if not hmac.compare_digest(digest, row["pw_hash"]):
            raise generic
        user = User(row["id"], row["username"], row["role"], bool(row["must_change"]))
        with self.tx():
            self._audit(user, "GIRIS")
        return user

    def change_password(self, user, old, new):
        row = self.q1("SELECT * FROM users WHERE id=?", (user.id,))
        if not hmac.compare_digest(hash_password(old, bytes.fromhex(row["salt"]))[0], row["pw_hash"]):
            raise ERPError("Mevcut şifre hatalı.")
        check_password_policy(new)
        if new == old:
            raise ERPError("Yeni şifre eskisiyle aynı olamaz.")
        h, s = hash_password(new)
        with self.tx():
            self.db.execute("UPDATE users SET pw_hash=?, salt=?, must_change=0 WHERE id=?", (h, s, user.id))
            self._audit(user, "SIFRE_DEGISTI")
        user.must_change = False

    # ── kullanıcılar ─────────────────────────────────────────────────
    def list_users(self):
        return self.q("SELECT id,username,role,active,created_at FROM users ORDER BY username")

    def add_user(self, user, username, password, role):
        self._require(user, "kullanici")
        username = username.strip()
        if len(username) < 3 or not username.replace("_", "").replace(".", "").isalnum():
            raise ERPError("Kullanıcı adı en az 3 karakter olmalı; harf, rakam, '.' ve '_' içerebilir.")
        if role not in ROLE_PERMS:
            raise ERPError("Geçersiz rol.")
        check_password_policy(password)
        h, s = hash_password(password)
        try:
            with self.tx():
                self.db.execute(
                    "INSERT INTO users(username,pw_hash,salt,role,must_change,created_at) VALUES(?,?,?,?,1,?)",
                    (username, h, s, role, now_str()))
                self._audit(user, "KULLANICI_EKLE", f"{username} ({role})")
        except sqlite3.IntegrityError:
            raise ERPError("Bu kullanıcı adı zaten var.")

    def set_user_active(self, user, user_id, active):
        self._require(user, "kullanici")
        if user_id == user.id:
            raise ERPError("Kendi hesabınızı pasifleştiremezsiniz.")
        with self.tx():
            self.db.execute("UPDATE users SET active=? WHERE id=?", (1 if active else 0, user_id))
            self._audit(user, "KULLANICI_DURUM", f"id={user_id} aktif={active}")

    def reset_password(self, user, user_id, new_password):
        self._require(user, "kullanici")
        check_password_policy(new_password)
        h, s = hash_password(new_password)
        with self.tx():
            self.db.execute("UPDATE users SET pw_hash=?, salt=?, must_change=1, failed=0, locked_until=NULL "
                            "WHERE id=?", (h, s, user_id))
            self._audit(user, "SIFRE_SIFIRLA", f"id={user_id}")

    # ── ürünler ──────────────────────────────────────────────────────
    def list_products(self, search="", only_active=True):
        like = f"%{search.strip()}%"
        sql = "SELECT * FROM products WHERE (sku LIKE ? OR name LIKE ?)"
        if only_active:
            sql += " AND active=1"
        return self.q(sql + " ORDER BY name", (like, like))

    def get_product(self, pid):
        return self.q1("SELECT * FROM products WHERE id=?", (pid,))

    def _validate_product(self, sku, name, unit, buy, sell, vat, min_stock):
        sku, name = sku.strip().upper(), name.strip()
        if not sku or not name:
            raise ERPError("Stok kodu ve ürün adı zorunludur.")
        vat = parse_int(vat, "KDV oranı", allow_zero=True)
        if vat not in (0, 1, 10, 20):
            raise ERPError("KDV oranı 0, 1, 10 veya 20 olmalı.")
        return (sku, name, unit.strip() or "Adet", parse_money(buy), parse_money(sell), vat,
                parse_int(min_stock, "Kritik stok", allow_zero=True))

    def add_product(self, user, sku, name, unit, buy, sell, vat=20, min_stock=0, opening_stock=0):
        self._require(user, "urun.yaz")
        vals = self._validate_product(sku, name, unit, buy, sell, vat, min_stock)
        opening = parse_int(opening_stock, "Açılış stoğu", allow_zero=True)
        try:
            with self.tx():
                cur = self.db.execute(
                    "INSERT INTO products(sku,name,unit,buy_price,sell_price,vat_rate,min_stock,stock) "
                    "VALUES(?,?,?,?,?,?,?,?)", vals + (opening,))
                if opening:
                    self.db.execute("INSERT INTO stock_moves(product_id,date,qty,kind,ref,user_id) "
                                    "VALUES(?,?,?,?,?,?)", (cur.lastrowid, now_str(), opening, "ACILIS", "", user.id))
                self._audit(user, "URUN_EKLE", vals[0])
                return cur.lastrowid
        except sqlite3.IntegrityError:
            raise ERPError(f"'{vals[0]}' stok kodu zaten kullanılıyor.")

    def update_product(self, user, pid, sku, name, unit, buy, sell, vat, min_stock, active=True):
        self._require(user, "urun.yaz")
        vals = self._validate_product(sku, name, unit, buy, sell, vat, min_stock)
        try:
            with self.tx():
                self.db.execute("UPDATE products SET sku=?,name=?,unit=?,buy_price=?,sell_price=?,vat_rate=?,"
                                "min_stock=?,active=? WHERE id=?", vals + (1 if active else 0, pid))
                self._audit(user, "URUN_GUNCELLE", vals[0])
        except sqlite3.IntegrityError:
            raise ERPError(f"'{vals[0]}' stok kodu zaten kullanılıyor.")

    def adjust_stock(self, user, pid, delta, note):
        self._require(user, "stok.duzelt")
        delta = parse_int(delta, "Düzeltme miktarı", allow_negative=True)
        if not note.strip():
            raise ERPError("Stok düzeltmesi için açıklama zorunludur.")
        p = self.get_product(pid)
        if p["stock"] + delta < 0:
            raise ERPError(f"Stok eksiye düşemez (mevcut: {p['stock']}).")
        with self.tx():
            self.db.execute("UPDATE products SET stock=stock+? WHERE id=?", (delta, pid))
            self.db.execute("INSERT INTO stock_moves(product_id,date,qty,kind,ref,user_id) VALUES(?,?,?,?,?,?)",
                            (pid, now_str(), delta, "DUZELTME", note.strip(), user.id))
            self._audit(user, "STOK_DUZELT", f"{p['sku']} {delta:+d} ({note.strip()})")

    def stock_history(self, pid):
        return self.q("SELECT date,kind,qty,ref FROM stock_moves WHERE product_id=? ORDER BY id DESC", (pid,))

    # ── cariler ──────────────────────────────────────────────────────
    def list_parties(self, search="", ptype=None):
        like = f"%{search.strip()}%"
        sql = f"SELECT p.*, {BALANCE_SQL} AS balance FROM parties p WHERE active=1 AND (code LIKE ? OR name LIKE ?)"
        params = [like, like]
        if ptype:
            sql += " AND (type=? OR type='IKISI')"
            params.append(ptype)
        return self.q(sql + " ORDER BY name", params)

    def party_balance(self, pid):
        return self.q1(f"SELECT {BALANCE_SQL} AS b FROM parties p WHERE id=?", (pid,))["b"]

    def save_party(self, user, pid, code, name, ptype, phone="", email="", tax_no="", address=""):
        self._require(user, "cari.yaz")
        code, name = code.strip().upper(), name.strip()
        if not code or not name:
            raise ERPError("Cari kodu ve unvan zorunludur.")
        if ptype not in PARTY_TYPES:
            raise ERPError("Geçersiz cari tipi.")
        if email and "@" not in email:
            raise ERPError("E-posta adresi geçersiz.")
        if tax_no and (not tax_no.isdigit() or len(tax_no) not in (10, 11)):
            raise ERPError("Vergi/TC no 10 veya 11 haneli olmalı.")
        vals = (code, name, ptype, phone.strip(), email.strip(), tax_no.strip(), address.strip())
        try:
            with self.tx():
                if pid:
                    self.db.execute("UPDATE parties SET code=?,name=?,type=?,phone=?,email=?,tax_no=?,address=? "
                                    "WHERE id=?", vals + (pid,))
                    self._audit(user, "CARI_GUNCELLE", code)
                else:
                    pid = self.db.execute("INSERT INTO parties(code,name,type,phone,email,tax_no,address) "
                                          "VALUES(?,?,?,?,?,?,?)", vals).lastrowid
                    self._audit(user, "CARI_EKLE", code)
                return pid
        except sqlite3.IntegrityError:
            raise ERPError(f"'{code}' cari kodu zaten kullanılıyor.")

    def party_statement(self, pid):
        """Cari ekstre: tarih sırasıyla hareketler ve yürüyen bakiye."""
        rows = self.q("""
            SELECT date, no AS doc, CASE type WHEN 'SATIS' THEN 'Satış faturası' ELSE 'Alış faturası' END AS descr,
                   CASE type WHEN 'SATIS' THEN total ELSE -total END AS amount
              FROM invoices WHERE party_id=? AND status='AKTIF'
            UNION ALL
            SELECT date, '#' || id, CASE kind WHEN 'TAHSILAT' THEN 'Tahsilat' ELSE 'Ödeme' END
                   || COALESCE(' (' || method || ')', ''),
                   CASE kind WHEN 'TAHSILAT' THEN -amount ELSE amount END
              FROM payments WHERE party_id=?
            ORDER BY date""", (pid, pid))
        out, run = [], 0
        for r in rows:
            run += r["amount"]
            out.append((r["date"], r["doc"], r["descr"], r["amount"], run))
        return out

    # ── faturalar ────────────────────────────────────────────────────
    def create_invoice(self, user, inv_type, party_id, lines, note="", date=None):
        """lines: [(product_id, qty, unit_price_kurus), ...] — tek bir işlem (transaction) içinde kaydedilir."""
        if inv_type not in ("SATIS", "ALIS"):
            raise ERPError("Geçersiz fatura tipi.")
        self._require(user, "fatura.satis" if inv_type == "SATIS" else "fatura.alis")
        party = self.q1("SELECT * FROM parties WHERE id=? AND active=1", (party_id,))
        if not party:
            raise ERPError("Cari seçiniz.")
        need = "MUSTERI" if inv_type == "SATIS" else "TEDARIKCI"
        if party["type"] not in (need, "IKISI"):
            raise ERPError(f"Bu cari {PARTY_TYPES[need].lower()} değil.")
        if not lines:
            raise ERPError("Faturaya en az bir satır ekleyin.")
        date = date or now_str()
        sign = -1 if inv_type == "SATIS" else 1
        prefix = "SF" if inv_type == "SATIS" else "AF"

        merged = {}
        for pid, qty, price in lines:
            qty = parse_int(qty)
            if price < 0:
                raise ERPError("Birim fiyat negatif olamaz.")
            if pid in merged and merged[pid][1] != price:
                raise ERPError("Aynı ürün farklı fiyatlarla iki kez eklenmiş.")
            merged[pid] = (merged.get(pid, (0, price))[0] + qty, price)

        with self.tx():
            computed, sub, vat_total = [], 0, 0
            for pid, (qty, price) in merged.items():
                p = self.q1("SELECT * FROM products WHERE id=? AND active=1", (pid,))
                if not p:
                    raise ERPError("Fatura satırında geçersiz ürün var.")
                if inv_type == "SATIS" and p["stock"] < qty:
                    raise ERPError(f"Yetersiz stok: {p['name']} (mevcut {p['stock']}, istenen {qty}).")
                net = qty * price
                vat = calc_vat(net, p["vat_rate"])
                sub += net
                vat_total += vat
                computed.append((p, qty, price, net, vat))

            year = date[:4]
            last = self.q1("SELECT no FROM invoices WHERE no LIKE ? ORDER BY no DESC LIMIT 1", (f"{prefix}-{year}-%",))
            seq = int(last["no"].rsplit("-", 1)[1]) + 1 if last else 1
            no = f"{prefix}-{year}-{seq:05d}"
            inv_id = self.db.execute(
                "INSERT INTO invoices(no,type,party_id,date,subtotal,vat_total,total,note,user_id) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (no, inv_type, party_id, date, sub, vat_total, sub + vat_total, note.strip(), user.id)).lastrowid
            for p, qty, price, net, vat in computed:
                self.db.execute("INSERT INTO invoice_lines(invoice_id,product_id,qty,unit_price,vat_rate,net,vat) "
                                "VALUES(?,?,?,?,?,?,?)", (inv_id, p["id"], qty, price, p["vat_rate"], net, vat))
                self.db.execute("UPDATE products SET stock=stock+? WHERE id=?", (sign * qty, p["id"]))
                self.db.execute("INSERT INTO stock_moves(product_id,date,qty,kind,ref,user_id) VALUES(?,?,?,?,?,?)",
                                (p["id"], date, sign * qty, inv_type, no, user.id))
                if inv_type == "ALIS" and price != p["buy_price"]:
                    self.db.execute("UPDATE products SET buy_price=? WHERE id=?", (price, p["id"]))
            self._audit(user, "FATURA_" + inv_type, f"{no} {fmt_money(sub + vat_total)}")
        return inv_id

    def cancel_invoice(self, user, inv_id, reason):
        self._require(user, "fatura.iptal")
        if not reason.strip():
            raise ERPError("İptal nedeni zorunludur.")
        inv = self.q1("SELECT * FROM invoices WHERE id=?", (inv_id,))
        if not inv or inv["status"] != "AKTIF":
            raise ERPError("Fatura bulunamadı veya zaten iptal edilmiş.")
        sign = 1 if inv["type"] == "SATIS" else -1
        lines = self.q("SELECT l.*, p.stock, p.name FROM invoice_lines l JOIN products p ON p.id=l.product_id "
                       "WHERE invoice_id=?", (inv_id,))
        for ln in lines:
            if ln["stock"] + sign * ln["qty"] < 0:
                raise ERPError(f"İptal edilemez: {ln['name']} stoğu yetersiz kalır.")
        with self.tx():
            for ln in lines:
                self.db.execute("UPDATE products SET stock=stock+? WHERE id=?", (sign * ln["qty"], ln["product_id"]))
                self.db.execute("INSERT INTO stock_moves(product_id,date,qty,kind,ref,user_id) VALUES(?,?,?,?,?,?)",
                                (ln["product_id"], now_str(), sign * ln["qty"], "IPTAL", inv["no"], user.id))
            self.db.execute("UPDATE invoices SET status='IPTAL', cancel_reason=? WHERE id=?", (reason.strip(), inv_id))
            self._audit(user, "FATURA_IPTAL", f"{inv['no']} — {reason.strip()}")

    def list_invoices(self, search="", inv_type=None, limit=500):
        like = f"%{search.strip()}%"
        sql = ("SELECT i.*, p.name AS party FROM invoices i JOIN parties p ON p.id=i.party_id "
               "WHERE (i.no LIKE ? OR p.name LIKE ?)")
        params = [like, like]
        if inv_type:
            sql += " AND i.type=?"
            params.append(inv_type)
        return self.q(sql + " ORDER BY i.id DESC LIMIT ?", params + [limit])

    def invoice_lines(self, inv_id):
        return self.q("SELECT l.*, p.sku, p.name FROM invoice_lines l JOIN products p ON p.id=l.product_id "
                      "WHERE invoice_id=? ORDER BY l.id", (inv_id,))

    # ── tahsilat / ödeme ─────────────────────────────────────────────
    def add_payment(self, user, party_id, kind, amount, method="Nakit", note=""):
        self._require(user, "odeme")
        if kind not in ("TAHSILAT", "ODEME"):
            raise ERPError("Geçersiz işlem tipi.")
        amt = parse_money(amount) if not isinstance(amount, int) else amount
        if amt <= 0:
            raise ERPError("Tutar sıfırdan büyük olmalı.")
        if not self.q1("SELECT 1 FROM parties WHERE id=? AND active=1", (party_id,)):
            raise ERPError("Cari seçiniz.")
        with self.tx():
            pid = self.db.execute("INSERT INTO payments(party_id,date,kind,amount,method,note,user_id) "
                                  "VALUES(?,?,?,?,?,?,?)",
                                  (party_id, now_str(), kind, amt, method, note.strip(), user.id)).lastrowid
            self._audit(user, kind, f"cari={party_id} {fmt_money(amt)}")
        return pid

    def list_payments(self, limit=300):
        return self.q("SELECT y.*, p.name AS party FROM payments y JOIN parties p ON p.id=y.party_id "
                      "ORDER BY y.id DESC LIMIT ?", (limit,))

    # ── gösterge paneli ve raporlar ──────────────────────────────────
    def dashboard(self):
        today, month = datetime.now().strftime("%Y-%m-%d"), datetime.now().strftime("%Y-%m")

        def total(where, params):
            return self.q1("SELECT COALESCE(SUM(total),0) t FROM invoices WHERE type='SATIS' AND status='AKTIF' "
                           + where, params)["t"]
        bal = self.q(f"SELECT {BALANCE_SQL} AS b FROM parties p WHERE active=1")
        return {
            "sales_today": total("AND substr(date,1,10)=?", (today,)),
            "sales_month": total("AND substr(date,1,7)=?", (month,)),
            "stock_value": self.q1("SELECT COALESCE(SUM(stock*buy_price),0) v FROM products WHERE active=1")["v"],
            "receivable": sum(r["b"] for r in bal if r["b"] > 0),
            "payable": -sum(r["b"] for r in bal if r["b"] < 0),
            "critical": self.q("SELECT sku,name,stock,min_stock FROM products "
                               "WHERE active=1 AND stock<=min_stock ORDER BY stock-min_stock"),
            "recent": self.list_invoices(limit=8),
        }

    REPORTS = {
        "stok": "Stok durumu ve stok değeri",
        "kritik": "Kritik stok listesi",
        "bakiye": "Cari bakiye listesi",
        "aylik": "Aylık satış özeti (son 12 ay)",
        "encok": "En çok satan 10 ürün",
    }

    def report(self, user, key):
        self._require(user, "rapor")
        if key == "stok":
            rows = self.q("SELECT sku,name,unit,stock,buy_price,stock*buy_price v FROM products WHERE active=1 "
                          "ORDER BY v DESC")
            return (["Stok kodu", "Ürün", "Birim", "Stok", "Alış fiyatı", "Stok değeri"],
                    [(r["sku"], r["name"], r["unit"], r["stock"], fmt_money(r["buy_price"]), fmt_money(r["v"]))
                     for r in rows])
        if key == "kritik":
            rows = self.q("SELECT sku,name,stock,min_stock FROM products WHERE active=1 AND stock<=min_stock "
                          "ORDER BY stock-min_stock")
            return (["Stok kodu", "Ürün", "Stok", "Kritik seviye", "Eksik"],
                    [(r["sku"], r["name"], r["stock"], r["min_stock"], r["min_stock"] - r["stock"]) for r in rows])
        if key == "bakiye":
            rows = [r for r in self.list_parties() if r["balance"]]
            return (["Cari kodu", "Unvan", "Tip", "Bakiye", "Durum"],
                    [(r["code"], r["name"], PARTY_TYPES[r["type"]], fmt_money(abs(r["balance"])),
                      "Alacaklıyız" if r["balance"] > 0 else "Borçluyuz") for r in rows])
        if key == "aylik":
            since = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-01")
            rows = self.q("SELECT substr(date,1,7) m, COUNT(*) n, SUM(subtotal) s, SUM(vat_total) k, SUM(total) t "
                          "FROM invoices WHERE type='SATIS' AND status='AKTIF' AND date>=? GROUP BY m ORDER BY m DESC",
                          (since,))
            return (["Ay", "Fatura adedi", "Net", "KDV", "Toplam"],
                    [(r["m"], r["n"], fmt_money(r["s"]), fmt_money(r["k"]), fmt_money(r["t"])) for r in rows])
        if key == "encok":
            rows = self.q("SELECT p.sku,p.name,SUM(l.qty) q,SUM(l.net) n FROM invoice_lines l "
                          "JOIN invoices i ON i.id=l.invoice_id JOIN products p ON p.id=l.product_id "
                          "WHERE i.type='SATIS' AND i.status='AKTIF' GROUP BY p.id ORDER BY q DESC LIMIT 10")
            return (["Stok kodu", "Ürün", "Satılan miktar", "Net ciro"],
                    [(r["sku"], r["name"], r["q"], fmt_money(r["n"])) for r in rows])
        raise ERPError("Bilinmeyen rapor.")

    def audit_log(self, limit=500):
        return self.q("SELECT ts,username,action,detail FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    # ── örnek veri ───────────────────────────────────────────────────
    def seed_demo(self, user):
        if self.q1("SELECT 1 FROM products LIMIT 1"):
            return
        prods = [("KBL-001", "Şarj kablosu Tip 2", "Adet", "850", "1450", 20, 10, 40),
                 ("ADP-010", "Duvar tipi şarj ünitesi 11 kW", "Adet", "18500", "27900", 20, 6, 8),
                 ("FLT-220", "Kabin hava filtresi", "Adet", "320", "590", 20, 15, 12),
                 ("LST-205", "Kış lastiği 235/45 R19", "Adet", "4200", "6350", 20, 8, 24),
                 ("SVC-100", "Periyodik bakım kiti", "Set", "2100", "3600", 20, 8, 9),
                 ("YAG-005", "Fren hidroliği DOT4 1L", "Adet", "180", "340", 20, 20, 60)]
        pids = [self.add_product(user, *p) for p in prods]
        m1 = self.save_party(user, None, "M001", "Akyazı Filo Kiralama Ltd.", "MUSTERI", "0264 000 00 00")
        m2 = self.save_party(user, None, "M002", "Sapanca Lojistik A.Ş.", "MUSTERI")
        t1 = self.save_party(user, None, "T001", "Marmara Oto Yedek Parça", "TEDARIKCI")
        self.create_invoice(user, "ALIS", t1, [(pids[2], 20, 31000), (pids[5], 30, 17500)])
        self.create_invoice(user, "SATIS", m1, [(pids[0], 4, 145000), (pids[3], 8, 635000)])
        self.create_invoice(user, "SATIS", m2, [(pids[1], 2, 2790000), (pids[4], 3, 360000)])
        self.add_payment(user, m1, "TAHSILAT", 2500000, "Havale/EFT", "Kısmi tahsilat")
        self.add_payment(user, t1, "ODEME", 500000, "Havale/EFT")


# ════════════════════════════════════════════════════════════════════
#  Birim testleri
# ════════════════════════════════════════════════════════════════════
class ERPTests(unittest.TestCase):
    def setUp(self):
        self.erp = ERP(":memory:")
        self.admin = self.erp.login("admin", "admin123")
        self.pid = self.erp.add_product(self.admin, "p-1", "Test ürünü", "Adet", "100", "150,50", 20, 2, 10)
        self.cust = self.erp.save_party(self.admin, None, "M1", "Müşteri A", "MUSTERI")
        self.supp = self.erp.save_party(self.admin, None, "T1", "Tedarikçi B", "TEDARIKCI")

    def test_money(self):
        self.assertEqual(parse_money("1.250,50 ₺"), 125050)
        self.assertEqual(parse_money("1250.5"), 125050)
        self.assertEqual(parse_money("0,005"), 1)
        self.assertEqual(fmt_money(123456789), "1.234.567,89 ₺")
        self.assertEqual(fmt_money(-5), "-0,05 ₺")
        self.assertRaises(ERPError, parse_money, "abc")
        self.assertRaises(ERPError, parse_money, "-3")

    def test_vat_rounding(self):
        self.assertEqual(calc_vat(1005, 20), 201)
        self.assertEqual(calc_vat(1002, 20), 200)

    def test_login_and_lockout(self):
        self.assertTrue(self.admin.must_change)
        for _ in range(MAX_FAILED_LOGINS):
            with self.assertRaises(ERPError):
                self.erp.login("admin", "yanlis")
        with self.assertRaisesRegex(ERPError, "kilitli"):
            self.erp.login("admin", "admin123")

    def test_password_change_policy(self):
        self.assertRaises(ERPError, self.erp.change_password, self.admin, "admin123", "kisa1")
        self.assertRaises(ERPError, self.erp.change_password, self.admin, "yanlis", "Guclu1234")
        self.erp.change_password(self.admin, "admin123", "Guclu1234")
        self.assertFalse(self.erp.login("admin", "Guclu1234").must_change)

    def test_role_permissions(self):
        self.erp.add_user(self.admin, "satisci", "Satis1234", "satis")
        s = self.erp.login("satisci", "Satis1234")
        self.assertRaises(ERPError, self.erp.add_product, s, "X", "X", "Adet", "1", "1")
        self.assertRaises(ERPError, self.erp.report, s, "stok")
        self.assertRaises(ERPError, self.erp.create_invoice, s, "ALIS", self.supp, [(self.pid, 1, 100)])
        self.erp.create_invoice(s, "SATIS", self.cust, [(self.pid, 1, 15050)])

    def test_sale_updates_stock_and_balance(self):
        inv = self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 3, 15050)])
        row = self.erp.q1("SELECT * FROM invoices WHERE id=?", (inv,))
        self.assertEqual(row["subtotal"], 45150)
        self.assertEqual(row["vat_total"], 9030)
        self.assertEqual(row["total"], 54180)
        self.assertEqual(row["no"][:3], "SF-")
        self.assertEqual(self.erp.get_product(self.pid)["stock"], 7)
        self.assertEqual(self.erp.party_balance(self.cust), 54180)

    def test_insufficient_stock_rolls_back(self):
        with self.assertRaisesRegex(ERPError, "Yetersiz stok"):
            self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 11, 100)])
        self.assertEqual(self.erp.get_product(self.pid)["stock"], 10)
        self.assertIsNone(self.erp.q1("SELECT 1 FROM invoices"))

    def test_wrong_party_type(self):
        self.assertRaises(ERPError, self.erp.create_invoice, self.admin, "SATIS", self.supp, [(self.pid, 1, 100)])

    def test_purchase_and_cancel(self):
        inv = self.erp.create_invoice(self.admin, "ALIS", self.supp, [(self.pid, 5, 9000)])
        self.assertEqual(self.erp.get_product(self.pid)["stock"], 15)
        self.assertEqual(self.erp.get_product(self.pid)["buy_price"], 9000)
        self.assertEqual(self.erp.party_balance(self.supp), -54000)
        self.erp.cancel_invoice(self.admin, inv, "Hatalı giriş")
        self.assertEqual(self.erp.get_product(self.pid)["stock"], 10)
        self.assertEqual(self.erp.party_balance(self.supp), 0)
        self.assertRaises(ERPError, self.erp.cancel_invoice, self.admin, inv, "tekrar")

    def test_invoice_numbering(self):
        a = self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 1, 100)])
        b = self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 1, 100)])
        na = self.erp.q1("SELECT no FROM invoices WHERE id=?", (a,))["no"]
        nb = self.erp.q1("SELECT no FROM invoices WHERE id=?", (b,))["no"]
        self.assertEqual(int(nb[-5:]), int(na[-5:]) + 1)

    def test_payment_and_statement(self):
        self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 2, 10000)])
        self.erp.add_payment(self.admin, self.cust, "TAHSILAT", "100,00")
        st = self.erp.party_statement(self.cust)
        self.assertEqual(st[-1][4], 24000 - 10000)
        self.assertRaises(ERPError, self.erp.add_payment, self.admin, self.cust, "TAHSILAT", "0")

    def test_stock_adjust(self):
        self.erp.adjust_stock(self.admin, self.pid, "-4", "Sayım farkı")
        self.assertEqual(self.erp.get_product(self.pid)["stock"], 6)
        self.assertRaises(ERPError, self.erp.adjust_stock, self.admin, self.pid, "-7", "x")
        self.assertRaises(ERPError, self.erp.adjust_stock, self.admin, self.pid, "1", "  ")

    def test_duplicates_and_injection(self):
        self.assertRaises(ERPError, self.erp.add_product, self.admin, "P-1", "Kopya", "Adet", "1", "1")
        self.assertEqual(self.erp.list_products("' OR 1=1 --"), [])
        self.assertRaises(ERPError, self.erp.login, "admin' --", "x")

    def test_reports_and_csv(self):
        import tempfile
        self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 9, 15050)])
        for key in ERP.REPORTS:
            headers, rows = self.erp.report(self.admin, key)
            self.assertTrue(headers)
        _, rows = self.erp.report(self.admin, "kritik")
        self.assertEqual(rows[0][0], "P-1")
        path = os.path.join(tempfile.mkdtemp(), "r.csv")
        export_csv(path, *self.erp.report(self.admin, "stok"))
        with open(path, encoding="utf-8-sig") as f:
            self.assertIn("Test ürünü", f.read())

    def test_dashboard(self):
        self.erp.create_invoice(self.admin, "SATIS", self.cust, [(self.pid, 1, 10000)])
        d = self.erp.dashboard()
        self.assertEqual(d["sales_today"], 12000)
        self.assertEqual(d["receivable"], 12000)
        self.assertEqual(d["stock_value"], 9 * 10000)

    def test_demo_seed(self):
        erp = ERP(":memory:")
        admin = erp.login("admin", "admin123")
        erp.seed_demo(admin)
        self.assertEqual(len(erp.list_products()), 6)
        self.assertGreater(erp.dashboard()["receivable"], 0)
        erp.seed_demo(admin)  # ikinci çağrı veri çoğaltmamalı
        self.assertEqual(len(erp.list_products()), 6)


# ════════════════════════════════════════════════════════════════════
#  Arayüz (tkinter / ttk)
# ════════════════════════════════════════════════════════════════════
def run_gui(erp, demo=False):
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog

    C = dict(bg="#111317", panel="#1b1e24", card="#22262d", fg="#e8eaed", muted="#9aa0a6",
             accent="#e31937", accent2="#ff4d5e", ok="#2ecc71", warn="#f5a623", line="#2c3038")
    FONT = ("Segoe UI", 10)

    def setup_style(root):
        st = ttk.Style(root)
        st.theme_use("clam")
        root.configure(bg=C["bg"])
        root.option_add("*TCombobox*Listbox.font", FONT)
        root.option_add("*TCombobox*Listbox.background", C["card"])
        root.option_add("*TCombobox*Listbox.foreground", C["fg"])
        st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["card"], font=FONT,
                     bordercolor=C["line"], lightcolor=C["line"], darkcolor=C["line"])
        st.configure("TFrame", background=C["bg"])
        st.configure("Panel.TFrame", background=C["panel"])
        st.configure("Card.TFrame", background=C["card"])
        st.configure("TLabel", background=C["bg"], foreground=C["fg"])
        st.configure("Panel.TLabel", background=C["panel"])
        st.configure("Muted.TLabel", foreground=C["muted"])
        st.configure("Card.TLabel", background=C["card"], foreground=C["muted"])
        st.configure("CardValue.TLabel", background=C["card"], foreground=C["fg"], font=("Segoe UI", 16, "bold"))
        st.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        st.configure("Logo.TLabel", background=C["panel"], foreground=C["accent"], font=("Segoe UI", 18, "bold"))
        st.configure("TButton", background=C["card"], foreground=C["fg"], padding=(12, 6), borderwidth=0)
        st.map("TButton", background=[("active", C["line"])])
        st.configure("Accent.TButton", background=C["accent"], foreground="white")
        st.map("Accent.TButton", background=[("active", C["accent2"])])
        st.configure("Nav.TButton", background=C["panel"], foreground=C["muted"], anchor="w", padding=(18, 10))
        st.map("Nav.TButton", background=[("active", C["card"])], foreground=[("active", C["fg"])])
        st.configure("NavActive.TButton", background=C["card"], foreground=C["fg"], anchor="w", padding=(18, 10))
        st.configure("TEntry", fieldbackground=C["card"], foreground=C["fg"], insertcolor=C["fg"], padding=5)
        st.configure("TCombobox", fieldbackground=C["card"], foreground=C["fg"], arrowcolor=C["fg"], padding=4)
        st.map("TCombobox", fieldbackground=[("readonly", C["card"])], foreground=[("readonly", C["fg"])])
        st.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["fg"],
                     rowheight=28, borderwidth=0)
        st.map("Treeview", background=[("selected", C["accent"])], foreground=[("selected", "white")])
        st.configure("Treeview.Heading", background=C["card"], foreground=C["muted"], relief="flat", padding=6)
        st.map("Treeview.Heading", background=[("active", C["line"])])
        st.configure("TCheckbutton", background=C["bg"], foreground=C["fg"])
        st.configure("Vertical.TScrollbar", background=C["card"], troughcolor=C["panel"], arrowcolor=C["muted"],
                     bordercolor=C["panel"], gripcount=0)
        st.map("Vertical.TScrollbar", background=[("active", C["line"])])

    def make_tree(parent, cols, height=15):
        """cols: [(anahtar, başlık, genişlik, hizalama)]"""
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", height=height)
        for key, title, width, anchor in cols:
            tree.heading(key, text=title)
            tree.column(key, width=width, anchor=anchor, stretch=True)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        tree.tag_configure("warn", foreground=C["warn"])
        tree.tag_configure("bad", foreground=C["accent2"])
        tree.tag_configure("ok", foreground=C["ok"])
        tree.tag_configure("muted", foreground=C["muted"])
        return frame, tree

    def fill_tree(tree, rows, tags=None):
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            tree.insert("", "end", iid=str(r[0]), values=r[1:], tags=(tags[i],) if tags and tags[i] else ())

    def selected_id(tree):
        sel = tree.selection()
        return int(sel[0]) if sel else None

    class FormDialog(tk.Toplevel):
        """Genel form. fields: dict(key,label,kind=entry|password|combo|check, values, default)"""
        def __init__(self, master, title, fields, on_submit, width=420):
            super().__init__(master)
            self.title(title)
            self.configure(bg=C["bg"])
            self.transient(master)
            self.resizable(False, False)
            self.on_submit, self.vars = on_submit, {}
            body = ttk.Frame(self, padding=18)
            body.pack(fill="both", expand=True)
            ttk.Label(body, text=title, style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                                                   pady=(0, 12))
            first = None
            for i, f in enumerate(fields, start=1):
                kind = f.get("kind", "entry")
                if kind == "check":
                    v = tk.BooleanVar(value=f.get("default", True))
                    w = ttk.Checkbutton(body, text=f["label"], variable=v)
                    w.grid(row=i, column=1, sticky="w", pady=4)
                else:
                    ttk.Label(body, text=f["label"], style="Muted.TLabel").grid(row=i, column=0, sticky="w",
                                                                                padx=(0, 12), pady=4)
                    v = tk.StringVar(value=str(f.get("default", "")))
                    if kind == "combo":
                        w = ttk.Combobox(body, textvariable=v, values=f["values"], state="readonly", width=30)
                    else:
                        w = ttk.Entry(body, textvariable=v, width=32, show="•" if kind == "password" else "")
                    w.grid(row=i, column=1, sticky="ew", pady=4)
                    first = first or w
                self.vars[f["key"]] = v
            btns = ttk.Frame(body)
            btns.grid(row=len(fields) + 1, column=0, columnspan=2, sticky="e", pady=(14, 0))
            ttk.Button(btns, text="Vazgeç", command=self.destroy).pack(side="right", padx=(8, 0))
            ttk.Button(btns, text="Kaydet", style="Accent.TButton", command=self.submit).pack(side="right")
            self.bind("<Return>", lambda e: self.submit())
            self.bind("<Escape>", lambda e: self.destroy())
            if first:
                first.focus_set()
            self.update_idletasks()
            self.geometry(f"+{master.winfo_rootx() + 120}+{master.winfo_rooty() + 80}")
            self.grab_set()

        def submit(self):
            values = {k: v.get() for k, v in self.vars.items()}
            try:
                self.on_submit(values)
            except ERPError as e:
                messagebox.showerror("Hata", str(e), parent=self)
                return
            self.destroy()

    # ── sayfalar ─────────────────────────────────────────────────────
    class Page(ttk.Frame):
        title = ""

        def __init__(self, app):
            super().__init__(app.content, padding=20)
            self.app, self.erp, self.user = app, app.erp, app.user
            head = ttk.Frame(self)
            head.pack(fill="x", pady=(0, 14))
            ttk.Label(head, text=self.title, style="Title.TLabel").pack(side="left")
            self.toolbar = ttk.Frame(head)
            self.toolbar.pack(side="right")
            self.build()

        def build(self):
            pass

        def refresh(self):
            pass

        def btn(self, text, cmd, accent=False):
            ttk.Button(self.toolbar, text=text, command=self.guard(cmd),
                       style="Accent.TButton" if accent else "TButton").pack(side="left", padx=(8, 0))

        def search_box(self, on_change):
            self.search = tk.StringVar()
            self.search.trace_add("write", lambda *_: on_change())
            e = ttk.Entry(self.toolbar, textvariable=self.search, width=26)
            e.pack(side="left")
            e.insert(0, "")
            ttk.Label(self.toolbar, text="🔍", style="Muted.TLabel").pack(side="left", padx=(4, 0), before=e)

        def guard(self, fn):
            def wrapped(*a):
                try:
                    fn(*a)
                except ERPError as e:
                    messagebox.showerror("Hata", str(e), parent=self)
            return wrapped

    class DashboardPage(Page):
        title = "Gösterge Paneli"

        def build(self):
            self.cards = ttk.Frame(self)
            self.cards.pack(fill="x")
            self.card_vals = {}
            for i, (key, label) in enumerate([("sales_today", "Bugünkü satış"), ("sales_month", "Bu ay satış"),
                                              ("receivable", "Toplam alacak"), ("payable", "Toplam borç"),
                                              ("stock_value", "Stok değeri")]):
                f = ttk.Frame(self.cards, style="Card.TFrame", padding=14)
                f.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
                self.cards.columnconfigure(i, weight=1)
                ttk.Label(f, text=label, style="Card.TLabel").pack(anchor="w")
                v = ttk.Label(f, text="-", style="CardValue.TLabel")
                v.pack(anchor="w", pady=(4, 0))
                self.card_vals[key] = v
            lower = ttk.Frame(self)
            lower.pack(fill="both", expand=True, pady=(18, 0))
            lower.columnconfigure(0, weight=3)
            lower.columnconfigure(1, weight=2)
            lower.rowconfigure(1, weight=1)
            ttk.Label(lower, text="Son faturalar", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(lower, text="Kritik stoktaki ürünler", style="Muted.TLabel").grid(row=0, column=1, sticky="w",
                                                                                      padx=(14, 0))
            f1, self.recent = make_tree(lower, [("no", "Fatura no", 120, "w"), ("date", "Tarih", 90, "center"),
                                                ("party", "Cari", 200, "w"), ("total", "Tutar", 110, "e")], 10)
            f1.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
            f2, self.crit = make_tree(lower, [("sku", "Kod", 90, "w"), ("name", "Ürün", 180, "w"),
                                              ("stock", "Stok", 60, "center"), ("min", "Kritik", 60, "center")], 10)
            f2.grid(row=1, column=1, sticky="nsew", padx=(14, 0), pady=(6, 0))

        def refresh(self):
            d = self.erp.dashboard()
            for k, lbl in self.card_vals.items():
                lbl.configure(text=fmt_money(d[k]))
            fill_tree(self.recent, [(r["id"], r["no"], fmt_date(r["date"]), r["party"], fmt_money(r["total"]))
                                    for r in d["recent"]],
                      ["muted" if r["status"] == "IPTAL" else "" for r in d["recent"]])
            fill_tree(self.crit, [(i, r["sku"], r["name"], r["stock"], r["min_stock"])
                                  for i, r in enumerate(d["critical"])],
                      ["bad" if r["stock"] == 0 else "warn" for r in d["critical"]])

    class ProductsPage(Page):
        title = "Ürünler ve Stok"

        def build(self):
            self.search_box(self.refresh)
            if self.erp.can(self.user, "urun.yaz"):
                self.btn("Yeni ürün", self.new, accent=True)
                self.btn("Düzenle", self.edit)
            if self.erp.can(self.user, "stok.duzelt"):
                self.btn("Stok düzelt", self.adjust)
            self.btn("Stok hareketleri", self.history)
            f, self.tree = make_tree(self, [("sku", "Stok kodu", 100, "w"), ("name", "Ürün adı", 260, "w"),
                                            ("unit", "Birim", 60, "center"), ("stock", "Stok", 70, "center"),
                                            ("min", "Kritik", 70, "center"), ("buy", "Alış", 110, "e"),
                                            ("sell", "Satış", 110, "e"), ("vat", "KDV %", 60, "center")])
            f.pack(fill="both", expand=True)
            self.tree.bind("<Double-1>", lambda e: self.guard(self.edit)() if self.erp.can(self.user, "urun.yaz")
                           else None)

        def refresh(self):
            rows = self.erp.list_products(self.search.get())
            fill_tree(self.tree, [(r["id"], r["sku"], r["name"], r["unit"], r["stock"], r["min_stock"],
                                   fmt_money(r["buy_price"]), fmt_money(r["sell_price"]), r["vat_rate"])
                                  for r in rows],
                      ["bad" if r["stock"] == 0 else "warn" if r["stock"] <= r["min_stock"] else "" for r in rows])

        def _fields(self, p=None, new=False):
            m = lambda k: fmt_money(p[k]).replace(" ₺", "") if p else ""
            f = [dict(key="sku", label="Stok kodu", default=p["sku"] if p else ""),
                 dict(key="name", label="Ürün adı", default=p["name"] if p else ""),
                 dict(key="unit", label="Birim", kind="combo", values=["Adet", "Set", "Kutu", "Paket", "Metre"],
                      default=p["unit"] if p else "Adet"),
                 dict(key="buy", label="Alış fiyatı (₺)", default=m("buy_price")),
                 dict(key="sell", label="Satış fiyatı (₺)", default=m("sell_price")),
                 dict(key="vat", label="KDV oranı (%)", kind="combo", values=["0", "1", "10", "20"],
                      default=p["vat_rate"] if p else "20"),
                 dict(key="min", label="Kritik stok", default=p["min_stock"] if p else "0")]
            if new:
                f.append(dict(key="open", label="Açılış stoğu", default="0"))
            else:
                f.append(dict(key="active", label="Aktif", kind="check", default=bool(p["active"])))
            return f

        def new(self):
            def save(v):
                self.erp.add_product(self.user, v["sku"], v["name"], v["unit"], v["buy"], v["sell"], v["vat"],
                                     v["min"], v["open"])
                self.refresh()
            FormDialog(self, "Yeni ürün", self._fields(new=True), save)

        def edit(self):
            pid = selected_id(self.tree)
            if not pid:
                raise ERPError("Önce bir ürün seçin.")
            p = self.erp.get_product(pid)

            def save(v):
                self.erp.update_product(self.user, pid, v["sku"], v["name"], v["unit"], v["buy"], v["sell"],
                                        v["vat"], v["min"], v["active"])
                self.refresh()
            FormDialog(self, f"Ürün düzenle — {p['sku']}", self._fields(p), save)

        def adjust(self):
            pid = selected_id(self.tree)
            if not pid:
                raise ERPError("Önce bir ürün seçin.")
            p = self.erp.get_product(pid)

            def save(v):
                self.erp.adjust_stock(self.user, pid, v["delta"], v["note"])
                self.refresh()
            FormDialog(self, f"Stok düzelt — {p['name']} (mevcut {p['stock']})",
                       [dict(key="delta", label="Miktar (+/-)", default=""),
                        dict(key="note", label="Açıklama", default="Sayım farkı")], save)

        def history(self):
            pid = selected_id(self.tree)
            if not pid:
                raise ERPError("Önce bir ürün seçin.")
            p = self.erp.get_product(pid)
            win = tk.Toplevel(self, bg=C["bg"])
            win.title(f"Stok hareketleri — {p['name']}")
            win.geometry("620x420")
            names = {"ACILIS": "Açılış", "SATIS": "Satış", "ALIS": "Alış", "IPTAL": "Fatura iptali",
                     "DUZELTME": "Düzeltme"}
            f, t = make_tree(win, [("date", "Tarih", 140, "w"), ("kind", "Hareket", 110, "w"),
                                   ("qty", "Miktar", 80, "center"), ("ref", "Belge / açıklama", 240, "w")])
            f.pack(fill="both", expand=True, padx=14, pady=14)
            rows = self.erp.stock_history(pid)
            fill_tree(t, [(i, r["date"], names.get(r["kind"], r["kind"]), f"{r['qty']:+d}", r["ref"])
                          for i, r in enumerate(rows)], ["ok" if r["qty"] > 0 else "bad" for r in rows])

    class PartiesPage(Page):
        title = "Cari Hesaplar"

        def build(self):
            self.search_box(self.refresh)
            if self.erp.can(self.user, "cari.yaz"):
                self.btn("Yeni cari", self.new, accent=True)
                self.btn("Düzenle", self.edit)
            self.btn("Ekstre", self.statement)
            f, self.tree = make_tree(self, [("code", "Kod", 80, "w"), ("name", "Unvan", 260, "w"),
                                            ("type", "Tip", 150, "w"), ("phone", "Telefon", 130, "w"),
                                            ("bal", "Bakiye", 130, "e"), ("dir", "Durum", 110, "w")])
            f.pack(fill="both", expand=True)
            self.tree.bind("<Double-1>", lambda e: self.guard(self.statement)())

        def refresh(self):
            rows = self.erp.list_parties(self.search.get())
            fill_tree(self.tree, [(r["id"], r["code"], r["name"], PARTY_TYPES[r["type"]], r["phone"] or "",
                                   fmt_money(abs(r["balance"])),
                                   "Alacaklıyız" if r["balance"] > 0 else "Borçluyuz" if r["balance"] < 0 else "—")
                                  for r in rows],
                      ["ok" if r["balance"] > 0 else "bad" if r["balance"] < 0 else "" for r in rows])

        def _form(self, title, p=None):
            types = list(PARTY_TYPES.values())
            g = lambda k: (p[k] or "") if p else ""

            def save(v):
                code = {n: k for k, n in PARTY_TYPES.items()}[v["type"]]
                self.erp.save_party(self.user, p["id"] if p else None, v["code"], v["name"], code, v["phone"],
                                    v["email"], v["tax"], v["addr"])
                self.refresh()
            FormDialog(self, title, [
                dict(key="code", label="Cari kodu", default=g("code")),
                dict(key="name", label="Unvan", default=g("name")),
                dict(key="type", label="Tip", kind="combo", values=types,
                     default=PARTY_TYPES[p["type"]] if p else types[0]),
                dict(key="phone", label="Telefon", default=g("phone")),
                dict(key="email", label="E-posta", default=g("email")),
                dict(key="tax", label="Vergi / TC no", default=g("tax_no")),
                dict(key="addr", label="Adres", default=g("address"))], save)

        def new(self):
            self._form("Yeni cari")

        def edit(self):
            pid = selected_id(self.tree)
            if not pid:
                raise ERPError("Önce bir cari seçin.")
            self._form("Cari düzenle", self.erp.q1("SELECT * FROM parties WHERE id=?", (pid,)))

        def statement(self):
            pid = selected_id(self.tree)
            if not pid:
                raise ERPError("Önce bir cari seçin.")
            p = self.erp.q1("SELECT * FROM parties WHERE id=?", (pid,))
            rows = self.erp.party_statement(pid)
            win = tk.Toplevel(self, bg=C["bg"])
            win.title(f"Cari ekstre — {p['name']}")
            win.geometry("760x460")
            f, t = make_tree(win, [("date", "Tarih", 100, "center"), ("doc", "Belge", 130, "w"),
                                   ("desc", "Açıklama", 220, "w"), ("amt", "Tutar", 120, "e"),
                                   ("run", "Bakiye", 120, "e")])
            f.pack(fill="both", expand=True, padx=14, pady=(14, 6))
            fill_tree(t, [(i, fmt_date(r[0]), r[1], r[2], fmt_money(r[3]), fmt_money(r[4]))
                          for i, r in enumerate(rows)])
            bal = rows[-1][4] if rows else 0
            ttk.Label(win, text=f"Güncel bakiye: {fmt_money(abs(bal))} "
                                f"({'alacaklıyız' if bal > 0 else 'borçluyuz' if bal < 0 else 'kapalı'})",
                      font=("Segoe UI", 11, "bold")).pack(anchor="e", padx=14, pady=(0, 6))

            def save_csv():
                path = filedialog.asksaveasfilename(parent=win, defaultextension=".csv",
                                                    initialfile=f"ekstre_{p['code']}.csv")
                if path:
                    export_csv(path, ["Tarih", "Belge", "Açıklama", "Tutar", "Bakiye"],
                               [(fmt_date(r[0]), r[1], r[2], fmt_money(r[3]), fmt_money(r[4])) for r in rows])
            ttk.Button(win, text="CSV olarak kaydet", command=save_csv).pack(anchor="e", padx=14, pady=(0, 14))

    class InvoiceDialog(tk.Toplevel):
        def __init__(self, page, inv_type):
            super().__init__(page)
            self.page, self.erp, self.user, self.inv_type = page, page.erp, page.user, inv_type
            self.lines = []  # (product_row, qty, price)
            self.title("Yeni satış faturası" if inv_type == "SATIS" else "Yeni alış faturası")
            self.configure(bg=C["bg"])
            self.geometry("1000x640")
            self.minsize(960, 560)
            self.transient(page)
            body = ttk.Frame(self, padding=18)
            body.pack(fill="both", expand=True)
            ttk.Label(body, text=self.title(), style="Title.TLabel").pack(anchor="w")

            top = ttk.Frame(body)
            top.pack(fill="x", pady=(12, 8))
            ttk.Label(top, text="Cari", style="Muted.TLabel").pack(side="left")
            parties = self.erp.list_parties(ptype="MUSTERI" if inv_type == "SATIS" else "TEDARIKCI")
            self.party_map = {f"{p['code']} — {p['name']}": p["id"] for p in parties}
            self.party = ttk.Combobox(top, values=list(self.party_map), state="readonly", width=46)
            self.party.pack(side="left", padx=(8, 20))
            ttk.Label(top, text="Not", style="Muted.TLabel").pack(side="left")
            self.note = ttk.Entry(top, width=30)
            self.note.pack(side="left", padx=(8, 0), fill="x", expand=True)

            add = ttk.Frame(body, style="Card.TFrame", padding=10)
            add.pack(fill="x", pady=(4, 8))
            prods = self.erp.list_products()
            self.prod_map = {f"{p['sku']} — {p['name']} (stok {p['stock']})": p for p in prods}
            ttk.Label(add, text="Ürün", style="Card.TLabel").grid(row=0, column=0, sticky="w")
            self.prod = ttk.Combobox(add, values=list(self.prod_map), width=50)
            self.prod.grid(row=1, column=0, padx=(0, 8))
            self.prod.bind("<<ComboboxSelected>>", self.on_product)
            self.prod.bind("<KeyRelease>", self.filter_products)
            ttk.Label(add, text="Miktar", style="Card.TLabel").grid(row=0, column=1, sticky="w")
            self.qty = ttk.Entry(add, width=8)
            self.qty.insert(0, "1")
            self.qty.grid(row=1, column=1, padx=(0, 8))
            ttk.Label(add, text="Birim fiyat (₺, KDV hariç)", style="Card.TLabel").grid(row=0, column=2, sticky="w")
            self.price = ttk.Entry(add, width=14)
            self.price.grid(row=1, column=2, padx=(0, 8))
            ttk.Button(add, text="Satır ekle", style="Accent.TButton",
                       command=page.guard(self.add_line)).grid(row=1, column=3)

            f, self.tree = make_tree(body, [("sku", "Kod", 90, "w"), ("name", "Ürün", 260, "w"),
                                            ("qty", "Miktar", 70, "center"), ("price", "Birim fiyat", 110, "e"),
                                            ("vat", "KDV %", 60, "center"), ("net", "Tutar", 120, "e")], 9)
            f.pack(fill="both", expand=True)

            self.totals = ttk.Label(body, text="", font=("Segoe UI", 11, "bold"))
            self.totals.pack(anchor="e", pady=(8, 0))
            bottom = ttk.Frame(body)
            bottom.pack(fill="x", pady=(10, 0))
            ttk.Button(bottom, text="Seçili satırı sil", command=self.remove_line).pack(side="left")
            ttk.Button(bottom, text="Vazgeç", command=self.destroy).pack(side="right", padx=(8, 0))
            ttk.Button(bottom, text="Faturayı kaydet", style="Accent.TButton",
                       command=page.guard(self.save)).pack(side="right")
            self.update_totals()
            self.grab_set()

        def filter_products(self, _e):
            text = self.prod.get().lower()
            self.prod["values"] = [k for k in self.prod_map if text in k.lower()]

        def on_product(self, _e=None):
            p = self.prod_map.get(self.prod.get())
            if p:
                self.price.delete(0, "end")
                price = p["sell_price"] if self.inv_type == "SATIS" else p["buy_price"]
                self.price.insert(0, fmt_money(price).replace(" ₺", ""))

        def add_line(self):
            p = self.prod_map.get(self.prod.get())
            if not p:
                raise ERPError("Listeden bir ürün seçin.")
            qty = parse_int(self.qty.get())
            price = parse_money(self.price.get())
            self.lines.append((p, qty, price))
            self.qty.delete(0, "end")
            self.qty.insert(0, "1")
            self.prod.set("")
            self.price.delete(0, "end")
            self.update_totals()

        def remove_line(self):
            sel = self.tree.selection()
            if sel:
                del self.lines[int(sel[0])]
                self.update_totals()

        def update_totals(self):
            fill_tree(self.tree, [(i, p["sku"], p["name"], q, fmt_money(pr), p["vat_rate"], fmt_money(q * pr))
                                  for i, (p, q, pr) in enumerate(self.lines)])
            net = sum(q * pr for _, q, pr in self.lines)
            vat = sum(calc_vat(q * pr, p["vat_rate"]) for p, q, pr in self.lines)
            self.totals.configure(text=f"Ara toplam: {fmt_money(net)}    KDV: {fmt_money(vat)}    "
                                       f"Genel toplam: {fmt_money(net + vat)}")

        def save(self):
            pid = self.party_map.get(self.party.get())
            if not pid:
                raise ERPError("Cari seçin.")
            inv_id = self.erp.create_invoice(self.user, self.inv_type, pid,
                                             [(p["id"], q, pr) for p, q, pr in self.lines], self.note.get())
            no = self.erp.q1("SELECT no FROM invoices WHERE id=?", (inv_id,))["no"]
            messagebox.showinfo("Kaydedildi", f"{no} numaralı fatura kaydedildi.", parent=self)
            self.destroy()
            self.page.refresh()

    class InvoicesPage(Page):
        title = "Faturalar"

        def build(self):
            self.search_box(self.refresh)
            if self.erp.can(self.user, "fatura.satis"):
                self.btn("Yeni satış", lambda: InvoiceDialog(self, "SATIS"), accent=True)
            if self.erp.can(self.user, "fatura.alis"):
                self.btn("Yeni alış", lambda: InvoiceDialog(self, "ALIS"))
            self.btn("Detay", self.detail)
            if self.erp.can(self.user, "fatura.iptal"):
                self.btn("İptal et", self.cancel)
            f, self.tree = make_tree(self, [("no", "Fatura no", 120, "w"), ("type", "Tip", 70, "center"),
                                            ("date", "Tarih", 90, "center"), ("party", "Cari", 230, "w"),
                                            ("sub", "Ara toplam", 110, "e"), ("vat", "KDV", 100, "e"),
                                            ("total", "Toplam", 120, "e"), ("st", "Durum", 70, "center")])
            f.pack(fill="both", expand=True)
            self.tree.bind("<Double-1>", lambda e: self.guard(self.detail)())

        def refresh(self):
            rows = self.erp.list_invoices(self.search.get())
            fill_tree(self.tree, [(r["id"], r["no"], "Satış" if r["type"] == "SATIS" else "Alış",
                                   fmt_date(r["date"]), r["party"], fmt_money(r["subtotal"]),
                                   fmt_money(r["vat_total"]), fmt_money(r["total"]),
                                   "Aktif" if r["status"] == "AKTIF" else "İptal") for r in rows],
                      ["muted" if r["status"] == "IPTAL" else "" for r in rows])

        def detail(self):
            iid = selected_id(self.tree)
            if not iid:
                raise ERPError("Önce bir fatura seçin.")
            inv = self.erp.q1("SELECT i.*, p.name party FROM invoices i JOIN parties p ON p.id=i.party_id "
                              "WHERE i.id=?", (iid,))
            win = tk.Toplevel(self, bg=C["bg"])
            win.title(f"Fatura {inv['no']}")
            win.geometry("720x420")
            info = f"{inv['no']}  ·  {fmt_date(inv['date'])}  ·  {inv['party']}"
            if inv["status"] == "IPTAL":
                info += f"  ·  İPTAL ({inv['cancel_reason']})"
            ttk.Label(win, text=info, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=14, pady=(14, 6))
            f, t = make_tree(win, [("sku", "Kod", 90, "w"), ("name", "Ürün", 240, "w"), ("q", "Miktar", 70, "center"),
                                   ("p", "Birim fiyat", 110, "e"), ("v", "KDV", 90, "e"), ("n", "Tutar", 110, "e")], 8)
            f.pack(fill="both", expand=True, padx=14)
            fill_tree(t, [(r["id"], r["sku"], r["name"], r["qty"], fmt_money(r["unit_price"]), fmt_money(r["vat"]),
                           fmt_money(r["net"])) for r in self.erp.invoice_lines(iid)])
            ttk.Label(win, text=f"Ara toplam {fmt_money(inv['subtotal'])}   KDV {fmt_money(inv['vat_total'])}   "
                                f"Toplam {fmt_money(inv['total'])}",
                      font=("Segoe UI", 11, "bold")).pack(anchor="e", padx=14, pady=14)

        def cancel(self):
            iid = selected_id(self.tree)
            if not iid:
                raise ERPError("Önce bir fatura seçin.")

            def save(v):
                self.erp.cancel_invoice(self.user, iid, v["reason"])
                self.refresh()
            FormDialog(self, "Fatura iptali", [dict(key="reason", label="İptal nedeni")], save)

    class PaymentsPage(Page):
        title = "Tahsilat ve Ödemeler"

        def build(self):
            self.btn("Tahsilat al", lambda: self.new("TAHSILAT"), accent=True)
            self.btn("Ödeme yap", lambda: self.new("ODEME"))
            f, self.tree = make_tree(self, [("date", "Tarih", 140, "w"), ("kind", "İşlem", 90, "center"),
                                            ("party", "Cari", 240, "w"), ("method", "Yöntem", 110, "w"),
                                            ("amt", "Tutar", 120, "e"), ("note", "Açıklama", 200, "w")])
            f.pack(fill="both", expand=True)

        def refresh(self):
            rows = self.erp.list_payments()
            fill_tree(self.tree, [(r["id"], r["date"][:16], "Tahsilat" if r["kind"] == "TAHSILAT" else "Ödeme",
                                   r["party"], r["method"] or "", fmt_money(r["amount"]), r["note"] or "")
                                  for r in rows], ["ok" if r["kind"] == "TAHSILAT" else "bad" for r in rows])

        def new(self, kind):
            parties = self.erp.list_parties(ptype="MUSTERI" if kind == "TAHSILAT" else "TEDARIKCI")
            pmap = {f"{p['code']} — {p['name']} (bakiye {fmt_money(p['balance'])})": p["id"] for p in parties}

            def save(v):
                if v["party"] not in pmap:
                    raise ERPError("Cari seçin.")
                self.erp.add_payment(self.user, pmap[v["party"]], kind, v["amount"], v["method"], v["note"])
                self.refresh()
            FormDialog(self, "Tahsilat" if kind == "TAHSILAT" else "Ödeme", [
                dict(key="party", label="Cari", kind="combo", values=list(pmap)),
                dict(key="amount", label="Tutar (₺)"),
                dict(key="method", label="Yöntem", kind="combo", values=["Nakit", "Havale/EFT", "Kredi kartı", "Çek"],
                     default="Nakit"),
                dict(key="note", label="Açıklama")], save)

    class ReportsPage(Page):
        title = "Raporlar"

        def build(self):
            self.names = {v: k for k, v in ERP.REPORTS.items()}
            self.choice = ttk.Combobox(self.toolbar, values=list(self.names), state="readonly", width=34)
            self.choice.pack(side="left")
            self.choice.current(0)
            self.choice.bind("<<ComboboxSelected>>", lambda e: self.refresh())
            self.btn("CSV olarak kaydet", self.save_csv, accent=True)
            self.holder = ttk.Frame(self)
            self.holder.pack(fill="both", expand=True)
            self.data = ([], [])

        def refresh(self):
            for w in self.holder.winfo_children():
                w.destroy()
            self.data = self.erp.report(self.user, self.names[self.choice.get()])
            headers, rows = self.data
            f, t = make_tree(self.holder, [(f"c{i}", h, 140, "w") for i, h in enumerate(headers)])
            f.pack(fill="both", expand=True)
            fill_tree(t, [(i, *r) for i, r in enumerate(rows)])

        def save_csv(self):
            path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                                initialfile=self.names[self.choice.get()] + "_raporu.csv")
            if path:
                export_csv(path, *self.data)
                messagebox.showinfo("Kaydedildi", "Rapor CSV olarak kaydedildi.", parent=self)

    class UsersPage(Page):
        title = "Kullanıcılar"

        def build(self):
            self.btn("Yeni kullanıcı", self.new, accent=True)
            self.btn("Aktif / pasif", self.toggle)
            self.btn("Şifre sıfırla", self.reset)
            f, self.tree = make_tree(self, [("u", "Kullanıcı adı", 180, "w"), ("r", "Rol", 140, "w"),
                                            ("a", "Durum", 90, "center"), ("c", "Oluşturulma", 160, "w")])
            f.pack(fill="both", expand=True)

        def refresh(self):
            rows = self.erp.list_users()
            fill_tree(self.tree, [(r["id"], r["username"], ROLE_NAMES[r["role"]],
                                   "Aktif" if r["active"] else "Pasif", r["created_at"]) for r in rows],
                      ["" if r["active"] else "muted" for r in rows])

        def new(self):
            roles = {v: k for k, v in ROLE_NAMES.items()}

            def save(v):
                self.erp.add_user(self.user, v["u"], v["p"], roles.get(v["r"], ""))
                self.refresh()
            FormDialog(self, "Yeni kullanıcı", [dict(key="u", label="Kullanıcı adı"),
                                                dict(key="p", label="Geçici şifre", kind="password"),
                                                dict(key="r", label="Rol", kind="combo", values=list(roles),
                                                     default="Satış")], save)

        def toggle(self):
            uid = selected_id(self.tree)
            if not uid:
                raise ERPError("Önce bir kullanıcı seçin.")
            row = self.erp.q1("SELECT active FROM users WHERE id=?", (uid,))
            self.erp.set_user_active(self.user, uid, not row["active"])
            self.refresh()

        def reset(self):
            uid = selected_id(self.tree)
            if not uid:
                raise ERPError("Önce bir kullanıcı seçin.")

            def save(v):
                self.erp.reset_password(self.user, uid, v["p"])
            FormDialog(self, "Şifre sıfırla", [dict(key="p", label="Yeni geçici şifre", kind="password")], save)

    class LogPage(Page):
        title = "İşlem Kaydı"

        def build(self):
            f, self.tree = make_tree(self, [("ts", "Zaman", 150, "w"), ("u", "Kullanıcı", 110, "w"),
                                            ("a", "İşlem", 150, "w"), ("d", "Detay", 380, "w")])
            f.pack(fill="both", expand=True)

        def refresh(self):
            fill_tree(self.tree, [(i, r["ts"], r["username"], r["action"], r["detail"] or "")
                                  for i, r in enumerate(self.erp.audit_log())])

    # ── ana uygulama ─────────────────────────────────────────────────
    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.erp, self.user, self.demo = erp, None, demo
            self.title(f"{APP_NAME} {VERSION}")
            self.geometry("1240x760")
            self.minsize(1000, 620)
            setup_style(self)
            self.show_login()

        def clear(self):
            for w in self.winfo_children():
                w.destroy()

        def show_login(self):
            self.clear()
            self.user = None
            outer = ttk.Frame(self)
            outer.pack(fill="both", expand=True)
            box = ttk.Frame(outer, style="Panel.TFrame", padding=36)
            box.place(relx=0.5, rely=0.5, anchor="center")
            ttk.Label(box, text="⚡ VOLT ERP", style="Logo.TLabel").pack(pady=(0, 4))
            ttk.Label(box, text="Kurumsal kaynak planlama", style="Panel.TLabel",
                      foreground=C["muted"]).pack(pady=(0, 20))
            u, p = tk.StringVar(), tk.StringVar()
            for text, var, show in (("Kullanıcı adı", u, ""), ("Şifre", p, "•")):
                ttk.Label(box, text=text, style="Panel.TLabel", foreground=C["muted"]).pack(anchor="w")
                e = ttk.Entry(box, textvariable=var, show=show, width=32)
                e.pack(pady=(2, 10))
                if not show:
                    e.focus_set()

            def do_login(*_):
                try:
                    self.user = self.erp.login(u.get(), p.get())
                except ERPError as ex:
                    messagebox.showerror("Giriş", str(ex), parent=self)
                    return
                if self.demo and self.user.role == "admin":
                    self.erp.seed_demo(self.user)
                if self.user.must_change:
                    self.force_password_change()
                else:
                    self.show_main()
            ttk.Button(box, text="Giriş yap", style="Accent.TButton", command=do_login).pack(fill="x", pady=(6, 0))
            ttk.Label(box, text="İlk giriş: admin / admin123", style="Panel.TLabel",
                      foreground=C["muted"]).pack(pady=(14, 0))
            self.bind("<Return>", do_login)

        def force_password_change(self):
            def save(v):
                if v["n1"] != v["n2"]:
                    raise ERPError("Yeni şifreler eşleşmiyor.")
                self.erp.change_password(self.user, v["old"], v["n1"])
                self.after(50, self.show_main)
            FormDialog(self, "Şifrenizi değiştirin", [dict(key="old", label="Mevcut şifre", kind="password"),
                                                       dict(key="n1", label="Yeni şifre", kind="password"),
                                                       dict(key="n2", label="Yeni şifre (tekrar)", kind="password")],
                       save)

        def show_main(self):
            self.clear()
            self.unbind("<Return>")
            side = ttk.Frame(self, style="Panel.TFrame", width=220)
            side.pack(side="left", fill="y")
            side.pack_propagate(False)
            ttk.Label(side, text="⚡ VOLT ERP", style="Logo.TLabel").pack(anchor="w", padx=18, pady=(20, 2))
            ttk.Label(side, text=f"{self.user.username} · {ROLE_NAMES[self.user.role]}", style="Panel.TLabel",
                      foreground=C["muted"]).pack(anchor="w", padx=18, pady=(0, 18))
            self.content = ttk.Frame(self)
            self.content.pack(side="left", fill="both", expand=True)

            can = lambda perm: self.erp.can(self.user, perm)
            pages = [("Gösterge paneli", DashboardPage, True),
                     ("Ürünler ve stok", ProductsPage, True),
                     ("Cari hesaplar", PartiesPage, can("cari.yaz") or can("odeme")),
                     ("Faturalar", InvoicesPage, can("fatura.satis") or can("fatura.alis")),
                     ("Tahsilat / ödeme", PaymentsPage, can("odeme")),
                     ("Raporlar", ReportsPage, can("rapor")),
                     ("Kullanıcılar", UsersPage, can("kullanici")),
                     ("İşlem kaydı", LogPage, self.user.role == "admin")]
            self.nav_buttons = {}
            for name, cls, visible in pages:
                if visible:
                    b = ttk.Button(side, text=name, style="Nav.TButton", command=lambda c=cls: self.open_page(c))
                    b.pack(fill="x")
                    self.nav_buttons[cls] = b
            ttk.Button(side, text="Çıkış yap", style="Nav.TButton", command=self.show_login).pack(side="bottom",
                                                                                                 fill="x", pady=12)
            self.page = None
            self.open_page(DashboardPage)

        def open_page(self, cls):
            if self.page:
                self.page.destroy()
            for c, b in self.nav_buttons.items():
                b.configure(style="NavActive.TButton" if c is cls else "Nav.TButton")
            self.page = cls(self)
            self.page.pack(fill="both", expand=True)
            try:
                self.page.refresh()
            except ERPError as e:
                messagebox.showerror("Hata", str(e), parent=self)

    app = App()
    app.mainloop()


# ════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description=f"{APP_NAME} {VERSION}")
    ap.add_argument("--test", action="store_true", help="birim testlerini çalıştır")
    ap.add_argument("--demo", action="store_true", help="boş veritabanına örnek veri ekle")
    ap.add_argument("--db", default=DEFAULT_DB, help="veritabanı dosyası")
    args = ap.parse_args()
    if args.test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ERPTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)
    run_gui(ERP(args.db), demo=args.demo)


if __name__ == "__main__":
    main()
