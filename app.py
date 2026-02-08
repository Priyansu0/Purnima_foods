from __future__ import annotations

import csv
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO, StringIO
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, abort
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, ForeignKey, Text, func
)
from sqlalchemy.orm import (
    sessionmaker, declarative_base,
    relationship, scoped_session
)
from werkzeug.security import generate_password_hash, check_password_hash

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm


# ---------------------------
# App / DB setup
# ---------------------------

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

engine = create_engine("sqlite:///stock.db", echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

_DB_INITIALIZED = False


# ---------------------------
# Models
# ---------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(60), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # ADMIN / STAFF
    created_at = Column(DateTime, default=datetime.utcnow)

    # Flask-Login interface
    @property
    def is_authenticated(self): return True

    @property
    def is_active(self): return True

    @property
    def is_anonymous(self): return False

    def get_id(self): return str(self.id)


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True)
    sku = Column(String(60), unique=True, nullable=True)
    barcode = Column(String(80), unique=True, nullable=True)

    name = Column(String(200), nullable=False)
    category = Column(String(100), nullable=True)

    quantity = Column(Integer, nullable=False, default=0)
    cost_price = Column(Float, nullable=False, default=0.0)
    sell_price = Column(Float, nullable=False, default=0.0)
    low_stock_threshold = Column(Integer, nullable=False, default=5)

    created_at = Column(DateTime, default=datetime.utcnow)


class Purchase(Base):
    __tablename__ = "purchases"

    id = Column(Integer, primary_key=True)
    supplier_name = Column(String(200), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    items = relationship("PurchaseItem", back_populates="purchase", cascade="all, delete-orphan")


class PurchaseItem(Base):
    __tablename__ = "purchase_items"

    id = Column(Integer, primary_key=True)
    purchase_id = Column(Integer, ForeignKey("purchases.id"), nullable=False)
    item_id = Column(Integer, ForeignKey("items.id"), nullable=False)

    qty = Column(Integer, nullable=False)
    unit_cost = Column(Float, nullable=False)

    purchase = relationship("Purchase", back_populates="items")
    item = relationship("Item")


class Sale(Base):
    __tablename__ = "sales"

    id = Column(Integer, primary_key=True)
    customer_name = Column(String(200), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    items = relationship("SaleItem", back_populates="sale", cascade="all, delete-orphan")


class SaleItem(Base):
    __tablename__ = "sale_items"

    id = Column(Integer, primary_key=True)
    sale_id = Column(Integer, ForeignKey("sales.id"), nullable=False)
    item_id = Column(Integer, ForeignKey("items.id"), nullable=False)

    qty = Column(Integer, nullable=False)
    unit_price = Column(Float, nullable=False)

    sale = relationship("Sale", back_populates="items")
    item = relationship("Item")


# ---------------------------
# Helpers / auth
# ---------------------------

@login_manager.user_loader
def load_user(user_id: str):
    s = SessionLocal()
    try:
        return s.get(User, int(user_id))
    finally:
        s.close()


def role_required(*roles: str):
    roles_set = set(roles)

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if getattr(current_user, "role", None) not in roles_set:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def init_db_and_seed():
    Base.metadata.create_all(engine)
    s = SessionLocal()
    try:
        if s.query(User).count() == 0:
            s.add_all([
                User(username="admin", password_hash=generate_password_hash("admin123"), role="ADMIN"),
                User(username="staff", password_hash=generate_password_hash("staff123"), role="STAFF"),
            ])
            s.commit()
    finally:
        s.close()


@app.before_request
def ensure_db_once():
    global _DB_INITIALIZED
    if not _DB_INITIALIZED:
        init_db_and_seed()
        _DB_INITIALIZED = True


@app.teardown_appcontext
def shutdown_session(exception=None):
    SessionLocal.remove()


def adjust_stock(s, item_id: int, delta: int):
    it = s.get(Item, item_id)
    if not it:
        raise ValueError("Item not found")
    new_qty = (it.quantity or 0) + int(delta)
    if new_qty < 0:
        raise ValueError(f"Insufficient stock for: {it.name}")
    it.quantity = new_qty
    return it


# ---------------------------
# Routes: Auth
# ---------------------------

@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    s = SessionLocal()
    try:
        user = s.query(User).filter(User.username == username).first()
    finally:
        s.close()

    if not user or not check_password_hash(user.password_hash, password):
        flash("Invalid username or password", "danger")
        return redirect(url_for("login"))

    login_user(user)
    return redirect(url_for("dashboard"))


@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------------------
# Profile & Password Change (self)
# ---------------------------

@app.get("/account/profile")
@login_required
def account_profile():
    return render_template("profile.html")


@app.get("/account/password")
@login_required
def account_password():
    return render_template("password_change.html")


@app.post("/account/password")
@login_required
def account_password_post():
    old_pw = (request.form.get("old_password") or "").strip()
    new_pw = (request.form.get("new_password") or "").strip()
    new_pw2 = (request.form.get("new_password2") or "").strip()

    if not old_pw or not new_pw:
        flash("All fields are required", "danger")
        return redirect(url_for("account_password"))

    if new_pw != new_pw2:
        flash("New passwords do not match", "danger")
        return redirect(url_for("account_password"))

    s = SessionLocal()
    try:
        u = s.get(User, int(current_user.get_id()))
        if not u or not check_password_hash(u.password_hash, old_pw):
            flash("Old password is incorrect", "danger")
            return redirect(url_for("account_password"))

        u.password_hash = generate_password_hash(new_pw)
        s.commit()
        flash("Password updated successfully", "success")
    finally:
        s.close()

    return redirect(url_for("dashboard"))


# ---------------------------
# User Management (ADMIN)
# ---------------------------

@app.get("/users")
@login_required
@role_required("ADMIN")
def users_list():
    s = SessionLocal()
    try:
        users = s.query(User).order_by(User.created_at.desc()).all()
    finally:
        s.close()
    return render_template("users.html", users=users)


@app.post("/users/new")
@login_required
@role_required("ADMIN")
def users_new():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    role = (request.form.get("role") or "STAFF").strip().upper()
    if role not in ("ADMIN", "STAFF"):
        role = "STAFF"

    if not username or not password:
        flash("Username and password required", "danger")
        return redirect(url_for("users_list"))

    s = SessionLocal()
    try:
        if s.query(User).filter(User.username == username).first():
            flash("Username already exists", "danger")
            return redirect(url_for("users_list"))

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role
        )
        s.add(user)
        s.commit()
        flash("User created", "success")
    finally:
        s.close()

    return redirect(url_for("users_list"))


@app.post("/users/<int:user_id>/reset_password")
@login_required
@role_required("ADMIN")
def admin_reset_password(user_id: int):
    new_pw = (request.form.get("new_password") or "").strip()
    if not new_pw:
        flash("New password is required", "danger")
        return redirect(url_for("users_list"))

    s = SessionLocal()
    try:
        u = s.get(User, user_id)
        if not u:
            abort(404)
        u.password_hash = generate_password_hash(new_pw)
        s.commit()
        flash(f"Password reset for {u.username}", "success")
    finally:
        s.close()

    return redirect(url_for("users_list"))


# ---------------------------
# Dashboard
# ---------------------------

@app.get("/")
@login_required
def dashboard():
    s = SessionLocal()
    try:
        items_count = s.query(func.count(Item.id)).scalar() or 0
        low_stock = (
            s.query(Item)
            .filter(Item.quantity <= Item.low_stock_threshold)
            .order_by(Item.quantity.asc())
            .limit(10)
            .all()
        )
        recent_sales = s.query(Sale).order_by(Sale.created_at.desc()).limit(8).all()
        recent_purchases = s.query(Purchase).order_by(Purchase.created_at.desc()).limit(8).all()
    finally:
        s.close()

    return render_template(
        "dashboard.html",
        items_count=items_count,
        low_stock=low_stock,
        recent_sales=recent_sales,
        recent_purchases=recent_purchases
    )


# ---------------------------
# Items (CRUD)
# ---------------------------

@app.get("/items")
@login_required
def items_list():
    q = (request.args.get("q") or "").strip().lower()
    s = SessionLocal()
    try:
        query = s.query(Item)
        if q:
            query = query.filter(
                (func.lower(Item.name).like(f"%{q}%")) |
                (func.lower(Item.category).like(f"%{q}%")) |
                (func.lower(Item.sku).like(f"%{q}%")) |
                (func.lower(Item.barcode).like(f"%{q}%"))
            )
        items = query.order_by(Item.name.asc()).all()
    finally:
        s.close()
    return render_template("items.html", items=items, q=q)


@app.get("/items/new")
@login_required
@role_required("ADMIN")
def item_new():
    return render_template("item_form.html", item=None)


@app.post("/items/new")
@login_required
@role_required("ADMIN")
def item_new_post():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Name is required", "danger")
        return redirect(url_for("item_new"))

    data = {
        "name": name,
        "category": (request.form.get("category") or "").strip() or None,
        "sku": (request.form.get("sku") or "").strip() or None,
        "barcode": (request.form.get("barcode") or "").strip() or None,
        "quantity": int(request.form.get("quantity") or 0),
        "cost_price": float(request.form.get("cost_price") or 0),
        "sell_price": float(request.form.get("sell_price") or 0),
        "low_stock_threshold": int(request.form.get("low_stock_threshold") or 5),
    }

    s = SessionLocal()
    try:
        if data["sku"] and s.query(Item).filter(Item.sku == data["sku"]).first():
            flash("SKU already exists", "danger")
            return redirect(url_for("item_new"))
        if data["barcode"] and s.query(Item).filter(Item.barcode == data["barcode"]).first():
            flash("Barcode already exists", "danger")
            return redirect(url_for("item_new"))

        s.add(Item(**data))
        s.commit()
        flash("Item created", "success")
    finally:
        s.close()

    return redirect(url_for("items_list"))


@app.get("/items/<int:item_id>/edit")
@login_required
@role_required("ADMIN")
def item_edit(item_id: int):
    s = SessionLocal()
    try:
        it = s.get(Item, item_id)
        if not it:
            abort(404)
    finally:
        s.close()
    return render_template("item_form.html", item=it)


@app.post("/items/<int:item_id>/edit")
@login_required
@role_required("ADMIN")
def item_edit_post(item_id: int):
    s = SessionLocal()
    try:
        it = s.get(Item, item_id)
        if not it:
            abort(404)

        it.name = (request.form.get("name") or "").strip() or it.name
        it.category = (request.form.get("category") or "").strip() or None

        sku = (request.form.get("sku") or "").strip() or None
        barcode = (request.form.get("barcode") or "").strip() or None

        if sku and s.query(Item).filter(Item.sku == sku, Item.id != it.id).first():
            flash("SKU already exists", "danger")
            return redirect(url_for("item_edit", item_id=item_id))
        if barcode and s.query(Item).filter(Item.barcode == barcode, Item.id != it.id).first():
            flash("Barcode already exists", "danger")
            return redirect(url_for("item_edit", item_id=item_id))

        it.sku = sku
        it.barcode = barcode
        it.quantity = int(request.form.get("quantity") or it.quantity or 0)
        it.cost_price = float(request.form.get("cost_price") or it.cost_price or 0)
        it.sell_price = float(request.form.get("sell_price") or it.sell_price or 0)
        it.low_stock_threshold = int(request.form.get("low_stock_threshold") or it.low_stock_threshold or 5)

        s.commit()
        flash("Item updated", "success")
    finally:
        s.close()

    return redirect(url_for("items_list"))


@app.post("/items/<int:item_id>/delete")
@login_required
@role_required("ADMIN")
def item_delete(item_id: int):
    s = SessionLocal()
    try:
        it = s.get(Item, item_id)
        if not it:
            abort(404)
        s.delete(it)
        s.commit()
        flash("Item deleted", "success")
    finally:
        s.close()
    return redirect(url_for("items_list"))


# ---------------------------
# CSV Import/Export (Items)
# ---------------------------

@app.get("/export/items.csv")
@login_required
@role_required("ADMIN")
def export_items_csv():
    s = SessionLocal()
    try:
        items = s.query(Item).order_by(Item.id.asc()).all()
    finally:
        s.close()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["name", "category", "sku", "barcode", "quantity", "cost_price", "sell_price", "low_stock_threshold"])
    for it in items:
        cw.writerow([
            it.name,
            it.category or "",
            it.sku or "",
            it.barcode or "",
            it.quantity,
            it.cost_price,
            it.sell_price,
            it.low_stock_threshold,
        ])

    return send_file(
        BytesIO(si.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="items.csv"
    )


@app.post("/import/items.csv")
@login_required
@role_required("ADMIN")
def import_items_csv():
    file = request.files.get("file")
    if not file:
        flash("No CSV file uploaded", "danger")
        return redirect(url_for("items_list"))

    content = file.stream.read().decode("utf-8", errors="replace").splitlines()
    reader = csv.DictReader(content)

    s = SessionLocal()
    try:
        count = 0
        for row in reader:
            name = (row.get("name") or "").strip()
            if not name:
                continue

            sku = (row.get("sku") or "").strip() or None
            barcode = (row.get("barcode") or "").strip() or None

            # if sku/barcode already exists, update; else insert
            existing = None
            if sku:
                existing = s.query(Item).filter(Item.sku == sku).first()
            if not existing and barcode:
                existing = s.query(Item).filter(Item.barcode == barcode).first()

            def _int(v, default=0):
                try: return int(float(v))
                except Exception: return default

            def _float(v, default=0.0):
                try: return float(v)
                except Exception: return default

            if existing:
                existing.name = name
                existing.category = (row.get("category") or "").strip() or None
                existing.quantity = _int(row.get("quantity"), existing.quantity or 0)
                existing.cost_price = _float(row.get("cost_price"), existing.cost_price or 0.0)
                existing.sell_price = _float(row.get("sell_price"), existing.sell_price or 0.0)
                existing.low_stock_threshold = _int(row.get("low_stock_threshold"), existing.low_stock_threshold or 5)
                if sku: existing.sku = sku
                if barcode: existing.barcode = barcode
            else:
                s.add(Item(
                    name=name,
                    category=(row.get("category") or "").strip() or None,
                    sku=sku,
                    barcode=barcode,
                    quantity=_int(row.get("quantity"), 0),
                    cost_price=_float(row.get("cost_price"), 0.0),
                    sell_price=_float(row.get("sell_price"), 0.0),
                    low_stock_threshold=_int(row.get("low_stock_threshold"), 5),
                ))
            count += 1

        s.commit()
        flash(f"CSV imported/updated {count} row(s)", "success")
    except Exception as e:
        s.rollback()
        flash(f"Import error: {e}", "danger")
    finally:
        s.close()

    return redirect(url_for("items_list"))


# ---------------------------
# Purchases (increase stock)
# ---------------------------

@app.get("/purchases")
@login_required
def purchases_list():
    s = SessionLocal()
    try:
        purchases = s.query(Purchase).order_by(Purchase.created_at.desc()).limit(200).all()
    finally:
        s.close()
    return render_template("purchases_list.html", purchases=purchases)


@app.get("/purchases/new")
@login_required
@role_required("ADMIN")
def purchase_new():
    s = SessionLocal()
    try:
        items = s.query(Item).order_by(Item.name.asc()).all()
    finally:
        s.close()
    return render_template("purchase_new.html", items=items)


@app.post("/purchases/new")
@login_required
@role_required("ADMIN")
def purchase_new_post():
    supplier = (request.form.get("supplier_name") or "").strip() or None
    note = (request.form.get("note") or "").strip() or None

    item_ids = request.form.getlist("item_id")
    qtys = request.form.getlist("qty")
    costs = request.form.getlist("unit_cost")

    parsed = []
    for i in range(len(item_ids)):
        if not item_ids[i]:
            continue
        qty = int(qtys[i] or 0)
        unit_cost = float(costs[i] or 0)
        if qty <= 0:
            continue
        parsed.append({"item_id": int(item_ids[i]), "qty": qty, "unit_cost": unit_cost})

    if not parsed:
        flash("Add at least one purchase item with qty > 0", "danger")
        return redirect(url_for("purchase_new"))

    s = SessionLocal()
    try:
        p = Purchase(supplier_name=supplier, note=note)
        s.add(p)
        s.flush()

        for li in parsed:
            s.add(PurchaseItem(
                purchase_id=p.id,
                item_id=li["item_id"],
                qty=li["qty"],
                unit_cost=li["unit_cost"],
            ))
            adjust_stock(s, li["item_id"], +li["qty"])

        s.commit()
        flash(f"Purchase #{p.id} saved, stock updated", "success")
    except Exception as e:
        s.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        s.close()

    return redirect(url_for("purchases_list"))


# ---------------------------
# Sales (decrease stock)
# ---------------------------

@app.get("/sales")
@login_required
def sales_list():
    s = SessionLocal()
    try:
        sales = s.query(Sale).order_by(Sale.created_at.desc()).limit(200).all()
    finally:
        s.close()
    return render_template("sales_list.html", sales=sales)


@app.get("/sales/new")
@login_required
def sales_new():
    s = SessionLocal()
    try:
        items = s.query(Item).order_by(Item.name.asc()).all()
    finally:
        s.close()
    return render_template("sales_new.html", items=items)


@app.post("/sales/new")
@login_required
def sales_new_post():
    customer = (request.form.get("customer_name") or "").strip() or None
    note = (request.form.get("note") or "").strip() or None

    item_ids = request.form.getlist("item_id")
    qtys = request.form.getlist("qty")
    prices = request.form.getlist("unit_price")

    parsed = []
    for i in range(len(item_ids)):
        if not item_ids[i]:
            continue
        qty = int(qtys[i] or 0)
        unit_price = float(prices[i] or 0)
        if qty <= 0:
            continue
        parsed.append({"item_id": int(item_ids[i]), "qty": qty, "unit_price": unit_price})

    if not parsed:
        flash("Add at least one sale item with qty > 0", "danger")
        return redirect(url_for("sales_new"))

    s = SessionLocal()
    try:
        # decrease stock first to validate
        for li in parsed:
            adjust_stock(s, li["item_id"], -li["qty"])

        sale = Sale(customer_name=customer, note=note)
        s.add(sale)
        s.flush()

        for li in parsed:
            s.add(SaleItem(
                sale_id=sale.id,
                item_id=li["item_id"],
                qty=li["qty"],
                unit_price=li["unit_price"],
            ))

        s.commit()
        flash(f"Sale #{sale.id} saved, stock updated", "success")
        return redirect(url_for("sale_invoice_html", sale_id=sale.id))
    except Exception as e:
        s.rollback()
        flash(f"Error: {e}", "danger")
        return redirect(url_for("sales_new"))
    finally:
        s.close()


# ---------------------------
# Invoice: HTML preview + PDF
# ---------------------------

@app.get("/sales/<int:sale_id>/invoice")
@login_required
def sale_invoice_html(sale_id: int):
    s = SessionLocal()
    try:
        sale = s.get(Sale, sale_id)
        if not sale:
            abort(404)
        _ = sale.items
        for li in sale.items:
            _ = li.item
        total = sum(li.qty * li.unit_price for li in sale.items)
    finally:
        s.close()
    return render_template("invoice_view.html", sale=sale, total=total)


def generate_invoice_pdf_bytes(sale: Sale) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    y = h - 18 * mm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(18 * mm, y, "INVOICE")
    y -= 10 * mm

    c.setFont("Helvetica", 10)
    c.drawString(18 * mm, y, f"Invoice #: {sale.id}")
    c.drawString(90 * mm, y, f"Date: {sale.created_at.strftime('%Y-%m-%d %H:%M')}")
    y -= 6 * mm
    c.drawString(18 * mm, y, f"Customer: {sale.customer_name or '-'}")
    y -= 10 * mm

    c.setFont("Helvetica-Bold", 10)
    c.drawString(18 * mm, y, "Item")
    c.drawRightString(130 * mm, y, "Qty")
    c.drawRightString(160 * mm, y, "Price")
    c.drawRightString(196 * mm, y, "Total")
    y -= 3 * mm
    c.line(18 * mm, y, 196 * mm, y)
    y -= 7 * mm

    c.setFont("Helvetica", 10)
    grand = 0.0

    for li in sale.items:
        line_total = li.qty * li.unit_price
        grand += line_total

        c.drawString(18 * mm, y, (li.item.name or "")[:45])
        c.drawRightString(130 * mm, y, str(li.qty))
        c.drawRightString(160 * mm, y, f"{li.unit_price:.2f}")
        c.drawRightString(196 * mm, y, f"{line_total:.2f}")
        y -= 6 * mm

        if y < 25 * mm:
            c.showPage()
            y = h - 18 * mm
            c.setFont("Helvetica", 10)

    y -= 6 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(196 * mm, y, f"Grand Total: {grand:.2f}")

    c.showPage()
    c.save()
    return buf.getvalue()


@app.get("/sales/<int:sale_id>/invoice.pdf")
@login_required
def sale_invoice_pdf(sale_id: int):
    s = SessionLocal()
    try:
        sale = s.get(Sale, sale_id)
        if not sale:
            abort(404)
        _ = sale.items
        for li in sale.items:
            _ = li.item
        pdf_bytes = generate_invoice_pdf_bytes(sale)
    finally:
        s.close()

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"invoice_sale_{sale_id}.pdf",
    )


# ---------------------------
# Reports + Profit + Chart Data (top_items used by JS)
# ---------------------------

@app.get("/reports")
@login_required
def reports():
    end_s = request.args.get("end") or date.today().isoformat()
    start_s = request.args.get("start") or (date.today() - timedelta(days=6)).isoformat()

    try:
        start_dt = datetime.fromisoformat(start_s + "T00:00:00")
        end_dt = datetime.fromisoformat(end_s + "T23:59:59")
    except ValueError:
        flash("Invalid date format. Use YYYY-MM-DD.", "danger")
        return redirect(url_for("reports"))

    s = SessionLocal()
    try:
        total_rev = (
            s.query(func.sum(SaleItem.qty * SaleItem.unit_price))
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.created_at >= start_dt, Sale.created_at <= end_dt)
            .scalar()
            or 0.0
        )

        total_qty = (
            s.query(func.sum(SaleItem.qty))
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.created_at >= start_dt, Sale.created_at <= end_dt)
            .scalar()
            or 0
        )

        top_items = (
            s.query(
                Item.name.label("name"),
                func.sum(SaleItem.qty).label("qty"),
                func.sum(SaleItem.qty * SaleItem.unit_price).label("rev"),
            )
            .join(Item, Item.id == SaleItem.item_id)
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.created_at >= start_dt, Sale.created_at <= end_dt)
            .group_by(Item.name)
            .order_by(func.sum(SaleItem.qty * SaleItem.unit_price).desc())
            .limit(10)
            .all()
        )

        low_stock = (
            s.query(Item)
            .filter(Item.quantity <= Item.low_stock_threshold)
            .order_by(Item.quantity.asc())
            .all()
        )

        profit_rows = (
            s.query(
                Item.name.label("name"),
                func.sum(SaleItem.qty).label("qty"),
                func.sum(SaleItem.qty * SaleItem.unit_price).label("revenue"),
                func.sum(SaleItem.qty * Item.cost_price).label("cost"),
            )
            .join(Item, Item.id == SaleItem.item_id)
            .join(Sale, Sale.id == SaleItem.sale_id)
            .filter(Sale.created_at >= start_dt, Sale.created_at <= end_dt)
            .group_by(Item.name)
            .order_by(func.sum(SaleItem.qty * SaleItem.unit_price).desc())
            .all()
        )

        total_profit = 0.0
        for r in profit_rows:
            total_profit += float((r.revenue or 0) - (r.cost or 0))

    finally:
        s.close()

    return render_template(
        "reports.html",
        start=start_s,
        end=end_s,
        total_rev=float(total_rev),
        total_qty=int(total_qty),
        top_items=top_items,
        low_stock=low_stock,
        profit_rows=profit_rows,
        total_profit=float(total_profit),
    )


# ---------------------------
# Run
# ---------------------------

if __name__ == "__main__":
    init_db_and_seed()
    _DB_INITIALIZED = True
    app.run(host="0.0.0.0", port=5000, debug=True)
