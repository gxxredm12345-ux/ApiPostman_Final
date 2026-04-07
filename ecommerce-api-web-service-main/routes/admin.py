from datetime import datetime
from flask import Blueprint, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    jwt_required,
    get_jwt,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    decode_token,
)

from extensions import db
from models import User, Category, Product, Order, OrderItem, RefreshToken, RevokedToken

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


def json_ok(message="", data=None, status=200):
    payload = {"success": True, "message": message}
    if data is not None:
        payload["data"] = data
    return payload, status


def json_err(message="", errors=None, status=400):
    payload = {"success": False, "message": message}
    if errors is not None:
        payload["errors"] = errors
    return payload, status


def admin_required():
    claims = get_jwt()
    return claims.get("role") == "admin"


def parse_date_yyyy_mm_dd(value: str):
   
    return datetime.strptime(value, "%Y-%m-%d")

# -------------------------
# Admin Auth
# -------------------------
@admin_bp.post("/auth/login")
def admin_login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return json_err("email and password are required", status=400)

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_err("invalid credentials", status=401)

    if user.role != "admin":
        return json_err("admin access only", status=403)

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )
    refresh_token = create_refresh_token(identity=str(user.id))


    decoded = decode_token(refresh_token)
    db.session.add(
        RefreshToken(
            jti=decoded["jti"],
            user_id=user.id,
            expires_at=datetime.utcfromtimestamp(decoded["exp"]),
        )
    )
    db.session.commit()

    return json_ok("admin login success", {"access_token": access_token, "refresh_token": refresh_token})


@admin_bp.post("/auth/refresh")
@jwt_required(refresh=True)
def admin_refresh():
    jwt_data = get_jwt()
    user_id = int(get_jwt_identity())
    jti = jwt_data["jti"]

    token = RefreshToken.query.filter_by(jti=jti, revoked=False).first()
    if not token:
        return json_err("refresh token revoked or invalid", status=401)

    user = User.query.get(user_id)
    if not user or user.role != "admin":
        return json_err("admin access only", status=403)

    new_access = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )
    return json_ok("token refreshed", {"access_token": new_access})


@admin_bp.post("/auth/logout")
@jwt_required()
def admin_logout():
    if not admin_required():
        return json_err("admin access only", status=403)

    jwt_data = get_jwt()
    user_id = int(jwt_data["sub"])

    # revoke access token
    db.session.add(
        RevokedToken(
            jti=jwt_data["jti"],
            user_id=user_id,
            expires_at=datetime.utcfromtimestamp(jwt_data["exp"]),
        )
    )

    # revoke all refresh tokens
    RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({"revoked": True})
    db.session.commit()

    return json_ok("logout success")


# Users CRUD (admin)
# -------------------------
@admin_bp.get("/users")
@jwt_required()
def list_users():
    if not admin_required():
        return json_err("admin access only", status=403)

    users = User.query.order_by(User.id.desc()).all()
    data = [{"id": u.id, "email": u.email, "role": u.role, "created_at": u.created_at.isoformat()} for u in users]
    return json_ok("users", data)


@admin_bp.post("/users")
@jwt_required()
def create_user():
    if not admin_required():
        return json_err("admin access only", status=403)

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "customer").strip().lower()

    if role not in ("customer", "admin"):
        return json_err("role must be customer or admin", status=400)

    if not email or not password:
        return json_err("email and password are required", status=400)

    if User.query.filter_by(email=email).first():
        return json_err("email already exists", status=409)

    u = User(email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(u)
    db.session.commit()

    return json_ok("user created", {"id": u.id, "email": u.email, "role": u.role}, 201)


@admin_bp.put("/users/<int:user_id>")
@jwt_required()
def update_user(user_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    u = User.query.get(user_id)
    if not u:
        return json_err("user not found", status=404)

    body = request.get_json(silent=True) or {}
    role = body.get("role")
    password = body.get("password")

    if role is not None:
        role = str(role).strip().lower()
        if role not in ("customer", "admin"):
            return json_err("role must be customer or admin", status=400)
        u.role = role

    if password:
        u.password_hash = generate_password_hash(password)

    db.session.commit()
    return json_ok("user updated", {"id": u.id, "email": u.email, "role": u.role})


@admin_bp.delete("/users/<int:user_id>")
@jwt_required()
def delete_user(user_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    u = User.query.get(user_id)
    if not u:
        return json_err("user not found", status=404)

    db.session.delete(u)
    db.session.commit()
    return json_ok("user deleted")


# Categories CRUD (admin)

@admin_bp.get("/categories")
@jwt_required()
def list_categories():
    if not admin_required():
        return json_err("admin access only", status=403)

    cats = Category.query.order_by(Category.id.desc()).all()
    return json_ok("categories", [{"id": c.id, "name": c.name} for c in cats])


@admin_bp.post("/categories")
@jwt_required()
def create_category():
    if not admin_required():
        return json_err("admin access only", status=403)

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return json_err("name is required", status=400)

    if Category.query.filter_by(name=name).first():
        return json_err("category already exists", status=409)

    c = Category(name=name)
    db.session.add(c)
    db.session.commit()
    return json_ok("category created", {"id": c.id, "name": c.name}, 201)


@admin_bp.put("/categories/<int:category_id>")
@jwt_required()
def update_category(category_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    c = Category.query.get(category_id)
    if not c:
        return json_err("category not found", status=404)

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return json_err("name is required", status=400)

    c.name = name
    db.session.commit()
    return json_ok("category updated", {"id": c.id, "name": c.name})


@admin_bp.delete("/categories/<int:category_id>")
@jwt_required()
def delete_category(category_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    c = Category.query.get(category_id)
    if not c:
        return json_err("category not found", status=404)

    db.session.delete(c)
    db.session.commit()
    return json_ok("category deleted")


# Products CRUD (admin)
# -------------------------
@admin_bp.get("/products")
@jwt_required()
def list_products():
    if not admin_required():
        return json_err("admin access only", status=403)

    products = Product.query.order_by(Product.id.desc()).all()
    data = []
    for p in products:
        data.append({
            "id": p.id,
            "category_id": p.category_id,
            "category_name": p.category.name if p.category else None,
            "name": p.name,
            "price": p.price,
            "stock": p.stock,
            "description": p.description,
            "image_url": p.image_url,
        })
    return json_ok("products", data)


@admin_bp.post("/products")
@jwt_required()
def create_product():
    if not admin_required():
        return json_err("admin access only", status=403)

    body = request.get_json(silent=True) or {}
    category_id = body.get("category_id")
    name = (body.get("name") or "").strip().lower()
    price = body.get("price", 0)
    stock = body.get("stock", 0)
    description = body.get("description")
    image_url = body.get("image_url")

    if not category_id or not name:
        return json_err("category_id and name are required", status=400)

    if not Category.query.get(category_id):
        return json_err("category not found", status=404)
    try:
        price = float(price)
        stock = int(stock)
    except Exception:
        return json_err("price must be number and stock must be whole number", status=400)

    if price < 0:
        return json_err("price must be >= 0", status=400)

    if stock < 0:
        return json_err("stock must be >= 0", status=400)

    existing = Product.query.filter_by(
        category_id=category_id,
        name=name,
        price=price,
    ).first()

    if existing:
        existing.stock += stock

        if description is not None:
            existing.description = description
        if image_url is not None:
            existing.image_url = image_url

        db.session.commit()
        return json_ok(
            "product exists: stock increased",
            {"id": existing.id, "stock": existing.stock},
            200,
        )

    p = Product(
        category_id=category_id,
        name=name,
        price=price,
        stock=stock,
        description=description,
        image_url=image_url,
    )
    db.session.add(p)
    db.session.commit()

    return json_ok("product created", {"id": p.id}, 201)



@admin_bp.put("/products/<int:product_id>")
@jwt_required()
def update_product(product_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    p = Product.query.get(product_id)
    if not p:
        return json_err("product not found", status=404)

    body = request.get_json(silent=True) or {}

    if "category_id" in body:
        cat_id = body.get("category_id")
        if not Category.query.get(cat_id):
            return json_err("category not found", status=404)
        p.category_id = cat_id

    if "name" in body:
        p.name = (body.get("name") or "").strip().lower()

    if "price" in body:
        try:
            new_price = float(body.get("price"))
        except Exception:
            return json_err("price must be a number", status=400)

        if new_price < 0:
            return json_err("price must be >= 0", status=400)

        p.price = new_price


    if "stock" in body:
        try:
            new_stock = int(body.get("stock"))
        except Exception:
            return json_err("stock must be an integer", status=400)

        if new_stock < 0:
            return json_err("stock must be >= 0", status=400)

        p.stock = new_stock


    if "description" in body:
        p.description = body.get("description")

    if "image_url" in body:
        p.image_url = body.get("image_url")

    db.session.commit()
    return json_ok("product updated", {"id": p.id})


@admin_bp.delete("/products/<int:product_id>")
@jwt_required()
def delete_product(product_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    p = Product.query.get(product_id)
    if not p:
        return json_err("product not found", status=404)

    db.session.delete(p)
    db.session.commit()
    return json_ok("product deleted")


# -------------------------
# Orders management (admin)
# -------------------------
@admin_bp.get("/orders")
@jwt_required()
def list_orders():
    if not admin_required():
        return json_err("admin access only", status=403)

    orders = Order.query.order_by(Order.id.desc()).all()
    data = []
    for o in orders:
        data.append({
            "id": o.id,
            "user_id": o.user_id,
            "user_email": o.user.email if o.user else None,
            "status": o.status,
            "total_amount": o.total_amount,
            "created_at": o.created_at.isoformat(),
        })
    return json_ok("orders", data)


@admin_bp.get("/orders/<int:order_id>")
@jwt_required()
def order_detail(order_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    o = Order.query.get(order_id)
    if not o:
        return json_err("order not found", status=404)

    items = []
    for it in o.items:
        items.append({
            "product_id": it.product_id,
            "name": it.product.name if it.product else None,
            "qty": it.qty,
            "unit_price": it.unit_price,
        })

    return json_ok("order detail", {
        "id": o.id,
        "user_id": o.user_id,
        "user_email": o.user.email if o.user else None,
        "status": o.status,
        "total_amount": o.total_amount,
        "created_at": o.created_at.isoformat(),
        "items": items,
    })


@admin_bp.put("/orders/<int:order_id>/status")
@jwt_required()
def update_order_status(order_id: int):
    if not admin_required():
        return json_err("admin access only", status=403)

    o = Order.query.get(order_id)
    if not o:
        return json_err("order not found", status=404)

    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip().lower()
    if not status:
        return json_err("status is required", status=400)

    allowed = {"pending", "paid", "shipped", "delivered", "cancelled"}
    if status not in allowed:
        return json_err(f"status must be one of {sorted(list(allowed))}", status=400)

    o.status = status
    db.session.commit()
    return json_ok("order status updated", {"id": o.id, "status": o.status})


# Sales report (admin) - detailed
# -------------------------
@admin_bp.get("/report/sales")
@jwt_required()
def sales_report():
    if not admin_required():
        return json_err("admin access only", status=403)

    date_from = request.args.get("from")
    date_to = request.args.get("to")

    q = Order.query

    if date_from:
        try:
            dt_from = parse_date_yyyy_mm_dd(date_from)
            q = q.filter(Order.created_at >= dt_from)
        except Exception:
            return json_err("from must be YYYY-MM-DD", status=400)

    if date_to:
        try:
            dt_to = parse_date_yyyy_mm_dd(date_to)
            dt_to_end = dt_to.replace(hour=23, minute=59, second=59)
            q = q.filter(Order.created_at <= dt_to_end)
        except Exception:
            return json_err("to must be YYYY-MM-DD", status=400)

    orders = q.order_by(Order.created_at.desc()).all()

    total_revenue = sum(float(o.total_amount) for o in orders)
    total_orders = len(orders)

    by_status = {}
    for o in orders:
        by_status[o.status] = by_status.get(o.status, 0) + 1

    orders_detail = []
    for o in orders:
        items = []
        order_total = 0.0

        for item in o.items:
            subtotal = float(item.qty * item.unit_price)
            order_total += subtotal

            items.append({
                "product_id": item.product_id,
                "product_name": item.product.name if item.product else None,
                "qty": item.qty,
                "unit_price": float(item.unit_price),
                "subtotal": subtotal,
            })

        orders_detail.append({
            "order_id": o.id,
            "ordered_by": {
                "user_id": o.user_id,
                "email": o.user.email if o.user else None,
            },
            "status": o.status,
            "created_at": o.created_at.isoformat() if o.created_at else None,
            "items": items,
            "total_amount": order_total,
        })

    return json_ok("sales report", {
        "from": date_from,
        "to": date_to,
        "summary": {
            "total_orders": total_orders,
            "total_revenue": total_revenue,
            "orders_by_status": by_status,
        },
        "orders": orders_detail,
    })
