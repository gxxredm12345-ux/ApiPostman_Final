from datetime import datetime
from flask import Blueprint, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)

from extensions import db
from models import RefreshToken, RevokedToken, User, Category, Product, CartItem, Order, OrderItem
from flask_jwt_extended import create_access_token, create_refresh_token

front_bp = Blueprint("front", __name__, url_prefix="/api/front")


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




# Auth - Customer


@front_bp.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    jwt_data = get_jwt()
    user_id = int(get_jwt_identity())
    jti = jwt_data["jti"]

    token = RefreshToken.query.filter_by(jti=jti, revoked=False).first()
    if not token:
        return json_err("refresh token revoked or invalid", status=401)

    # Issue new access token
    new_access_token = create_access_token(
        identity=str(user_id),
        additional_claims={"role": jwt_data.get("role")},
    )

    return json_ok("token refreshed", {"access_token": new_access_token})



@front_bp.post("/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return json_err("email and password are required", status=400)

    if User.query.filter_by(email=email).first():
        return json_err("email already registered", status=409)

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        role="customer",
    )
    db.session.add(user)
    db.session.commit()

    return json_ok("registered", {"id": user.id, "email": user.email, "role": user.role}, 201)


@front_bp.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email:
        return json_err("email is required", status=400)

    if not password:
        return json_err("password is required", status=400)

    user = User.query.filter_by(email=email).first()
    if not user:
        return json_err("invalid credentials", status=401)

    if not check_password_hash(user.password_hash, password):
        return json_err("invalid credentials", status=401)

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )

    refresh_token = create_refresh_token(identity=str(user.id))

    # Save refresh token in DB
    from flask_jwt_extended import decode_token
    decoded = decode_token(refresh_token)

    db.session.add(
        RefreshToken(
            jti=decoded["jti"],
            user_id=user.id,
            expires_at=datetime.utcfromtimestamp(decoded["exp"]),
        )
    )
    db.session.commit()

    return json_ok(
        "login success",
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    )
@front_bp.post("/auth/logout")
@jwt_required()
def logout():
    jwt_data = get_jwt()
    user_id = int(jwt_data["sub"])

    # Revoke access token
    db.session.add(
        RevokedToken(
            jti=jwt_data["jti"],
            user_id=user_id,
            expires_at=datetime.utcfromtimestamp(jwt_data["exp"]),
        )
    )

    # Revoke all refresh tokens for user
    RefreshToken.query.filter_by(user_id=user_id, revoked=False).update(
        {"revoked": True}
    )

    db.session.commit()
    return json_ok("logout success")

@front_bp.post("/auth/reset-password")
@jwt_required()
def reset_password():
    body = request.get_json(silent=True) or {}
    old_password = body.get("old_password") or ""
    new_password = body.get("new_password") or ""

    if not old_password:
        return json_err("old_password is required", status=400)
    if not new_password:
        return json_err("new_password is required", status=400)
    if len(new_password) < 4:
        return json_err("new_password must be at least 4 characters", status=400)

    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return json_err("user not found", status=404)

 
    if not check_password_hash(user.password_hash, old_password):
        return json_err("old_password is incorrect", status=401)

    user.password_hash = generate_password_hash(new_password)

 
    RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({"revoked": True})

    jwt_data = get_jwt()
    db.session.add(
        RevokedToken(
            jti=jwt_data["jti"],
            user_id=user_id,
            expires_at=datetime.utcfromtimestamp(jwt_data["exp"]),
        )
    )

    db.session.commit()
    return json_ok("password updated. please login again.")


@front_bp.get("/category-list")
def category_list():
    categories = Category.query.order_by(Category.id.desc()).all()
    data = [{"id": c.id, "name": c.name} for c in categories]
    return json_ok("category list", data)


@front_bp.get("/product-list")
def product_list():
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
    return json_ok("product list", data)

@front_bp.get("/product-by-category-list/<int:category_id>")
def product_by_category(category_id: int):
    products = (
        Product.query
        .filter_by(category_id=category_id)
        .order_by(Product.id.desc())
        .all()
    )

    if not products:
        return json_ok("no products found for this category", [])

    data = []
    for p in products:
        data.append({
            "id": p.id,
            "category_id": p.category_id,
            "name": p.name,
            "price": p.price,
            "stock": p.stock,
            "description": p.description,
            "image_url": p.image_url,
        })

    return json_ok("list products by category", data)


@front_bp.post("/cart/add")
@jwt_required()
def add_to_cart():
    user_id = int(get_jwt_identity())
    body = request.get_json(silent=True) or {}

    product_id = body.get("product_id")
    qty = body.get("qty", 1)

    if not product_id:
        return json_err("product_id is required", status=400)

    try:
        qty = int(qty)
    except Exception:
        return json_err("qty must be a number", status=400)

    if qty <= 0:
        return json_err("qty must be >= 1", status=400)

    product = Product.query.get(product_id)
    if not product:
        return json_err("product not found", status=404)

    existing = CartItem.query.filter_by(
        user_id=user_id,
        product_id=product.id
    ).first()

    already_in_cart = existing.qty if existing else 0
    effective_available = product.stock - already_in_cart

    if qty > effective_available:
        return json_err(
            "not enough stock",
            {"available": effective_available},
            status=400
        )

    if existing:
        existing.qty += qty
    else:
        db.session.add(
            CartItem(
                user_id=user_id,
                product_id=product.id,
                qty=qty
            )
        )

    db.session.commit()
    return json_ok("added to cart")


@front_bp.post("/cart/remove")
@jwt_required()
def remove_qty_from_cart():
    user_id = int(get_jwt_identity())
    body = request.get_json(silent=True) or {}

    product_id = body.get("product_id")
    qty = body.get("qty", 1)

    if not product_id:
        return json_err("product_id is required", status=400)

    try:
        qty = int(qty)
    except Exception:
        return json_err("qty must be a number", status=400)

    if qty <= 0:
        return json_err("qty must be >= 1", status=400)

    item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if not item:
        return json_err("item not found in cart", status=404)

    if qty >= item.qty:
        db.session.delete(item)   # remove item completely
        db.session.commit()
        return json_ok("item removed from cart")
    else:
        item.qty -= qty
        db.session.commit()
        return json_ok("cart item quantity decreased", {"product_id": product_id, "qty": item.qty})



@front_bp.get("/cart")
@jwt_required()
def view_cart():
    user_id = int(get_jwt_identity())
    items = CartItem.query.filter_by(user_id=user_id).all()

    data = []
    total = 0.0
    for item in items:
        p = item.product
        line_total = float(p.price) * item.qty
        total += line_total
        data.append({
            "cart_item_id": item.id,
            "product_id": p.id,
            "name": p.name,
            "qty": item.qty,
            "unit_price": p.price,
            "total_amount_by_product": line_total,
        })

    return json_ok("cart", {"items": data, "total": total})



@front_bp.post("/checkout")
@jwt_required()
def checkout():
    user_id = int(get_jwt_identity())

    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    if not cart_items:
        return json_err("cart is empty", status=400)

    # Verify stock + compute total
    total = 0.0
    for ci in cart_items:
        product = ci.product
        if product.stock < ci.qty:
            return json_err(
                "not enough stock",
                {"product_id": product.id, "available": product.stock, "requested": ci.qty},
                status=400,
            )
        total += float(product.price) * ci.qty

    order = Order(user_id=user_id, status="pending", total_amount=total)
    db.session.add(order)
    db.session.flush()  # so order.id exists without committing yet

    # Create order items and deduct stock
    for ci in cart_items:
        product = ci.product
        db.session.add(OrderItem(
            order_id=order.id,
            product_id=product.id,
            qty=ci.qty,
            unit_price=product.price,
        ))
        product.stock -= ci.qty

    # Clear cart
    for ci in cart_items:
        db.session.delete(ci)

    db.session.commit()

    return json_ok("checkout success", {"order_id": order.id, "total_amount": order.total_amount}, 201)



# Order tracking 
# -------------------------
@front_bp.get("/order/tracking")
@jwt_required()
def tracking():
    user_id = int(get_jwt_identity())
    orders = Order.query.filter_by(user_id=user_id).order_by(Order.id.desc()).all()

    data = []
    for o in orders:
        data.append({
            "id": o.id,
            "status": o.status,
            "total_amount": o.total_amount,
            "created_at": o.created_at.isoformat(),
        })
    return json_ok("orders", data)


@front_bp.get("/order/<int:order_id>")
@jwt_required()
def order_detail(order_id: int):
    user_id = int(get_jwt_identity())
    order = Order.query.filter_by(id=order_id, user_id=user_id).first()
    if not order:
        return json_err("order not found", status=404)

    items = []
    for it in order.items:
        items.append({
            "product_id": it.product_id,
            "name": it.product.name if it.product else None,
            "qty": it.qty,
            "unit_price": it.unit_price,
        })

    return json_ok("order detail", {
        "id": order.id,
        "status": order.status,
        "total_amount": order.total_amount,
        "created_at": order.created_at.isoformat(),
        "items": items
    })
