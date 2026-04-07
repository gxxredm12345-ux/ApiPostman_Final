from flask import Flask
from config import Config
from extensions import db, jwt
from models import RevokedToken
from routes.front import front_bp
from routes.admin import admin_bp
from werkzeug.security import generate_password_hash
from models import User
import os

def create_default_admin():
    admin_email = "admin@gmail.com"
    admin_password = "admin123"

    admin = User.query.filter_by(role="admin").first()
    if admin:
        return 

    user = User(
        email=admin_email,
        password_hash=generate_password_hash(admin_password),
        role="admin",
    )
    db.session.add(user)
    db.session.commit()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)

    with app.app_context():
       # if os.getenv("AUTO_DB_CREATE", "false").lower() == "true":
            db.create_all()
            create_default_admin()


    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload.get("jti")
        return (
            RevokedToken.query.filter_by(jti=jti).first()
            is not None
        )

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {
            "success": False,
            "message": "Token has been revoked. Please login again."
        }, 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {
            "success": False,
            "message": "Token expired. Please login again."
        }, 401
    
    
    app.register_blueprint(front_bp)
    app.register_blueprint(admin_bp)

    @app.get("/")
    def root():
        return {"success": True, "message": "E-commerce API running"}

    return app

app = create_app()



if __name__ == "__main__":
    app.run(debug=True)
