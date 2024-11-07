from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')  # Load configurations from config.py

    # Import routes and register them with the app
    from .routes import main
    app.register_blueprint(main)

    return app
