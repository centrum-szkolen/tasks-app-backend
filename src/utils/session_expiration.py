from flask import session 
from datetime import timedelta

def set_session_expiration(app):
    session.permanent = True 
    app.permament_session_lifetime = timedelta(minutes=30)
    return app.permament_session_lifetime