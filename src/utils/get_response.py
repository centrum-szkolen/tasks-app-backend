from flask import jsonify

def get_response(msg,status,code,data=None):
    response = jsonify({
        'message':msg,
        'ok':status,
        'status':code,
        'data':data
    })
    response.status_code = code
    return response