from Model.user import *

def setuproute(app, call):
    @app.route('/signup',               ['OPTIONS', 'POST'],        lambda x = None: call([external_login]))
    def base():
        return
