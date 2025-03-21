from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_session import Session #manejo de sesiones
from functools import wraps
import sqlite3
from datetime import datetime, timedelta
import bcrypt

app = Flask(__name__)

app.secret_key = 'tu_clave_secreta'  # Asegúrate de establecer una clave secreta

# Configure session to use filesystem (instead ofe signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

database_path = "library.db"  # Ruta al archivo de la base de datos SQLite

# Conexión con SQLite
connection = sqlite3.connect(database_path, check_same_thread=False)  

connection.row_factory = sqlite3.Row

#Decorador de ruta para el requerimiento de inicio de sesion
def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#ruta para el cierre de sesion


# Ruta para la página de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()  # Borra la sesión activa

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        print("Usuario ingresado:", username)

        try:
           # conn = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT id, user, contrasena FROM usuarios WHERE user = ?", (username,))
            user = cursor.fetchone()
            print(user)
            #conn.close()

            if user:
                user_id = user["id"]
                stored_hashed_password = user["contrasena"]
                if isinstance(stored_hashed_password, str):  
                    stored_hashed_password = stored_hashed_password.encode('utf-8')

                if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
                    session['user_id'] = user_id
                    session['username'] = username
                    print("Sesión iniciada correctamente para", username)
                    return redirect(url_for('index'))
                else:
                    print("Contraseña incorrecta")
                    flash("Contraseña incorrecta. Inténtalo de nuevo.", "danger")
            else:
                print("Usuario no encontrado")
                flash("Usuario no encontrado.", "danger")

        except sqlite3.Error as e:
            print("Error en la consulta:", e)
            flash("Error al procesar la solicitud. Intenta nuevamente.", "danger")

    return render_template('samples/login.html')

#cierre de sesion
@app.route("/logout", methods=['POST'])
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# Ruta para la página principal
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template("index.html")

#ruta para mostrar los productos en el apartado de venta
@app.route('/catalogo')
def catalogo():
    cursor = connection.cursor()
    cursor.execute("SELECT IDProducto, Nombre, Precio, ImagenURL FROM Producto")
    productos = cursor.fetchall()

    
    return render_template('catalogo.html', productos=productos)



if __name__ == '__main__':
    app.run(debug=True)