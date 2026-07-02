from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
from flask_mysqldb import MySQL
import bcrypt
import secrets
from datetime import datetime, timedelta
import re

app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

# Helper Functions 

def obtener_usuario_por_email(email):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    usuario = cur.fetchone()
    cur.close()
    return usuario

def obtener_usuario_por_id(usuario_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (usuario_id,))
    usuario = cur.fetchone()
    cur.close()
    return usuario

def actualizar_actividad(usuario_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE usuarios SET ultima_actividad = %s WHERE id = %s",
                (datetime.now(), usuario_id))
    mysql.connection.commit()
    cur.close()

def verificar_sesion_activa():
    if 'usuario_id' not in session:
        return False
    usuario = obtener_usuario_por_id(session['usuario_id'])
    if not usuario:
        return False
    if not usuario['sesion_activa']:
        session.clear()
        return False
    if usuario['ultima_actividad']:
        tiempo_inactivo = datetime.now() - usuario['ultima_actividad']
        if tiempo_inactivo.total_seconds() > 15 * 60:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE usuarios SET sesion_activa = FALSE WHERE id = %s", (usuario['id'],))
            mysql.connection.commit()
            cur.close()
            session.clear()
            return False
    actualizar_actividad(usuario['id'])
    return True

def generar_token():
    return secrets.token_urlsafe(32)

def validar_contraseña(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

#  Middleware 
@app.before_request
def antes_de_cada_request():
    rutas_publicas = ['login', 'registro', 'recuperar', 'cambiar_password']
    if request.endpoint in rutas_publicas:
        return
    if not verificar_sesion_activa():
        flash('Your session has expired or you are not authenticated.', 'warning')
        return redirect(url_for('login'))

#  Routes 

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form.get('email')
        nombre = request.form.get('nombre')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if not email or not nombre or not password or not confirm:
            flash('All fields are required.', 'danger')
            return render_template('registro.html')
        if len(nombre) < 5:
            flash('Full name must be at least 5 characters.', 'danger')
            return render_template('registro.html')
        if not validar_contraseña(password):
            flash('Password must be at least 8 characters, including a letter and a number.', 'danger')
            return render_template('registro.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('registro.html')

        if obtener_usuario_por_email(email):
            flash('Email address is already registered.', 'danger')
            return render_template('registro.html')

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO usuarios (email, nombre_completo, password_hash)
            VALUES (%s, %s, %s)
        """, (email, nombre, password_hash))
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')

        usuario = obtener_usuario_por_email(email)
        if not usuario:
            flash('Invalid credentials.', 'danger')
            return render_template('login.html')

        if usuario['bloqueado_hasta'] and usuario['bloqueado_hasta'] > datetime.now():
            flash('Your account is locked for 2 hours due to multiple failed attempts.', 'danger')
            return render_template('login.html')

        if bcrypt.checkpw(password.encode('utf-8'), usuario['password_hash'].encode('utf-8')):
            cur = mysql.connection.cursor()
            cur.execute("""
                UPDATE usuarios
                SET intentos_fallidos = 0,
                    bloqueado_hasta = NULL,
                    sesion_activa = TRUE,
                    ultima_actividad = %s
                WHERE id = %s
            """, (datetime.now(), usuario['id']))
            mysql.connection.commit()
            cur.close()

            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario['nombre_completo']
            flash(f'Welcome {usuario["nombre_completo"]}! To logout click <a href="{url_for("logout")}">here</a>.', 'success')
            return redirect(url_for('dashboard'))
        else:
            nuevos_intentos = usuario['intentos_fallidos'] + 1
            bloqueo = None
            if nuevos_intentos >= 3:
                bloqueo = datetime.now() + timedelta(hours=2)
                flash('You have reached 3 failed attempts. Account locked for 2 hours.', 'danger')
            cur = mysql.connection.cursor()
            cur.execute("""
                UPDATE usuarios
                SET intentos_fallidos = %s,
                    bloqueado_hasta = %s
                WHERE id = %s
            """, (nuevos_intentos, bloqueo, usuario['id']))
            mysql.connection.commit()
            cur.close()
            flash('Invalid credentials.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'usuario_id' in session:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE usuarios SET sesion_activa = FALSE WHERE id = %s", (session['usuario_id'],))
        mysql.connection.commit()
        cur.close()
    session.clear()
    flash('Session closed successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', nombre=session.get('usuario_nombre'))

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please provide an email address.', 'danger')
            return render_template('recuperar.html')

        usuario = obtener_usuario_por_email(email)
        if not usuario:
            flash('If the email exists, you will receive a recovery link.', 'info')
            return redirect(url_for('login'))

        token = generar_token()
        expira = datetime.now() + timedelta(minutes=15)
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO tokens_recuperacion (usuario_id, token, expira_en)
            VALUES (%s, %s, %s)
        """, (usuario['id'], token, expira))
        mysql.connection.commit()
        cur.close()

        flash(f'Token generated (simulated): {token}. Use this token to change your password.', 'info')
        return redirect(url_for('cambiar_password', token=token))

    return render_template('recuperar.html')

@app.route('/cambiar_password', methods=['GET', 'POST'])
def cambiar_password():
    token = request.args.get('token') or request.form.get('token')
    if not token:
        flash('Token not provided.', 'danger')
        return redirect(url_for('recuperar'))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT * FROM tokens_recuperacion
        WHERE token = %s AND usado = FALSE AND expira_en > %s
    """, (token, datetime.now()))
    registro = cur.fetchone()
    cur.close()

    if not registro:
        flash('Invalid token, already used or expired.', 'danger')
        return redirect(url_for('recuperar'))

    if request.method == 'POST':
        nueva_password = request.form.get('nueva_password')
        confirmar = request.form.get('confirmar_password')

        if not validar_contraseña(nueva_password):
            flash('Password must be at least 8 characters, including a letter and a number.', 'danger')
            return render_template('cambiar_password.html', token=token)

        if nueva_password != confirmar:
            flash('Passwords do not match.', 'danger')
            return render_template('cambiar_password.html', token=token)

        password_hash = bcrypt.hashpw(nueva_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cur = mysql.connection.cursor()
        cur.execute("UPDATE usuarios SET password_hash = %s WHERE id = %s",
                    (password_hash, registro['usuario_id']))
        cur.execute("UPDATE tokens_recuperacion SET usado = TRUE WHERE id = %s", (registro['id'],))
        mysql.connection.commit()
        cur.close()

        flash('Password updated successfully. Login with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('cambiar_password.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)