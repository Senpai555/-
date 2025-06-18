from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import os
import requests
import ollama
import re
import logging
import traceback
from oauthlib.oauth1 import Client, SIGNATURE_TYPE_AUTH_HEADER

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key_here')  # Використовуйте змінну оточення або тимчасовий ключ

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Logging setup
logging.basicConfig(level=logging.DEBUG)

# SQLite database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

# Google OAuth setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Для розробки на localhost
GOOGLE_CLIENT_ID = '325257999772-lamvnof0pl8pbn3jpnn5t96rt5g9s72a.apps.googleusercontent.com'
client_secrets_file = os.path.join(os.path.dirname(__file__), "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/login/google/callback"
)

def ask_coach(question, domain="fitness", muscle_group=None, user_params=None):
    if domain == "nutrition":
        system_prompt = "Ти — тренер Ши, професійний дієтолог і фітнес-тренер. Якщо запит стосується продуктів харчування, відповідай списком із 1–5 реальних продуктів, які корисні для здоров’я та підтримання форми. Використовуй лише офіційні назви продуктів українською мовою, наприклад, 'Куряча грудка', 'Гречка', 'Авокадо', 'Лосось', 'Яйця'. Кожен продукт має супроводжуватися коротким описом (1-2 речення) про його користь та вміст білків, жирів або вуглеводів, якщо це уточнено. Не включай шкідливі продукти (фастфуд, солодощі тощо). Якщо запит стосується розподілу білків, жирів і вуглеводів (БЖВ), дай рекомендацію у відсотках або грамах на день для середньої людини (наприклад, 70 кг), враховуючи мету (набір маси, схуднення тощо), якщо вона вказана. Подавай відповідь чітко у форматі: '1. Назва продукту – опис' або 'БЖВ: Білки – X%, Жири – Y%, Вуглеводи – Z%'."
    elif domain == "training_plan":
        if user_params:
            level = user_params.get('level', 'середній')
            weight = user_params.get('weight', 70)
            height = user_params.get('height', 170)
            goal = user_params.get('goal', 'підтримка форми')
            system_prompt = f"Ти — тренер Ши, професійний фітнес-тренер. Склади персоналізовану тренувальну програму на 3–5 днів для користувача з рівнем підготовки '{level}', вагою {weight} кг, зростом {height} см і метою '{goal}'. Для кожної вправи вкажи кількість підходів, повторень і відпочинок між підходами, враховуючи ці параметри. Використовуй офіційні назви вправ українською мовою, наприклад, 'Присідання', 'Підтягування', 'Станова тяга'. Подавай відповідь у форматі: 'День 1: 1. Назва вправи – X підходів по Y повторень, відпочинок Z секунд'."
        else:
            system_prompt = "Ти — тренер Ши, професійний фітнес-тренер. Якщо користувач просить скласти тренувальну програму, створи план на 3–5 днів, враховуючи мету (набір маси, схуднення, витривалість тощо), якщо вона вказана, або тривалість (тиждень, місяць тощо). Для кожної вправи вкажи кількість підходів, повторень і відпочинок між підходами. Використовуй офіційні назви вправ українською мовою, наприклад, 'Присідання', 'Підтягування', 'Станова тяга'. Якщо мета чи тривалість не вказана, орієнтуйся на загальну підтримку форми на тиждень. Подавай відповідь у форматі: 'День 1: 1. Назва вправи – X підходів по Y повторень, відпочинок Z секунд'."
    else:  # fitness
        if not muscle_group:
            system_prompt = "Ти — тренер Ши, професійний фітнес-тренер. Якщо група м’язів не вказана, попроси користувача уточнити (наприклад, 'спина', 'ноги', 'руки'). Якщо група м’язів вказана, відповідай лише списком із 1–5 реальних вправ для цієї групи. Використовуй офіційні назви вправ українською мовою, наприклад, 'Присідання', 'Підтягування', 'Станова тяга'. Уникай вигаданих або неправильних перекладів. Кожна вправа має супроводжуватися коротким описом про те, які м’язи вона розвиває. Подавай відповідь у форматі: '1. Назва вправи – опис'."
        else:
            system_prompt = f"Ти — тренер Ши, професійний фітнес-тренер. Відповідай списком із 1–5 реальних вправ, які націлені на м’язи {muscle_group.lower()}. Використовуй лише офіційні назви вправ українською мовою, наприклад, 'Присідання', 'Підтягування', 'Станова тяга'. Уникай вигаданих або неправильних перекладів. Кожна вправа має супроводжуватися коротким описом (1-2 речення) про те, які м’язи {muscle_group.lower()} вона розвиває, без філософії чи вигадок. Подавай відповідь у форматі: '1. Назва вправи – опис'."

    return ollama.chat(
        model="mistral:instruct",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

@app.route('/')
def index():
    lang = session.get('lang', 'ua')
    return render_template('index.html', lang=lang)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1])
            login_user(user_obj)
            return redirect(url_for('welcome'))
        else:
            flash('Невірний email або пароль', 'error')
            return redirect(url_for('login'))
    
    lang = session.get('lang', 'ua')
    return render_template('login.html', lang=lang)

@app.route('/login/google')
def login_google():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/login/google/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        return "State does not match!", 400

    credentials = flow.credentials
    id_info = id_token.verify_oauth2_token(
        credentials.id_token, Request(), GOOGLE_CLIENT_ID
    )

    email = id_info['email']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    
    if not user:
        hashed_password = generate_password_hash('google_oauth_user')
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
    
    user_obj = User(user[0], user[1])
    login_user(user_obj)
    conn.close()
    
    return redirect(url_for('welcome'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Паролі не співпадають', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            conn.commit()
            conn.close()
            
            flash('Реєстрація успішна! Увійдіть в систему.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email вже зареєстрований', 'error')
            return redirect(url_for('register'))
    
    lang = session.get('lang', 'ua')
    return render_template('register.html', lang=lang)

@app.route('/welcome')
@login_required
def welcome():
    lang = session.get('lang', 'ua')
    return render_template('welcome.html', lang=lang)

@app.route('/profile')
@login_required
def profile():
    lang = session.get('lang', 'ua')
    return render_template('profile.html', lang=lang)

@app.route('/guides')
@login_required
def guides():
    lang = session.get('lang', 'ua')
    return render_template('guides.html', lang=lang)

@app.route('/bju_calculator')
@login_required
def bju_calculator():
    lang = session.get('lang', 'ua')
    return render_template('bju_calculator.html', lang=lang)

@app.route('/nutrition_recommendations')
@login_required
def nutrition_recommendations():
    lang = session.get('lang', 'ua')
    return render_template('nutrition_recommendations.html', lang=lang)

@app.route('/ai_chat')
@login_required
def ai_chat():
    lang = session.get('lang', 'ua')
    return render_template('ai_chat.html', lang=lang)

@app.route('/ask', methods=['POST'])
@login_required
def ask():
    question = request.json.get('question')
    if not question:
        return jsonify({"error": "No question provided"}), 400
    
    domain = "fitness"
    muscle_group = None
    user_params = None

    question_lower = question.lower()
    muscle_groups = {
        'ноги': ['ноги', 'стегна', 'квадрицепси', 'литки'],
        'спина': ['спина', 'поперековий'],
        'руки': ['руки', 'біцепс', 'трицепс'],
        'груди': ['груди', 'грудні'],
        'прес': ['прес', 'живіт', 'абдомінальні'],
        'плечі': ['плечі', 'дельти', 'дельтовидні'],
        'сідниці': ['сідниці', 'ягодичні'],
        'передпліччя': ['передпліччя'],
        'задня поверхня стегна': ['задня поверхня стегна', 'біцепс стегна'],
        'шия': ['шия'],
        'кор': ['кор', 'центральна частина', 'стабілізуючі м’язи'],
        'трапеції': ['трапеції']
    }

    for group, keywords in muscle_groups.items():
        if any(keyword in question_lower for keyword in keywords):
            muscle_group = group
            break

    if any(word in question_lower for word in ['програма', 'план', 'розпиши', 'на тиждень', 'на місяць']):
        domain = "training_plan"
        user_params = {}
        if any(word in question_lower for word in ['початківець', 'новачок']):
            user_params['level'] = 'початківець'
        elif any(word in question_lower for word in ['середній', 'досвідчений']):
            user_params['level'] = 'середній'
        elif any(word in question_lower for word in ['просунутий', 'експерт']):
            user_params['level'] = 'просунутий'
        
        weight_match = re.search(r'вага\s*(\d+)\s*кг', question_lower)
        if weight_match:
            user_params['weight'] = int(weight_match.group(1))
        
        height_match = re.search(r'зріст\s*(\d+)\s*см', question_lower)
        if height_match:
            user_params['height'] = int(height_match.group(1))
        
        if any(word in question_lower for word in ['набір маси', 'набрати масу']):
            user_params['goal'] = 'набір маси'
        elif any(word in question_lower for word in ['схуднення', 'схуднути']):
            user_params['goal'] = 'схуднення'
        elif any(word in question_lower for word in ['витривалість', 'виносливість']):
            user_params['goal'] = 'витривалість'
        elif any(word in question_lower for word in ['підтримка форми', 'форма']):
            user_params['goal'] = 'підтримка форми'

    elif any(word in question_lower for word in ['продукт', 'їжа', 'харчування', 'їсти', 'кушати', 'білки', 'жири', 'вуглеводи', 'бжв']):
        domain = "nutrition"

    logging.debug(f"Question: {question}, Domain: {domain}, Muscle Group: {muscle_group}, User Params: {user_params}")

    response = ask_coach(question, domain=domain, muscle_group=muscle_group, user_params=user_params)
    
    if "щелеп" in response['message']['content'].lower():
        logging.warning("⚠️ Підозріла відповідь — можливо, варто уточнити інструкцію.")
    
    return jsonify({"answer": response['message']['content']})

@app.route('/ask_nutrition', methods=['POST'])
@login_required
def ask_nutrition():
    question = request.json.get('question')
    if not question:
        return jsonify({"error": "No question provided"}), 400
    
    response = ask_coach(question, domain="nutrition")
    
    if "щелеп" in response['message']['content'].lower():
        logging.warning("⚠️ Підозріла відповідь — можливо, варто уточнити інструкцію.")
    
    return jsonify({"answer": response['message']['content']})

@app.route('/technique_analysis')
@login_required
def technique_analysis():
    lang = session.get('lang', 'ua')
    return render_template('technique_analysis.html', lang=lang)

@app.route('/progress_forecast')
@login_required
def progress_forecast():
    lang = session.get('lang', 'ua')
    return render_template('progress_forecast.html', lang=lang)

@app.route('/muscle_map')
@login_required
def muscle_map():
    lang = session.get('lang', 'ua')
    return render_template('muscle_map.html', lang=lang)

@app.route('/fitness_test')
@login_required
def fitness_test():
    lang = session.get('lang', 'ua')
    return render_template('fitness_test.html', lang=lang)

@app.route('/warmup_trainer')
@login_required
def warmup_trainer():
    lang = session.get('lang', 'ua')
    return render_template('warmup_trainer.html', lang=lang)

@app.route('/training_planner')
@login_required
def training_planner():
    lang = session.get('lang', 'ua')
    return render_template('training_planner.html', lang=lang)

@app.route('/recovery_plan')
@login_required
def recovery_plan():
    lang = session.get('lang', 'ua')
    return render_template('recovery_plan.html', lang=lang)

@app.route('/training_programs')
@login_required
def training_programs():
    lang = session.get('lang', 'ua')
    return render_template('training_programs.html', lang=lang)

@app.route('/virtual_run')
@login_required
def virtual_run():
    lang = session.get('lang', 'ua')
    logging.debug(f"Rendering virtual_run.html with lang={lang}")
    try:
        return render_template('virtual_run.html', lang=lang)
    except Exception as e:
        logging.error(f"Error rendering virtual_run: {str(e)}")
        flash('Помилка при завантаженні сторінки пробіжки', 'error')
        return redirect(url_for('welcome'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('lang', None)
    return redirect(url_for('index'))

@app.route('/set_language/<lang>')
def set_language(lang):
    session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/download_program/<program>')
@login_required
def download_program(program):
    if program in ['basic_bodybuilding', 'advanced_bodybuilding', 'intense_bodybuilding']:
        file_extension = '.xlsx'
    else:
        file_extension = '.xlsm'
    
    file_name = f"{program}{file_extension}"
    file_path = os.path.join('static', 'programs', file_name)
    
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        flash('Файл програми не знайдено', 'error')
        return redirect(url_for('training_programs'))
    except Exception as e:
        flash(f'Помилка при завантаженні файлу: {str(e)}', 'error')
        return redirect(url_for('training_programs'))

@app.route('/static/videos/<path:filename>')
def serve_video(filename):
    return send_from_directory('static/videos', filename)

# Проксі для FatSecret API з підтримкою OAuth 1.0a
@app.route('/fatsecret', methods=['GET'])
@login_required
def fatsecret_proxy():
    search_expression = request.args.get('q')
    if not search_expression:
        return jsonify({'error': 'Missing search query'}), 400

    # Отримання ключів із змінних оточення або стандартних значень
    consumer_key = os.getenv('FATSECRET_CONSUMER_KEY', 'a660a07b61064124918c8f01e89a0f2b')
    consumer_secret = os.getenv('FATSECRET_CONSUMER_SECRET', '7d235c214ae04dd696b347cb104542bb')
    api_url = 'https://platform.fatsecret.com/rest/server.api'

    # Параметри запиту
    params = {
        'method': 'foods.search',
        'format': 'json',
        'search_expression': search_expression,
        'max_results': 10
    }

    # Ініціалізація OAuth 1.0a клієнта
    client = Client(
        client_key=consumer_key,
        client_secret=consumer_secret,
        signature_method='HMAC-SHA1',
        signature_type=SIGNATURE_TYPE_AUTH_HEADER
    )

    try:
        # Генерація підпису та URI
        uri, headers, body = client.sign(api_url, http_method='GET', body='', headers={}, realm='', urlencode_params=True)
        logging.debug(f"Request URI: {uri}")
        logging.debug(f"Request Headers: {headers}")
        logging.debug(f"Request Params: {params}")

        # Відправка запиту до FatSecret API
        response = requests.get(uri, headers=headers, params=params)
        response.raise_for_status()  # Викликає помилку, якщо статус не 200

        # Перевірка відповіді
        data = response.json()
        logging.debug(f"FatSecret Response: {data}")
        if 'error' in data:
            logging.error(f"FatSecret API error: {data['error']}")
            return jsonify({'error': 'FatSecret API returned an error', 'details': data.get('error')}), 500

        return jsonify(data)

    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error: {str(e)}, Status Code: {e.response.status_code}, Response: {e.response.text if e.response else 'No response'}")
        if e.response.status_code == 401:  # Unauthorized (можливо, проблема з IP або ключами)
            logging.warning("Possible IP restriction or invalid API keys. Returning fallback data.")
            return jsonify({
                'foods': {
                    'food': [
                        {'food_name': 'Test Food', 'food_id': '123', 'serving': {'calories': '100'}}
                    ]
                }
            })
        return jsonify({'error': 'Failed to fetch data from FatSecret API', 'details': str(e)}), 500
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Exception: {str(e)}")
        return jsonify({'error': 'Network error with FatSecret API', 'details': str(e)}), 500
    except ValueError as e:
        logging.error(f"JSON Decode Error: {str(e)}, Response: {response.text if 'response' in locals() else 'No response'}")
        return jsonify({'error': 'Invalid response from FatSecret API', 'details': str(e)}), 500
    except Exception as e:
        logging.error(f"Unexpected Error: {str(e)}, Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Unexpected server error', 'details': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)