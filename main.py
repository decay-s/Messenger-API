from flask import Flask, request, jsonify, send_file
import sqlite3
import json
import uuid
import os
import logging
from typing import Optional, Dict, Any, Tuple
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['DATABASE'] = 'messenger.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_FILE_SIZE'] = 1000 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

app.config['RATE_LIMIT_REQUESTS'] = 600
app.config['RATE_LIMIT_WINDOW'] = 60

request_counts = {}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

JSONResponse = Tuple[Dict[str, Any], int]

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr

        current_time = time.time()

        if client_ip not in request_counts:
            request_counts[client_ip] = {'count': 0, 'start_time': current_time}

        if current_time - request_counts[client_ip]['start_time'] > app.config['RATE_LIMIT_WINDOW']:
            request_counts[client_ip] = {'count': 0, 'start_time': current_time}

        request_counts[client_ip]['count'] += 1

        if request_counts[client_ip]['count'] > app.config['RATE_LIMIT_REQUESTS']:
            retry_after = int(app.config['RATE_LIMIT_WINDOW'] - (current_time - request_counts[client_ip]['start_time']))
            return jsonify({
                'ok': False,
                'error_code': 429,
                'description': 'Too Many Requests',
                'retry_after': retry_after
            }), 429

        return f(*args, **kwargs)
    return decorated_function

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    if not os.path.exists(app.config['DATABASE']):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT,
                phone_number TEXT,
                is_bot BOOLEAN DEFAULT FALSE,
                token TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_online BOOLEAN DEFAULT FALSE
            )
        ''')

        cursor.execute('''
            CREATE TABLE user_settings (
                user_id INTEGER PRIMARY KEY,
                privacy_mode TEXT DEFAULT 'everyone',
                show_online_status BOOLEAN DEFAULT TRUE,
                allow_group_invites BOOLEAN DEFAULT TRUE,
                language TEXT DEFAULT 'en',
                theme TEXT DEFAULT 'light',
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL CHECK(type IN ('private', 'group', 'channel', 'supergroup')),
                title TEXT,
                username TEXT UNIQUE,
                description TEXT,
                invite_link TEXT UNIQUE,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_public BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE chat_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                status TEXT DEFAULT 'member' CHECK(status IN (
                    'creator', 'administrator', 'member', 'restricted', 'left', 'kicked'
                )),
                custom_title TEXT,
                until_date TIMESTAMP NULL,
                can_send_messages BOOLEAN DEFAULT TRUE,
                can_send_media_messages BOOLEAN DEFAULT TRUE,
                can_send_polls BOOLEAN DEFAULT TRUE,
                can_send_other_messages BOOLEAN DEFAULT TRUE,
                can_add_web_page_previews BOOLEAN DEFAULT TRUE,
                can_change_info BOOLEAN DEFAULT FALSE,
                can_invite_users BOOLEAN DEFAULT FALSE,
                can_pin_messages BOOLEAN DEFAULT FALSE,
                joined_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(chat_id, user_id),
                FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                from_user_id INTEGER NOT NULL,
                text TEXT,
                message_id INTEGER NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                edit_date TIMESTAMP NULL,
                message_type TEXT DEFAULT 'text' CHECK(message_type IN (
                    'text', 'photo', 'document', 'video', 'audio', 'voice',
                    'sticker', 'animation', 'location', 'contact', 'poll', 'dice'
                )),
                caption TEXT,
                file_id TEXT,
                file_size INTEGER,
                mime_type TEXT,
                duration INTEGER,
                width INTEGER,
                height INTEGER,
                reply_to_message_id INTEGER,
                is_pinned BOOLEAN DEFAULT FALSE,
                views INTEGER DEFAULT 0,
                UNIQUE(chat_id, message_id),
                FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
                FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (reply_to_message_id) REFERENCES messages (id) ON DELETE SET NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE message_read_status (
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (message_id, user_id),
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                contact_user_id INTEGER NOT NULL,
                first_name TEXT,
                last_name TEXT,
                phone_number TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, contact_user_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (contact_user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE blocked_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                blocked_user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, blocked_user_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (blocked_user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                emoji TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(message_id, user_id),
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE user_profile_photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                file_id TEXT NOT NULL,
                file_size INTEGER,
                width INTEGER,
                height INTEGER,
                is_current BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE chat_permissions (
                chat_id INTEGER PRIMARY KEY,
                can_send_messages BOOLEAN DEFAULT TRUE,
                can_send_media_messages BOOLEAN DEFAULT TRUE,
                can_send_polls BOOLEAN DEFAULT TRUE,
                can_send_other_messages BOOLEAN DEFAULT TRUE,
                can_add_web_page_previews BOOLEAN DEFAULT TRUE,
                can_change_info BOOLEAN DEFAULT FALSE,
                can_invite_users BOOLEAN DEFAULT FALSE,
                can_pin_messages BOOLEAN DEFAULT FALSE,
                can_manage_chat BOOLEAN DEFAULT FALSE,
                can_manage_video_chats BOOLEAN DEFAULT FALSE,
                can_restrict_members BOOLEAN DEFAULT FALSE,
                can_promote_members BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE video_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                title TEXT,
                created_by INTEGER NOT NULL,
                start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_date TIMESTAMP NULL,
                participant_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE video_chat_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                join_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                leave_time TIMESTAMP NULL,
                is_muted BOOLEAN DEFAULT FALSE,
                is_video_enabled BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (video_chat_id) REFERENCES video_chats (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE pinned_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                pinned_by INTEGER NOT NULL,
                pinned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(chat_id, message_id),
                FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE,
                FOREIGN KEY (pinned_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE message_stats (
                message_id INTEGER PRIMARY KEY,
                view_count INTEGER DEFAULT 0,
                forward_count INTEGER DEFAULT 0,
                reply_count INTEGER DEFAULT 0,
                reaction_count INTEGER DEFAULT 0,
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE user_stats (
                user_id INTEGER PRIMARY KEY,
                message_count INTEGER DEFAULT 0,
                media_count INTEGER DEFAULT 0,
                group_count INTEGER DEFAULT 0,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE message_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                view_count INTEGER DEFAULT 1,
                UNIQUE(message_id, user_id),
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Database created successfully!")

def authenticate_token(token: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE token = ?',
        (token,)
    ).fetchone()

    if user:
        conn.execute(
            'UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()

    conn.close()
    return user

def validate_json(schema: Dict[str, Any]):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'ok': False,
                    'error_code': 400,
                    'description': 'Request must be JSON'
                }), 400

            data = request.get_json()
            if data is None:
                return jsonify({
                    'ok': False,
                    'error_code': 400,
                    'description': 'Invalid JSON format'
                }), 400

            errors = {}
            for field, field_type in schema.items():
                if field not in data:
                    errors[field] = 'This field is required'
                elif not isinstance(data[field], field_type):
                    errors[field] = f'Must be of type {field_type.__name__}'

            if errors:
                return jsonify({
                    'ok': False,
                    'error_code': 400,
                    'description': 'Invalid input',
                    'errors': errors
                }), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/bot<token>/<method>', methods=['GET', 'POST'])
@rate_limit
def api_method(token: str, method: str) -> JSONResponse:
    method_handlers = {
        'getMe': get_me,
        'getMessages': get_messages,
        'getChat': get_chat,
        'getRecentChats': get_recent_chats,
        'getMyChats': get_my_chats,
        'getPrivateChats': get_private_chats,
        'getGroupChats': get_group_chats,
        'getSupergroupChats': get_supergroup_chats,
        'getChannelChats': get_channel_chats,
        'getUpdates': get_updates,
        'getContacts': get_contacts,
        'addContact': add_contact,
        'sendMessage': send_message,
        'editMessageText': edit_message_text,
        'deleteMessage': delete_message,
        'editMessageCaption': edit_message_caption,
        'joinChat': join_chat,
        'leaveChat': leave_chat,
        'deleteChat': delete_chat,
        'createChat': create_chat,
        'banChatMember': ban_chat_member,
        'unbanChatMember': unban_chat_member,
        'sendChatAction': send_chat_action,
        'sendNotification': send_notification,
        'sendDocument': send_document,
        'fetchMessages': fetch_messages,
        'logout': logout,
        'close': close,
        'connect': connect,
        'disconnect': disconnect,
        'refresh': refresh,
        'update': update,
        'upgrade': upgrade,
        'getUserProfilePhotos': get_user_profile_photos,
        'setChatPermissions': set_chat_permissions,
        'getChatMembersCount': get_chat_members_count,
        'getChatMember': get_chat_member,
        'setChatPhoto': set_chat_photo,
        'deleteChatPhoto': delete_chat_photo,
        'setChatTitle': set_chat_title,
        'setChatDescription': set_chat_description,
        'pinChatMessage': pin_chat_message,
        'unpinChatMessage': unpin_chat_message,
        'unpinAllChatMessages': unpin_all_chat_messages,
        'answerCallbackQuery': answer_callback_query,
        'setMessageReaction': set_message_reaction,
        'getMessageReactions': get_message_reactions,
        'forwardMessage': forward_message,
        'copyMessage': copy_message,
        'sendPhoto': send_photo,
        'sendAudio': send_audio,
        'sendVideo': send_video,
        'sendVoice': send_voice,
        'sendAnimation': send_animation,
        'sendSticker': send_sticker,
        'sendLocation': send_location,
        'sendContact': send_contact,
        'sendPoll': send_poll,
        'sendDice': send_dice,
        'getUser': get_user,
        'blockUser': block_user,
        'unblockUser': unblock_user,
        'getBlockedUsers': get_blocked_users,
        'searchMessages': search_messages,
        'readMessage': read_message,
        'getUnreadCount': get_unread_count,
        'setUserProfilePhoto': set_user_profile_photo,
        'getUserProfilePhotos': get_user_profile_photos,
        'setChatPermissions': set_chat_permissions,
        'startVideoChat': start_video_chat,
        'joinVideoChat': join_video_chat,
        'getMessageStatistics': get_message_statistics,
        'getUserStatistics': get_user_statistics,
        'setMemberCustomTitle': set_member_custom_title,
        'viewMessage': view_message,
        'getMessageViewsCount': get_message_views_count,
        'getMessageViewers': get_message_viewers,
        'getUserMessageViews': get_user_message_views,
        'getChatActivityStats': get_chat_activity_stats,
    }

    if method in ['signin', 'signup']:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Method not found. Use /api/bot/signin or /api/bot/signup instead'
        }), 404

    handler = method_handlers.get(method)
    if not handler:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Method not found'
        }), 404

    user = authenticate_token(token)
    if not user:
        return jsonify({
            'ok': False,
            'error_code': 401,
            'description': 'Unauthorized: Invalid token'
        }), 401

    return handler(user)

@app.route('/api/bot/signin', methods=['POST'])
@rate_limit
def api_signin() -> JSONResponse:
    return sign_in(request)

@app.route('/api/bot/signup', methods=['POST'])
@rate_limit
def api_signup() -> JSONResponse:
    return sign_up(request)

@rate_limit
@validate_json({'username': str, 'password': str})
def sign_in(request) -> JSONResponse:
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()

    if not user or not check_password_hash(user['password_hash'], password):
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 401,
            'description': 'Invalid username or password'
        }), 401

    if not user['token']:
        new_token = str(uuid.uuid4())
        conn.execute(
            'UPDATE users SET token = ? WHERE id = ?',
            (new_token, user['id'])
        )
        conn.commit()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user['id'],)
        ).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'user': {
                'id': user['id'],
                'username': user['username'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'phone_number': user['phone_number'],
                'is_bot': bool(user['is_bot']),
                'is_online': bool(user['is_online']),
                'last_seen': user['last_seen']
            },
            'token': user['token']
        }
    })

@rate_limit
@validate_json({
    'username': str,
    'password': str,
    'first_name': str,
    'last_name': str,
    'phone_number': str
})
def sign_up(request) -> JSONResponse:
    data = request.get_json()
    username = data['username']
    password = data['password']
    first_name = data['first_name']
    last_name = data.get('last_name', '')
    phone_number = data['phone_number']

    conn = get_db_connection()

    existing_user = conn.execute(
        'SELECT id FROM users WHERE username = ? OR phone_number = ?',
        (username, phone_number)
    ).fetchone()

    if existing_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'Username or phone number already exists'
        }), 409

    password_hash = generate_password_hash(password)
    token = str(uuid.uuid4())

    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO users
            (username, password_hash, first_name, last_name, phone_number, token)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (username, password_hash, first_name, last_name, phone_number, token)
        )
        user_id = cursor.lastrowid

        cursor.execute(
            'INSERT INTO user_settings (user_id) VALUES (?)',
            (user_id,)
        )

        cursor.execute(
            'INSERT INTO user_stats (user_id) VALUES (?)',
            (user_id,)
        )

        conn.commit()

        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'phone_number': user['phone_number'],
                    'is_bot': bool(user['is_bot']),
                    'is_online': bool(user['is_online']),
                    'last_seen': user['last_seen']
                },
                'token': user['token']
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_me(user: sqlite3.Row) -> JSONResponse:
    return jsonify({
        'ok': True,
        'result': {
            'id': user['id'],
            'username': user['username'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'phone_number': user['phone_number'],
            'is_bot': bool(user['is_bot']),
            'is_online': bool(user['is_online']),
            'last_seen': user['last_seen']
        }
    })

def get_messages(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    messages = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.date DESC
        LIMIT ? OFFSET ?
    ''', (chat_id, limit, offset)).fetchall()

    result = []
    for msg in messages:
        message_data = {
            'message_id': msg['message_id'],
            'from': {
                'id': msg['from_user_id'],
                'username': msg['username'],
                'first_name': msg['first_name'],
                'last_name': msg['last_name']
            },
            'chat': {'id': msg['chat_id']},
            'date': msg['date'],
            'text': msg['text'],
            'message_type': msg['message_type'],
            'caption': msg['caption'],
            'file_id': msg['file_id'],
            'file_size': msg['file_size'],
            'mime_type': msg['mime_type'],
            'duration': msg['duration'],
            'width': msg['width'],
            'height': msg['height'],
            'reply_to_message_id': msg['reply_to_message_id'],
            'is_pinned': bool(msg['is_pinned']),
            'views': msg['views']
        }
        result.append(message_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def get_chat(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    members_count = conn.execute(
        'SELECT COUNT(*) as count FROM chat_members WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()['count']

    chat_data = {
        'id': chat['id'],
        'type': chat['type'],
        'title': chat['title'],
        'username': chat['username'],
        'description': chat['description'],
        'invite_link': chat['invite_link'],
        'is_public': bool(chat['is_public']),
        'members_count': members_count,
        'created_at': chat['created_at']
    }

    conn.close()
    return jsonify({'ok': True, 'result': chat_data})

def get_my_chats(user: sqlite3.Row) -> JSONResponse:
    """Get all chats where user is a member and has sent messages"""
    conn = get_db_connection()

    try:
        chats = conn.execute('''
            SELECT DISTINCT c.*,
                   (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id) as message_count,
                   (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id = c.id) as members_count,
                   (SELECT MAX(date) FROM messages m WHERE m.chat_id = c.id) as last_activity
            FROM chats c
            JOIN chat_members cm ON c.id = cm.chat_id
            JOIN messages m ON c.id = m.chat_id
            WHERE cm.user_id = ? AND m.from_user_id = ?
            ORDER BY last_activity DESC
        ''', (user['id'], user['id'])).fetchall()

        result = []
        for chat in chats:
            chat_data = {
                'id': chat['id'],
                'type': chat['type'],
                'title': chat['title'],
                'username': chat['username'],
                'description': chat['description'],
                'invite_link': chat['invite_link'],
                'is_public': bool(chat['is_public']),
                'created_at': chat['created_at'],
                'message_count': chat['message_count'],
                'members_count': chat['members_count'],
                'last_activity': chat['last_activity']
            }
            result.append(chat_data)

        return jsonify({'ok': True, 'result': result})

    except sqlite3.Error as e:
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500
    finally:
        conn.close()

def get_private_chats(user: sqlite3.Row) -> JSONResponse:
    """Get all private chats where user has sent messages"""
    conn = get_db_connection()

    try:
        chats = conn.execute('''
            SELECT DISTINCT c.*,
                   u.username as partner_username,
                   u.first_name as partner_first_name,
                   u.last_name as partner_last_name,
                   (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id) as message_count,
                   (SELECT MAX(date) FROM messages m WHERE m.chat_id = c.id) as last_activity
            FROM chats c
            JOIN chat_members cm ON c.id = cm.chat_id
            JOIN messages m ON c.id = m.chat_id
            JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id != ?
            JOIN users u ON cm2.user_id = u.id
            WHERE c.type = 'private'
            AND cm.user_id = ?
            AND m.from_user_id = ?
            ORDER BY last_activity DESC
        ''', (user['id'], user['id'], user['id'])).fetchall()

        result = []
        for chat in chats:
            chat_data = {
                'id': chat['id'],
                'type': chat['type'],
                'title': chat['title'] or f"{chat['partner_first_name']} {chat['partner_last_name']}",
                'partner': {
                    'id': chat['partner_username'],
                    'username': chat['partner_username'],
                    'first_name': chat['partner_first_name'],
                    'last_name': chat['partner_last_name']
                },
                'message_count': chat['message_count'],
                'last_activity': chat['last_activity']
            }
            result.append(chat_data)

        return jsonify({'ok': True, 'result': result})

    except sqlite3.Error as e:
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500
    finally:
        conn.close()

def get_group_chats(user: sqlite3.Row) -> JSONResponse:
    """Get all group chats where user is a member and has sent messages"""
    return get_chats_by_type(user, 'group')

def get_supergroup_chats(user: sqlite3.Row) -> JSONResponse:
    """Get all supergroup chats where user is a member and has sent messages"""
    return get_chats_by_type(user, 'supergroup')

def get_channel_chats(user: sqlite3.Row) -> JSONResponse:
    """Get all channel chats where user is a member and has sent messages"""
    return get_chats_by_type(user, 'channel')

def get_chats_by_type(user: sqlite3.Row, chat_type: str) -> JSONResponse:
    """Helper function to get chats by specific type"""
    conn = get_db_connection()

    try:
        chats = conn.execute('''
            SELECT DISTINCT c.*,
                   (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id) as message_count,
                   (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id = c.id) as members_count,
                   (SELECT MAX(date) FROM messages m WHERE m.chat_id = c.id) as last_activity
            FROM chats c
            JOIN chat_members cm ON c.id = cm.chat_id
            JOIN messages m ON c.id = m.chat_id
            WHERE c.type = ?
            AND cm.user_id = ?
            AND m.from_user_id = ?
            ORDER BY last_activity DESC
        ''', (chat_type, user['id'], user['id'])).fetchall()

        result = []
        for chat in chats:
            chat_data = {
                'id': chat['id'],
                'type': chat['type'],
                'title': chat['title'],
                'username': chat['username'],
                'description': chat['description'],
                'invite_link': chat['invite_link'],
                'is_public': bool(chat['is_public']),
                'created_at': chat['created_at'],
                'message_count': chat['message_count'],
                'members_count': chat['members_count'],
                'last_activity': chat['last_activity']
            }
            result.append(chat_data)

        return jsonify({'ok': True, 'result': result})

    except sqlite3.Error as e:
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500
    finally:
        conn.close()

def get_recent_chats(user: sqlite3.Row) -> JSONResponse:
    """Get recent chats with activity"""
    limit = request.args.get('limit', 20, type=int)

    conn = get_db_connection()

    try:
        chats = conn.execute('''
            SELECT c.*,
                   MAX(m.date) as last_activity,
                   (SELECT COUNT(*) FROM messages m2 WHERE m2.chat_id = c.id) as message_count,
                   (SELECT text FROM messages m3 WHERE m3.chat_id = c.id ORDER BY m3.date DESC LIMIT 1) as last_message
            FROM chats c
            JOIN chat_members cm ON c.id = cm.chat_id
            JOIN messages m ON c.id = m.chat_id
            WHERE cm.user_id = ?
            GROUP BY c.id
            ORDER BY last_activity DESC
            LIMIT ?
        ''', (user['id'], limit)).fetchall()

        result = []
        for chat in chats:
            chat_data = {
                'id': chat['id'],
                'type': chat['type'],
                'title': chat['title'],
                'username': chat['username'],
                'last_activity': chat['last_activity'],
                'message_count': chat['message_count'],
                'last_message': chat['last_message']
            }
            result.append(chat_data)

        return jsonify({'ok': True, 'result': result})

    except sqlite3.Error as e:
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500
    finally:
        conn.close()

def get_updates(user: sqlite3.Row) -> JSONResponse:
    offset = request.args.get('offset', 0, type=int)
    limit = request.args.get('limit', 100, type=int)
    timeout = request.args.get('timeout', 30, type=int)

    conn = get_db_connection()

    updates = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name, c.type as chat_type, c.title as chat_title
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        JOIN chats c ON m.chat_id = c.id
        JOIN chat_members cm ON m.chat_id = cm.chat_id AND cm.user_id = ?
        WHERE m.id > ?
        ORDER BY m.date ASC
        LIMIT ?
    ''', (user['id'], offset, limit)).fetchall()

    result = []
    for msg in updates:
        update_data = {
            'update_id': msg['id'],
            'message': {
                'message_id': msg['message_id'],
                'from': {
                    'id': msg['from_user_id'],
                    'username': msg['username'],
                    'first_name': msg['first_name'],
                    'last_name': msg['last_name']
                },
                'chat': {
                    'id': msg['chat_id'],
                    'type': msg['chat_type'],
                    'title': msg['chat_title']
                },
                'date': msg['date'],
                'text': msg['text'],
                'message_type': msg['message_type'],
                'caption': msg['caption'],
                'file_id': msg['file_id']
            }
        }
        result.append(update_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def get_contacts(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()

    contacts = conn.execute('''
        SELECT u.id, u.username, u.first_name, u.last_name, u.phone_number, u.is_online, u.last_seen
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ?
        ORDER BY u.first_name, u.last_name
    ''', (user['id'],)).fetchall()

    result = []
    for contact in contacts:
        contact_data = {
            'id': contact['id'],
            'username': contact['username'],
            'first_name': contact['first_name'],
            'last_name': contact['last_name'],
            'phone_number': contact['phone_number'],
            'is_online': bool(contact['is_online']),
            'last_seen': contact['last_seen']
        }
        result.append(contact_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

@validate_json({'user_id': int, 'first_name': str, 'last_name': str, 'phone_number': str})
def add_contact(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    contact_user_id = data['user_id']
    first_name = data['first_name']
    last_name = data['last_name']
    phone_number = data['phone_number']

    if contact_user_id == user['id']:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Cannot add yourself as contact'
        }), 400

    conn = get_db_connection()

    contact_user = conn.execute(
        'SELECT id FROM users WHERE id = ?',
        (contact_user_id,)
    ).fetchone()

    if not contact_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User not found'
        }), 404

    existing_contact = conn.execute(
        'SELECT id FROM contacts WHERE user_id = ? AND contact_user_id = ?',
        (user['id'], contact_user_id)
    ).fetchone()

    if existing_contact:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'Contact already exists'
        }), 409

    try:
        conn.execute(
            '''INSERT INTO contacts
            (user_id, contact_user_id, first_name, last_name, phone_number)
            VALUES (?, ?, ?, ?, ?)''',
            (user['id'], contact_user_id, first_name, last_name, phone_number)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Contact added successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'text': str})
def send_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    text = data['text']
    reply_to_message_id = data.get('reply_to_message_id')

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    if reply_to_message_id:
        replied_message = conn.execute(
            'SELECT id FROM messages WHERE chat_id = ? AND message_id = ?',
            (chat_id, reply_to_message_id)
        ).fetchone()
        if not replied_message:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 404,
                'description': 'Replied message not found'
            }), 404

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, text, message_id, reply_to_message_id)
            VALUES (?, ?, ?, ?, ?)''',
            (chat_id, user['id'], text, new_message_id, reply_to_message_id)
        )

        message_id = cursor.lastrowid

        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'text': message['text'],
            'reply_to_message_id': message['reply_to_message_id']
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'message_id': int, 'text': str})
def edit_message_text(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']
    text = data['text']

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ? AND from_user_id = ?',
        (chat_id, message_id, user['id'])
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found or you are not the author'
        }), 404

    try:
        conn.execute(
            'UPDATE messages SET text = ?, edit_date = CURRENT_TIMESTAMP WHERE id = ?',
            (text, message['id'])
        )
        conn.commit()

        updated_message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message['id'],)).fetchone()

        conn.close()

        message_data = {
            'message_id': updated_message['message_id'],
            'from': {
                'id': updated_message['from_user_id'],
                'username': updated_message['username'],
                'first_name': updated_message['first_name'],
                'last_name': updated_message['last_name']
            },
            'chat': {'id': chat_id},
            'date': updated_message['date'],
            'edit_date': updated_message['edit_date'],
            'text': updated_message['text']
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'message_id': int})
def delete_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    is_admin = conn.execute('''
        SELECT 1 FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if message['from_user_id'] != user['id'] and not is_admin:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You can only delete your own messages'
        }), 403

    try:
        conn.execute(
            'DELETE FROM messages WHERE id = ?',
            (message['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Message deleted successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'message_id': int, 'caption': str})
def edit_message_caption(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']
    caption = data['caption']

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ? AND from_user_id = ?',
        (chat_id, message_id, user['id'])
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found or you are not the author'
        }), 404

    if message['message_type'] == 'text':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Text messages do not have captions'
        }), 400

    try:
        conn.execute(
            'UPDATE messages SET caption = ?, edit_date = CURRENT_TIMESTAMP WHERE id = ?',
            (caption, message['id'])
        )
        conn.commit()

        updated_message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message['id'],)).fetchone()

        conn.close()

        message_data = {
            'message_id': updated_message['message_id'],
            'from': {
                'id': updated_message['from_user_id'],
                'username': updated_message['username'],
                'first_name': updated_message['first_name'],
                'last_name': updated_message['last_name']
            },
            'chat': {'id': chat_id},
            'date': updated_message['date'],
            'edit_date': updated_message['edit_date'],
            'message_type': updated_message['message_type'],
            'caption': updated_message['caption'],
            'file_id': updated_message['file_id']
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int})
def join_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    existing_member = conn.execute(
        'SELECT id FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if existing_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'Already a member of this chat'
        }), 409

    try:
        conn.execute(
            'INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)',
            (chat_id, user['id'])
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Joined chat successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int})
def leave_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    member = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Not a member of this chat'
        }), 404

    if member['status'] == 'creator':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Creator cannot leave the chat. Transfer ownership first.'
        }), 403

    try:
        conn.execute(
            'DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?',
            (chat_id, user['id'])
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Left chat successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int})
def delete_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    member = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not member or member['status'] != 'creator':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Only the creator can delete the chat'
        }), 403

    try:
        conn.execute('DELETE FROM chats WHERE id = ?', (chat_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat deleted successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({
    'type': str,
    'title': str,
    'username': str,
    'description': str,
    'is_public': bool
})
def create_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_type = data['type']
    title = data['title']
    username = data.get('username')
    description = data.get('description', '')
    is_public = data['is_public']

    if chat_type not in ['private', 'group', 'channel', 'supergroup']:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid chat type. Must be one of: private, group, channel, supergroup'
        }), 400

    if is_public and not username:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Public chats must have a username'
        }), 400

    if not is_public and username:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Private chats cannot have a username'
        }), 400

    conn = get_db_connection()

    if username:
        existing_chat = conn.execute(
            'SELECT id FROM chats WHERE username = ?',
            (username,)
        ).fetchone()
        if existing_chat:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 409,
                'description': 'Username already taken'
            }), 409

    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO chats
            (type, title, username, description, created_by, is_public)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (chat_type, title, username, description, user['id'], is_public)
        )
        chat_id = cursor.lastrowid

        invite_link = f"https://t.me/{username}"

        cursor.execute(
            'UPDATE chats SET invite_link = ? WHERE id = ?',
            (invite_link, chat_id)
        )

        cursor.execute(
            '''INSERT INTO chat_members
            (chat_id, user_id, status)
            VALUES (?, ?, 'creator')''',
            (chat_id, user['id'])
        )

        conn.commit()

        chat = conn.execute(
            'SELECT * FROM chats WHERE id = ?',
            (chat_id,)
        ).fetchone()

        conn.close()

        chat_data = {
            'id': chat['id'],
            'type': chat['type'],
            'title': chat['title'],
            'username': chat['username'],
            'description': chat['description'],
            'invite_link': chat['invite_link'],
            'is_public': bool(chat['is_public']),
            'created_at': chat['created_at']
        }

        return jsonify({'ok': True, 'result': chat_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'user_id': int})
def ban_chat_member(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    user_id_to_ban = data['user_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to ban members'
        }), 403

    target_user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user_id_to_ban)
    ).fetchone()

    if not target_user_status:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not a member of this chat'
        }), 404

    if target_user_status['status'] == 'creator':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Cannot ban the chat creator'
        }), 403

    if user_status['status'] == 'administrator' and target_user_status['status'] == 'administrator':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Administrators cannot ban other administrators'
        }), 403

    try:
        conn.execute(
            'UPDATE chat_members SET status = "kicked" WHERE chat_id = ? AND user_id = ?',
            (chat_id, user_id_to_ban)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'User banned successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'user_id': int})
def unban_chat_member(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    user_id_to_unban = data['user_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to unban members'
        }), 403

    target_user = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user_id_to_unban)
    ).fetchone()

    if not target_user or target_user['status'] != 'kicked':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not banned from this chat'
        }), 404

    try:
        conn.execute(
            'UPDATE chat_members SET status = "member" WHERE chat_id = ? AND user_id = ?',
            (chat_id, user_id_to_unban)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'User unbanned successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'action': str})
def send_chat_action(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    action = data['action']

    valid_actions = [
        'typing', 'upload_photo', 'record_video', 'upload_video',
        'record_voice', 'upload_voice', 'upload_document', 'choose_sticker',
        'find_location', 'record_video_note', 'upload_video_note'
    ]

    if action not in valid_actions:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid action'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'success': True,
            'description': f'Chat action "{action}" sent successfully'
        }
    })

@validate_json({'user_id': int, 'message': str})
def send_notification(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    user_id = data['user_id']
    message = data['message']

    conn = get_db_connection()

    target_user = conn.execute(
        'SELECT id FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()

    if not target_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User not found'
        }), 404

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'success': True,
            'description': 'Notification sent successfully'
        }
    })

def send_document(user: sqlite3.Row) -> JSONResponse:
    if 'file' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No file provided'
        }), 400

    file = request.files['file']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if file.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No file selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type)
            VALUES (?, ?, ?, 'document', ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, file.mimetype)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'document': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'mime_type': message['mime_type']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading file: {str(e)}'
        }), 500

def fetch_messages(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    messages = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.date DESC
        LIMIT ? OFFSET ?
    ''', (chat_id, limit, offset)).fetchall()

    result = []
    for msg in messages:
        message_data = {
            'message_id': msg['message_id'],
            'from': {
                'id': msg['from_user_id'],
                'username': msg['username'],
                'first_name': msg['first_name'],
                'last_name': msg['last_name']
            },
            'chat': {'id': msg['chat_id']},
            'date': msg['date'],
            'text': msg['text'],
            'message_type': msg['message_type'],
            'caption': msg['caption'],
            'file_id': msg['file_id'],
            'file_size': msg['file_size'],
            'mime_type': msg['mime_type'],
            'duration': msg['duration'],
            'width': msg['width'],
            'height': msg['height'],
            'reply_to_message_id': msg['reply_to_message_id'],
            'is_pinned': bool(msg['is_pinned']),
            'views': msg['views']
        }
        result.append(message_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def logout(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET token = NULL, is_online = FALSE WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Logged out successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def close(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Connection closed successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def connect(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Connected successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def disconnect(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Disconnected successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def refresh(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()
    try:
        conn.execute(
            'UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
            (user['id'],)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Refreshed successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def update(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_number = data.get('phone_number')

    conn = get_db_connection()
    try:
        update_fields = []
        params = []

        if first_name:
            update_fields.append('first_name = ?')
            params.append(first_name)
        if last_name is not None:
            update_fields.append('last_name = ?')
            params.append(last_name)
        if phone_number:
            update_fields.append('phone_number = ?')
            params.append(phone_number)

        if not update_fields:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 400,
                'description': 'No fields to update'
            }), 400

        params.append(user['id'])
        query = f'UPDATE users SET {", ".join(update_fields)} WHERE id = ?'
        conn.execute(query, params)
        conn.commit()

        updated_user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user['id'],)
        ).fetchone()

        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'id': updated_user['id'],
                'username': updated_user['username'],
                'first_name': updated_user['first_name'],
                'last_name': updated_user['last_name'],
                'phone_number': updated_user['phone_number'],
                'is_bot': bool(updated_user['is_bot']),
                'is_online': bool(updated_user['is_online']),
                'last_seen': updated_user['last_seen']
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def upgrade(user: sqlite3.Row) -> JSONResponse:
    return jsonify({
        'ok': True,
        'result': {
            'success': True,
            'description': 'Upgrade functionality not implemented yet'
        }
    })

def get_user_profile_photos(user: sqlite3.Row) -> JSONResponse:
    target_user_id = request.args.get('user_id', type=int)
    offset = request.args.get('offset', 0, type=int)
    limit = request.args.get('limit', 100, type=int)

    if not target_user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'user_id parameter is required'
        }), 400

    conn = get_db_connection()

    photos = conn.execute('''
        SELECT * FROM user_profile_photos
        WHERE user_id = ? AND is_current = TRUE
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    ''', (target_user_id, limit, offset)).fetchall()

    result = []
    for photo in photos:
        photo_data = {
            'file_id': photo['file_id'],
            'file_size': photo['file_size'],
            'width': photo['width'],
            'height': photo['height'],
            'created_at': photo['created_at']
        }
        result.append(photo_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

@validate_json({'chat_id': int, 'permissions': dict})
def set_chat_permissions(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    permissions = data['permissions']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to set chat permissions'
        }), 403

    try:
        existing_permissions = conn.execute(
            'SELECT * FROM chat_permissions WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()

        if existing_permissions:
            update_fields = []
            params = []
            for key, value in permissions.items():
                if key in [
                    'can_send_messages', 'can_send_media_messages', 'can_send_polls',
                    'can_send_other_messages', 'can_add_web_page_previews',
                    'can_change_info', 'can_invite_users', 'can_pin_messages',
                    'can_manage_chat', 'can_manage_video_chats',
                    'can_restrict_members', 'can_promote_members'
                ]:
                    update_fields.append(f'{key} = ?')
                    params.append(value)

            if update_fields:
                params.append(chat_id)
                query = f'UPDATE chat_permissions SET {", ".join(update_fields)} WHERE chat_id = ?'
                conn.execute(query, params)
        else:
            conn.execute(
                '''INSERT INTO chat_permissions
                (chat_id, can_send_messages, can_send_media_messages, can_send_polls,
                 can_send_other_messages, can_add_web_page_previews, can_change_info,
                 can_invite_users, can_pin_messages, can_manage_chat, can_manage_video_chats,
                 can_restrict_members, can_promote_messages)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (chat_id,
                 permissions.get('can_send_messages', True),
                 permissions.get('can_send_media_messages', True),
                 permissions.get('can_send_polls', True),
                 permissions.get('can_send_other_messages', True),
                 permissions.get('can_add_web_page_previews', True),
                 permissions.get('can_change_info', False),
                 permissions.get('can_invite_users', False),
                 permissions.get('can_pin_messages', False),
                 permissions.get('can_manage_chat', False),
                 permissions.get('can_manage_video_chats', False),
                 permissions.get('can_restrict_members', False),
                 permissions.get('can_promote_members', False))
            )

        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat permissions updated successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_chat_members_count(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    count = conn.execute(
        'SELECT COUNT(*) as count FROM chat_members WHERE chat_id = ? AND status != "kicked"',
        (chat_id,)
    ).fetchone()['count']

    conn.close()
    return jsonify({'ok': True, 'result': count})

def get_chat_member(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)
    user_id = request.args.get('user_id', type=int)

    if not chat_id or not user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id and user_id parameters are required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    member = conn.execute('''
        SELECT cm.*, u.username, u.first_name, u.last_name
        FROM chat_members cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.chat_id = ? AND cm.user_id = ?
    ''', (chat_id, user_id)).fetchone()

    if not member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat member not found'
        }), 404

    member_data = {
        'user': {
            'id': member['user_id'],
            'username': member['username'],
            'first_name': member['first_name'],
            'last_name': member['last_name']
        },
        'status': member['status'],
        'custom_title': member['custom_title'],
        'until_date': member['until_date'],
        'can_send_messages': bool(member['can_send_messages']),
        'can_send_media_messages': bool(member['can_send_media_messages']),
        'can_send_polls': bool(member['can_send_polls']),
        'can_send_other_messages': bool(member['can_send_other_messages']),
        'can_add_web_page_previews': bool(member['can_add_web_page_previews']),
        'can_change_info': bool(member['can_change_info']),
        'can_invite_users': bool(member['can_invite_users']),
        'can_pin_messages': bool(member['can_pin_messages']),
        'joined_date': member['joined_date']
    }

    conn.close()
    return jsonify({'ok': True, 'result': member_data})

def set_chat_photo(user: sqlite3.Row) -> JSONResponse:
    if 'photo' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo provided'
        }), 400

    photo = request.files['photo']
    chat_id = request.form.get('chat_id', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if photo.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo selected'
        }), 400

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to set chat photo'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{photo.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        photo.save(file_path)

        conn.execute(
            'UPDATE chats SET photo_file_id = ? WHERE id = ?',
            (file_id, chat_id)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat photo updated successfully'
            }
        })

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading photo: {str(e)}'
        }), 500

def delete_chat_photo(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to delete chat photo'
        }), 403

    try:
        conn.execute(
            'UPDATE chats SET photo_file_id = NULL WHERE id = ?',
            (chat_id,)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat photo deleted successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'title': str})
def set_chat_title(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    title = data['title']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to set chat title'
        }), 403

    try:
        conn.execute(
            'UPDATE chats SET title = ? WHERE id = ?',
            (title, chat_id)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat title updated successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'description': str})
def set_chat_description(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    description = data['description']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to set chat description'
        }), 403

    try:
        conn.execute(
            'UPDATE chats SET description = ? WHERE id = ?',
            (description, chat_id)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Chat description updated successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'message_id': int})
def pin_chat_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to pin messages'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        conn.execute(
            'UPDATE messages SET is_pinned = TRUE WHERE id = ?',
            (message['id'],)
        )

        conn.execute(
            'INSERT INTO pinned_messages (chat_id, message_id, pinned_by) VALUES (?, ?, ?)',
            (chat_id, message_id, user['id'])
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Message pinned successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'message_id': int})
def unpin_chat_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to unpin messages'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        conn.execute(
            'UPDATE messages SET is_pinned = FALSE WHERE id = ?',
            (message['id'],)
        )

        conn.execute(
            'DELETE FROM pinned_messages WHERE chat_id = ? AND message_id = ?',
            (chat_id, message_id)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Message unpinned successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int})
def unpin_all_chat_messages(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to unpin messages'
        }), 403

    try:
        conn.execute(
            'UPDATE messages SET is_pinned = FALSE WHERE chat_id = ?',
            (chat_id,)
        )

        conn.execute(
            'DELETE FROM pinned_messages WHERE chat_id = ?',
            (chat_id,)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'All messages unpinned successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'callback_query_id': str, 'text': str, 'show_alert': bool})
def answer_callback_query(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    callback_query_id = data['callback_query_id']
    text = data['text']
    show_alert = data.get('show_alert', False)

    return jsonify({
        'ok': True,
        'result': {
            'callback_query_id': callback_query_id,
            'text': text,
            'show_alert': show_alert,
            'success': True
        }
    })

@validate_json({'chat_id': int, 'message_id': int, 'reaction': str})
def set_message_reaction(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']
    reaction = data['reaction']

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        existing_reaction = conn.execute(
            'SELECT * FROM reactions WHERE message_id = ? AND user_id = ?',
            (message['id'], user['id'])
        ).fetchone()

        if existing_reaction:
            conn.execute(
                'UPDATE reactions SET emoji = ? WHERE message_id = ? AND user_id = ?',
                (reaction, message['id'], user['id'])
            )
        else:
            conn.execute(
                'INSERT INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?)',
                (message['id'], user['id'], reaction)
            )

        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Reaction set successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_message_reactions(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)
    message_id = request.args.get('message_id', type=int)

    if not chat_id or not message_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id and message_id parameters are required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    reactions = conn.execute('''
        SELECT r.emoji, COUNT(*) as count,
               GROUP_CONCAT(u.username) as users
        FROM reactions r
        JOIN users u ON r.user_id = u.id
        WHERE r.message_id = ?
        GROUP BY r.emoji
    ''', (message['id'],)).fetchall()

    result = []
    for reaction in reactions:
        reaction_data = {
            'emoji': reaction['emoji'],
            'count': reaction['count'],
            'users': reaction['users'].split(',') if reaction['users'] else []
        }
        result.append(reaction_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

@validate_json({'chat_id': int, 'from_chat_id': int, 'message_id': int})
def forward_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    from_chat_id = data['from_chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    is_member_target = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member_target:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of the target chat'
        }), 403

    is_member_source = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (from_chat_id, user['id'])
    ).fetchone()

    if not is_member_source:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of the source chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (from_chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, text, message_type, caption,
             file_id, file_size, mime_type, duration, width, height)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, message['text'], message['message_type'],
             message['caption'], message['file_id'], message['file_size'], message['mime_type'],
             message['duration'], message['width'], message['height'])
        )

        new_message_db_id = cursor.lastrowid
        conn.commit()

        forwarded_message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (new_message_db_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': forwarded_message['message_id'],
            'from': {
                'id': forwarded_message['from_user_id'],
                'username': forwarded_message['username'],
                'first_name': forwarded_message['first_name'],
                'last_name': forwarded_message['last_name']
            },
            'chat': {'id': chat_id},
            'date': forwarded_message['date'],
            'forwarded_from': {
                'chat_id': from_chat_id,
                'message_id': message_id
            },
            'text': forwarded_message['text'],
            'message_type': forwarded_message['message_type'],
            'caption': forwarded_message['caption'],
            'file_id': forwarded_message['file_id']
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'from_chat_id': int, 'message_id': int})
def copy_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    from_chat_id = data['from_chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    is_member_target = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member_target:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of the target chat'
        }), 403

    is_member_source = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (from_chat_id, user['id'])
    ).fetchone()

    if not is_member_source:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of the source chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (from_chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, text, message_type, caption,
             file_id, file_size, mime_type, duration, width, height)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, message['text'], message['message_type'],
             message['caption'], message['file_id'], message['file_size'], message['mime_type'],
             message['duration'], message['width'], message['height'])
        )

        new_message_db_id = cursor.lastrowid
        conn.commit()

        copied_message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (new_message_db_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': copied_message['message_id'],
            'from': {
                'id': copied_message['from_user_id'],
                'username': copied_message['username'],
                'first_name': copied_message['first_name'],
                'last_name': copied_message['last_name']
            },
            'chat': {'id': chat_id},
            'date': copied_message['date'],
            'text': copied_message['text'],
            'message_type': copied_message['message_type'],
            'caption': copied_message['caption'],
            'file_id': copied_message['file_id']
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def send_photo(user: sqlite3.Row) -> JSONResponse:
    if 'photo' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo provided'
        }), 400

    photo = request.files['photo']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if photo.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{photo.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        photo.save(file_path)
        file_size = os.path.getsize(file_path)

        from PIL import Image
        img = Image.open(file_path)
        width, height = img.size

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type, width, height)
            VALUES (?, ?, ?, 'photo', ?, ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, photo.mimetype, width, height)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'photo': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'width': message['width'],
                'height': message['height']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading photo: {str(e)}'
        }), 500

def send_audio(user: sqlite3.Row) -> JSONResponse:
    if 'audio' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No audio provided'
        }), 400

    audio = request.files['audio']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')
    duration = request.form.get('duration', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if audio.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No audio selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{audio.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        audio.save(file_path)
        file_size = os.path.getsize(file_path)

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type, duration)
            VALUES (?, ?, ?, 'audio', ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, audio.mimetype, duration)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'audio': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'duration': message['duration'],
                'mime_type': message['mime_type']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading audio: {str(e)}'
        }), 500

def send_video(user: sqlite3.Row) -> JSONResponse:
    if 'video' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No video provided'
        }), 400

    video = request.files['video']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')
    duration = request.form.get('duration', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if video.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No video selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{video.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        video.save(file_path)
        file_size = os.path.getsize(file_path)

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type, duration)
            VALUES (?, ?, ?, 'video', ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, video.mimetype, duration)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'video': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'duration': message['duration'],
                'mime_type': message['mime_type']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading video: {str(e)}'
        }), 500

def send_voice(user: sqlite3.Row) -> JSONResponse:
    if 'voice' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No voice message provided'
        }), 400

    voice = request.files['voice']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')
    duration = request.form.get('duration', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if voice.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No voice message selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{voice.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        voice.save(file_path)
        file_size = os.path.getsize(file_path)

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type, duration)
            VALUES (?, ?, ?, 'voice', ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, voice.mimetype, duration)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'voice': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'duration': message['duration'],
                'mime_type': message['mime_type']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading voice message: {str(e)}'
        }), 500

def send_animation(user: sqlite3.Row) -> JSONResponse:
    if 'animation' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No animation provided'
        }), 400

    animation = request.files['animation']
    chat_id = request.form.get('chat_id', type=int)
    caption = request.form.get('caption', '')
    duration = request.form.get('duration', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if animation.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No animation selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{animation.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        animation.save(file_path)
        file_size = os.path.getsize(file_path)

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, caption, file_id, file_size, mime_type, duration)
            VALUES (?, ?, ?, 'animation', ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, caption, file_id, file_size, animation.mimetype, duration)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'caption': message['caption'],
            'animation': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'duration': message['duration'],
                'mime_type': message['mime_type']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading animation: {str(e)}'
        }), 500

def send_sticker(user: sqlite3.Row) -> JSONResponse:
    if 'sticker' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No sticker provided'
        }), 400

    sticker = request.files['sticker']
    chat_id = request.form.get('chat_id', type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id is required'
        }), 400

    if sticker.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No sticker selected'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{sticker.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        sticker.save(file_path)
        file_size = os.path.getsize(file_path)

        from PIL import Image
        img = Image.open(file_path)
        width, height = img.size

        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, file_id, file_size, mime_type, width, height)
            VALUES (?, ?, ?, 'sticker', ?, ?, ?, ?, ?)''',
            (chat_id, user['id'], new_message_id, file_id, file_size, sticker.mimetype, width, height)
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'sticker': {
                'file_id': message['file_id'],
                'file_size': message['file_size'],
                'width': message['width'],
                'height': message['height']
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading sticker: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'latitude': float, 'longitude': float})
def send_location(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    latitude = data['latitude']
    longitude = data['longitude']

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, text)
            VALUES (?, ?, ?, 'location', ?)''',
            (chat_id, user['id'], new_message_id, f"{latitude},{longitude}")
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'location': {
                'latitude': latitude,
                'longitude': longitude
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'phone_number': str, 'first_name': str, 'last_name': str})
def send_contact(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    phone_number = data['phone_number']
    first_name = data['first_name']
    last_name = data.get('last_name', '')

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, text)
            VALUES (?, ?, ?, 'contact', ?)''',
            (chat_id, user['id'], new_message_id, f"{phone_number}|{first_name}|{last_name}")
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'contact': {
                'phone_number': phone_number,
                'first_name': first_name,
                'last_name': last_name
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'question': str, 'options': list, 'is_anonymous': bool})
def send_poll(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    question = data['question']
    options = data['options']
    is_anonymous = data.get('is_anonymous', True)

    if len(options) < 2 or len(options) > 10:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Poll must have between 2 and 10 options'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, text)
            VALUES (?, ?, ?, 'poll', ?)''',
            (chat_id, user['id'], new_message_id, f"{question}|{','.join(options)}|{is_anonymous}")
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'poll': {
                'question': question,
                'options': options,
                'is_anonymous': is_anonymous
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'emoji': str})
def send_dice(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    emoji = data['emoji']

    valid_emojis = ['🎲', '🎯', '🏀', '⚽', '🎳', '🎰']
    if emoji not in valid_emojis:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': f'Invalid emoji. Must be one of: {", ".join(valid_emojis)}'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    import random
    if emoji == '🎲':
        value = random.randint(1, 6)
    elif emoji == '🎯':
        value = random.randint(1, 6)
    elif emoji == '🏀':
        value = random.randint(1, 5)
    elif emoji == '⚽':
        value = random.randint(1, 5)
    elif emoji == '🎳':
        value = random.randint(1, 6)
    elif emoji == '🎰':
        value = random.randint(1, 64)

    try:
        max_message_id = conn.execute(
            'SELECT COALESCE(MAX(message_id), 0) as max_id FROM messages WHERE chat_id = ?',
            (chat_id,)
        ).fetchone()['max_id']
        new_message_id = max_message_id + 1

        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO messages
            (chat_id, from_user_id, message_id, message_type, text)
            VALUES (?, ?, ?, 'dice', ?)''',
            (chat_id, user['id'], new_message_id, f"{emoji}|{value}")
        )

        message_id = cursor.lastrowid
        conn.commit()

        message = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.id = ?
        ''', (message_id,)).fetchone()

        conn.close()

        message_data = {
            'message_id': message['message_id'],
            'from': {
                'id': message['from_user_id'],
                'username': message['username'],
                'first_name': message['first_name'],
                'last_name': message['last_name']
            },
            'chat': {'id': chat_id},
            'date': message['date'],
            'message_type': message['message_type'],
            'dice': {
                'emoji': emoji,
                'value': value
            }
        }

        return jsonify({'ok': True, 'result': message_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_user(user: sqlite3.Row) -> JSONResponse:
    user_id = request.args.get('user_id', type=int)

    if not user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'user_id parameter is required'
        }), 400

    conn = get_db_connection()

    target_user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()

    if not target_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User not found'
        }), 404

    user_data = {
        'id': target_user['id'],
        'username': target_user['username'],
        'first_name': target_user['first_name'],
        'last_name': target_user['last_name'],
        'phone_number': target_user['phone_number'],
        'is_bot': bool(target_user['is_bot']),
        'is_online': bool(target_user['is_online']),
        'last_seen': target_user['last_seen']
    }

    conn.close()
    return jsonify({'ok': True, 'result': user_data})

@validate_json({'user_id': int})
def block_user(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    user_id_to_block = data['user_id']

    if user_id_to_block == user['id']:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Cannot block yourself'
        }), 400

    conn = get_db_connection()

    target_user = conn.execute(
        'SELECT id FROM users WHERE id = ?',
        (user_id_to_block,)
    ).fetchone()

    if not target_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User not found'
        }), 404

    existing_block = conn.execute(
        'SELECT id FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
        (user['id'], user_id_to_block)
    ).fetchone()

    if existing_block:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'User already blocked'
        }), 409

    try:
        conn.execute(
            'INSERT INTO blocked_users (user_id, blocked_user_id) VALUES (?, ?)',
            (user['id'], user_id_to_block)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'User blocked successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'user_id': int})
def unblock_user(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    user_id_to_unblock = data['user_id']

    conn = get_db_connection()

    existing_block = conn.execute(
        'SELECT id FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
        (user['id'], user_id_to_unblock)
    ).fetchone()

    if not existing_block:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not blocked'
        }), 404

    try:
        conn.execute(
            'DELETE FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
            (user['id'], user_id_to_unblock)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'User unblocked successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_blocked_users(user: sqlite3.Row) -> JSONResponse:
    conn = get_db_connection()

    blocked_users = conn.execute('''
        SELECT u.id, u.username, u.first_name, u.last_name, u.phone_number
        FROM blocked_users b
        JOIN users u ON b.blocked_user_id = u.id
        WHERE b.user_id = ?
        ORDER BY u.first_name, u.last_name
    ''', (user['id'],)).fetchall()

    result = []
    for blocked_user in blocked_users:
        user_data = {
            'id': blocked_user['id'],
            'username': blocked_user['username'],
            'first_name': blocked_user['first_name'],
            'last_name': blocked_user['last_name'],
            'phone_number': blocked_user['phone_number']
        }
        result.append(user_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def search_messages(user: sqlite3.Row) -> JSONResponse:
    query = request.args.get('query', '')
    chat_id = request.args.get('chat_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    if not query:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'query parameter is required'
        }), 400

    conn = get_db_connection()

    if chat_id:
        is_member = conn.execute(
            'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
            (chat_id, user['id'])
        ).fetchone()

        if not is_member:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 403,
                'description': 'You are not a member of this chat'
            }), 403

        messages = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            WHERE m.chat_id = ? AND (m.text LIKE ? OR m.caption LIKE ?)
            ORDER BY m.date DESC
            LIMIT ? OFFSET ?
        ''', (chat_id, f'%{query}%', f'%{query}%', limit, offset)).fetchall()
    else:
        messages = conn.execute('''
            SELECT m.*, u.username, u.first_name, u.last_name, c.title as chat_title
            FROM messages m
            JOIN users u ON m.from_user_id = u.id
            JOIN chats c ON m.chat_id = c.id
            JOIN chat_members cm ON m.chat_id = cm.chat_id AND cm.user_id = ?
            WHERE (m.text LIKE ? OR m.caption LIKE ?)
            ORDER BY m.date DESC
            LIMIT ? OFFSET ?
        ''', (user['id'], f'%{query}%', f'%{query}%', limit, offset)).fetchall()

    result = []
    for msg in messages:
        message_data = {
            'message_id': msg['message_id'],
            'from': {
                'id': msg['from_user_id'],
                'username': msg['username'],
                'first_name': msg['first_name'],
                'last_name': msg['last_name']
            },
            'chat': {
                'id': msg['chat_id'],
                'title': msg.get('chat_title', '')
            },
            'date': msg['date'],
            'text': msg['text'],
            'message_type': msg['message_type'],
            'caption': msg['caption'],
            'file_id': msg['file_id']
        }
        result.append(message_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

@validate_json({'chat_id': int, 'message_id': int})
def read_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        existing_read = conn.execute(
            'SELECT * FROM message_read_status WHERE message_id = ? AND user_id = ?',
            (message['id'], user['id'])
        ).fetchone()

        if not existing_read:
            conn.execute(
                'INSERT INTO message_read_status (message_id, user_id) VALUES (?, ?)',
                (message['id'], user['id'])
            )
            conn.commit()

        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Message marked as read'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_unread_count(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)

    conn = get_db_connection()

    if chat_id:
        is_member = conn.execute(
            'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
            (chat_id, user['id'])
        ).fetchone()

        if not is_member:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 403,
                'description': 'You are not a member of this chat'
            }), 403

        count = conn.execute('''
            SELECT COUNT(*) as count
            FROM messages m
            WHERE m.chat_id = ?
            AND m.id NOT IN (
                SELECT message_id FROM message_read_status WHERE user_id = ?
            )
        ''', (chat_id, user['id'])).fetchone()['count']
    else:
        count = conn.execute('''
            SELECT COUNT(*) as count
            FROM messages m
            JOIN chat_members cm ON m.chat_id = cm.chat_id AND cm.user_id = ?
            WHERE m.id NOT IN (
                SELECT message_id FROM message_read_status WHERE user_id = ?
            )
        ''', (user['id'], user['id'])).fetchone()['count']

    conn.close()
    return jsonify({'ok': True, 'result': count})

def set_user_profile_photo(user: sqlite3.Row) -> JSONResponse:
    if 'photo' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo provided'
        }), 400

    photo = request.files['photo']

    if photo.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No photo selected'
        }), 400

    file_id = str(uuid.uuid4())
    filename = f"{file_id}_{photo.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        photo.save(file_path)
        file_size = os.path.getsize(file_path)

        from PIL import Image
        img = Image.open(file_path)
        width, height = img.size

        conn = get_db_connection()

        conn.execute(
            'UPDATE user_profile_photos SET is_current = FALSE WHERE user_id = ?',
            (user['id'],)
        )

        conn.execute(
            '''INSERT INTO user_profile_photos
            (user_id, file_id, file_size, width, height, is_current)
            VALUES (?, ?, ?, ?, ?, TRUE)''',
            (user['id'], file_id, file_size, width, height)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Profile photo updated successfully'
            }
        })

    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Error uploading profile photo: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'user_id': int, 'custom_title': str})
def set_member_custom_title(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    user_id = data['user_id']
    custom_title = data['custom_title']

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] != 'creator':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Only chat creator can set custom titles'
        }), 403

    target_member = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user_id)
    ).fetchone()

    if not target_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not a member of this chat'
        }), 404

    if target_member['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Can only set custom title for administrators'
        }), 400

    try:
        conn.execute(
            'UPDATE chat_members SET custom_title = ? WHERE chat_id = ? AND user_id = ?',
            (custom_title, chat_id, user_id)
        )
        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Custom title set successfully'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'chat_id': int, 'title': str})
def start_video_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    title = data.get('title', 'Video Chat')

    conn = get_db_connection()

    user_status = conn.execute(
        'SELECT status FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not user_status or user_status['status'] not in ['creator', 'administrator']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You do not have permission to start video chats'
        }), 403

    active_chat = conn.execute(
        'SELECT id FROM video_chats WHERE chat_id = ? AND is_active = TRUE',
        (chat_id,)
    ).fetchone()

    if active_chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'Video chat is already active in this chat'
        }), 409

    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO video_chats
            (chat_id, title, created_by, participant_count)
            VALUES (?, ?, ?, 1)''',
            (chat_id, title, user['id'])
        )
        video_chat_id = cursor.lastrowid

        cursor.execute(
            '''INSERT INTO video_chat_participants
            (video_chat_id, user_id, join_time)
            VALUES (?, ?, CURRENT_TIMESTAMP)''',
            (video_chat_id, user['id'])
        )
        conn.commit()

        video_chat = conn.execute(
            'SELECT * FROM video_chats WHERE id = ?',
            (video_chat_id,)
        ).fetchone()

        conn.close()

        video_chat_data = {
            'id': video_chat['id'],
            'chat_id': video_chat['chat_id'],
            'title': video_chat['title'],
            'created_by': video_chat['created_by'],
            'start_date': video_chat['start_date'],
            'participant_count': video_chat['participant_count'],
            'is_active': bool(video_chat['is_active'])
        }

        return jsonify({'ok': True, 'result': video_chat_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

@validate_json({'video_chat_id': int})
def join_video_chat(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    video_chat_id = data['video_chat_id']

    conn = get_db_connection()

    video_chat = conn.execute(
        'SELECT * FROM video_chats WHERE id = ? AND is_active = TRUE',
        (video_chat_id,)
    ).fetchone()

    if not video_chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Video chat not found or not active'
        }), 404

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (video_chat['chat_id'], user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    existing_participant = conn.execute(
        'SELECT id FROM video_chat_participants WHERE video_chat_id = ? AND user_id = ? AND leave_time IS NULL',
        (video_chat_id, user['id'])
    ).fetchone()

    if existing_participant:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 409,
            'description': 'Already joined this video chat'
        }), 409

    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO video_chat_participants
            (video_chat_id, user_id, join_time)
            VALUES (?, ?, CURRENT_TIMESTAMP)''',
            (video_chat_id, user['id'])
        )

        cursor.execute(
            'UPDATE video_chats SET participant_count = participant_count + 1 WHERE id = ?',
            (video_chat_id,)
        )
        conn.commit()

        participant = conn.execute('''
            SELECT vcp.*, u.username, u.first_name, u.last_name
            FROM video_chat_participants vcp
            JOIN users u ON vcp.user_id = u.id
            WHERE vcp.id = ?
        ''', (cursor.lastrowid,)).fetchone()

        conn.close()

        participant_data = {
            'id': participant['id'],
            'video_chat_id': participant['video_chat_id'],
            'user': {
                'id': participant['user_id'],
                'username': participant['username'],
                'first_name': participant['first_name'],
                'last_name': participant['last_name']
            },
            'join_time': participant['join_time'],
            'is_muted': bool(participant['is_muted']),
            'is_video_enabled': bool(participant['is_video_enabled'])
        }

        return jsonify({'ok': True, 'result': participant_data})

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_message_statistics(user: sqlite3.Row) -> JSONResponse:
    message_id = request.args.get('message_id', type=int)

    if not message_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'message_id parameter is required'
        }), 400

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE id = ?',
        (message_id,)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (message['chat_id'], user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    stats = conn.execute(
        'SELECT * FROM message_stats WHERE message_id = ?',
        (message_id,)
    ).fetchone()

    if not stats:
        stats = {
            'view_count': 0,
            'forward_count': 0,
            'reply_count': 0,
            'reaction_count': 0
        }
    else:
        stats = dict(stats)

    reactions = conn.execute(
        'SELECT COUNT(*) as count FROM reactions WHERE message_id = ?',
        (message_id,)
    ).fetchone()['count']

    stats['reaction_count'] = reactions

    conn.close()
    return jsonify({'ok': True, 'result': stats})

def get_user_statistics(user: sqlite3.Row) -> JSONResponse:
    user_id = request.args.get('user_id', type=int) or user['id']

    conn = get_db_connection()

    user_stats = conn.execute(
        'SELECT * FROM user_stats WHERE user_id = ?',
        (user_id,)
    ).fetchone()

    if not user_stats:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User statistics not found'
        }), 404

    stats = dict(user_stats)

    conn.close()
    return jsonify({'ok': True, 'result': stats})

@validate_json({'chat_id': int, 'message_id': int})
def view_message(user: sqlite3.Row) -> JSONResponse:
    data = request.get_json()
    chat_id = data['chat_id']
    message_id = data['message_id']

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    message = conn.execute(
        'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    try:
        existing_view = conn.execute(
            'SELECT * FROM message_views WHERE message_id = ? AND user_id = ?',
            (message['id'], user['id'])
        ).fetchone()

        if existing_view:
            conn.execute(
                'UPDATE message_views SET view_count = view_count + 1, viewed_at = CURRENT_TIMESTAMP WHERE id = ?',
                (existing_view['id'],)
            )
        else:
            conn.execute(
                'INSERT INTO message_views (message_id, user_id) VALUES (?, ?)',
                (message['id'], user['id'])
            )

        conn.execute(
            'UPDATE messages SET views = views + 1 WHERE id = ?',
            (message['id'],)
        )

        conn.commit()
        conn.close()

        return jsonify({
            'ok': True,
            'result': {
                'success': True,
                'description': 'Message view recorded'
            }
        })

    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 500,
            'description': f'Database error: {str(e)}'
        }), 500

def get_message_views_count(user: sqlite3.Row) -> JSONResponse:
    message_id = request.args.get('message_id', type=int)

    if not message_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'message_id parameter is required'
        }), 400

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE id = ?',
        (message_id,)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (message['chat_id'], user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    views_count = conn.execute(
        'SELECT SUM(view_count) as total_views FROM message_views WHERE message_id = ?',
        (message_id,)
    ).fetchone()['total_views'] or 0

    conn.close()
    return jsonify({'ok': True, 'result': views_count})

def get_message_viewers(user: sqlite3.Row) -> JSONResponse:
    message_id = request.args.get('message_id', type=int)
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    if not message_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'message_id parameter is required'
        }), 400

    conn = get_db_connection()

    message = conn.execute(
        'SELECT * FROM messages WHERE id = ?',
        (message_id,)
    ).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (message['chat_id'], user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    viewers = conn.execute('''
        SELECT mv.*, u.username, u.first_name, u.last_name
        FROM message_views mv
        JOIN users u ON mv.user_id = u.id
        WHERE mv.message_id = ?
        ORDER BY mv.viewed_at DESC
        LIMIT ? OFFSET ?
    ''', (message_id, limit, offset)).fetchall()

    result = []
    for viewer in viewers:
        viewer_data = {
            'user': {
                'id': viewer['user_id'],
                'username': viewer['username'],
                'first_name': viewer['first_name'],
                'last_name': viewer['last_name']
            },
            'view_count': viewer['view_count'],
            'last_viewed': viewer['viewed_at']
        }
        result.append(viewer_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def get_user_message_views(user: sqlite3.Row) -> JSONResponse:
    target_user_id = request.args.get('user_id', type=int) or user['id']
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    conn = get_db_connection()

    message_views = conn.execute('''
        SELECT mv.*, m.message_id, m.chat_id, c.title as chat_title
        FROM message_views mv
        JOIN messages m ON mv.message_id = m.id
        JOIN chats c ON m.chat_id = c.id
        WHERE mv.user_id = ?
        ORDER BY mv.viewed_at DESC
        LIMIT ? OFFSET ?
    ''', (target_user_id, limit, offset)).fetchall()

    result = []
    for view in message_views:
        view_data = {
            'message_id': view['message_id'],
            'chat': {
                'id': view['chat_id'],
                'title': view['chat_title']
            },
            'view_count': view['view_count'],
            'last_viewed': view['viewed_at']
        }
        result.append(view_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

def get_chat_activity_stats(user: sqlite3.Row) -> JSONResponse:
    chat_id = request.args.get('chat_id', type=int)
    days = request.args.get('days', 7, type=int)

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    is_member = conn.execute(
        'SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not is_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'You are not a member of this chat'
        }), 403

    activity_stats = conn.execute('''
        SELECT
            DATE(date) as day,
            COUNT(*) as message_count,
            COUNT(DISTINCT from_user_id) as active_users
        FROM messages
        WHERE chat_id = ? AND date >= DATE('now', ?)
        GROUP BY DATE(date)
        ORDER BY day DESC
    ''', (chat_id, f'-{days} days')).fetchall()

    result = []
    for stat in activity_stats:
        stat_data = {
            'day': stat['day'],
            'message_count': stat['message_count'],
            'active_users': stat['active_users']
        }
        result.append(stat_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
