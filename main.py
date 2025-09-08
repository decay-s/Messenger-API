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
    """Decorator to implement rate limiting."""
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
    """Create and return a database connection."""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize the database with required tables."""
    if not os.path.exists(app.config['DATABASE']):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT,
                phone TEXT,
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
                media_type TEXT CHECK(media_type IN (
                    'text', 'photo', 'document', 'video', 'audio', 'voice', 'sticker', 'location', 'contact'
                )),
                media_caption TEXT,
                file_id TEXT,
                file_size INTEGER,
                mime_type TEXT,
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
                phone TEXT,
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

        conn.commit()
        conn.close()
        logger.info("Database created successfully!")

def authenticate_token(token: str) -> Optional[sqlite3.Row]:
    """Authenticate user by token and update last seen."""
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

def token_required(f):
    """Decorator to require token authentication for API methods."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = kwargs.get('token')
        if not token:
            return jsonify({
                'ok': False,
                'error_code': 401,
                'description': 'Token is required'
            }), 401

        user = authenticate_token(token)
        if not user:
            return jsonify({
                'ok': False,
                'error_code': 401,
                'description': 'Unauthorized: Invalid token'
            }), 401

        return f(user, *args, **kwargs)
    return decorated_function

def validate_json(schema: Dict[str, Any]):
    """Decorator to validate JSON input against a schema."""
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
    """Main API endpoint router."""
    method_handlers = {
        'getMe': get_me,
        'getMessages': get_messages,
        'getChat': get_chat,
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
        'signin': sign_in,
        'signup': sign_up,
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
        'getChatActivityStats': get_chat_activity_stats,
    }

    handler = method_handlers.get(method)
    if not handler:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Method not found'
        }), 404

    if method in ['signin', 'signup']:
        return handler(request)
    else:
        return handler(token)

@rate_limit
@validate_json({'username': str, 'password': str})
def sign_in(request) -> JSONResponse:
    """Authenticate user and return token."""
    username = request.json['username']
    password = request.json['password']

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
            'description': 'Invalid credentials'
        }), 401

    token = str(uuid.uuid4())
    conn.execute(
        'UPDATE users SET token = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
        (token, user['id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'phone': user['phone'],
                'is_bot': bool(user['is_bot'])
            }
        }
    })

@rate_limit
@validate_json({
    'username': str,
    'password': str,
    'first_name': str
})
def sign_up(request) -> JSONResponse:
    """Register a new user."""
    username = request.json['username']
    password = request.json['password']
    first_name = request.json['first_name']
    last_name = request.json.get('last_name', '')
    phone = request.json.get('phone', '')

    if not username.isalnum() or len(username) < 3:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Username must be alphanumeric and at least 3 characters long'
        }), 400

    if len(password) < 6:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Password must be at least 6 characters long'
        }), 400

    conn = get_db_connection()

    existing_user = conn.execute(
        'SELECT id FROM users WHERE username = ?',
        (username,)
    ).fetchone()

    if existing_user:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Username already exists'
        }), 400

    password_hash = generate_password_hash(password)
    token = str(uuid.uuid4())

    conn.execute('''
        INSERT INTO users (username, password_hash, first_name, last_name, phone, token)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, password_hash, first_name, last_name, phone, token))

    user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    conn.execute('''
        INSERT INTO user_settings (user_id)
        VALUES (?)
    ''', (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'token': token,
            'user': {
                'id': user_id,
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'phone': phone,
                'is_bot': False
            }
        }
    })

@token_required
def logout(user: sqlite3.Row) -> JSONResponse:
    """Log out user by invalidating token."""
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET token = NULL WHERE id = ?',
        (user['id'],)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Logged out successfully'
    })

@token_required
def get_me(user: sqlite3.Row) -> JSONResponse:
    """Get current user information."""
    return jsonify({
        'ok': True,
        'result': {
            'id': user['id'],
            'is_bot': bool(user['is_bot']),
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'username': user['username'],
            'phone': user['phone'],
            'is_online': bool(user['is_online']),
            'last_seen': user['last_seen']
        }
    })

@token_required
def get_user(user: sqlite3.Row) -> JSONResponse:
    """Get information about a user."""
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'user_id parameter is required'
        }), 400

    conn = get_db_connection()
    target_user = conn.execute(
        'SELECT id, username, first_name, last_name, phone, is_bot, last_seen, is_online FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()

    conn.close()

    if not target_user:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User not found'
        }), 404

    is_blocked = check_if_blocked(user['id'], int(user_id))

    return jsonify({
        'ok': True,
        'result': {
            'id': target_user['id'],
            'is_bot': bool(target_user['is_bot']),
            'first_name': target_user['first_name'],
            'last_name': target_user['last_name'],
            'username': target_user['username'],
            'phone': target_user['phone'],
            'is_online': bool(target_user['is_online']),
            'last_seen': target_user['last_seen'],
            'is_blocked': is_blocked
        }
    })

@token_required
@validate_json({'user_id': int})
def block_user(user: sqlite3.Row) -> JSONResponse:
    """Block a user."""
    user_id_to_block = request.json['user_id']

    if user['id'] == user_id_to_block:
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
            'error_code': 400,
            'description': 'User is already blocked'
        }), 400

    conn.execute(
        'INSERT INTO blocked_users (user_id, blocked_user_id) VALUES (?, ?)',
        (user['id'], user_id_to_block)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'User blocked successfully'
    })

@token_required
@validate_json({'user_id': int})
def unblock_user(user: sqlite3.Row) -> JSONResponse:
    """Unblock a user."""
    user_id_to_unblock = request.json['user_id']

    conn = get_db_connection()

    result = conn.execute(
        'DELETE FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
        (user['id'], user_id_to_unblock)
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User was not blocked'
        }), 404

    return jsonify({
        'ok': True,
        'result': 'User unblocked successfully'
    })

@token_required
def get_blocked_users(user: sqlite3.Row) -> JSONResponse:
    """Get list of blocked users."""
    conn = get_db_connection()

    blocked_users = conn.execute('''
        SELECT u.id, u.username, u.first_name, u.last_name, u.phone
        FROM blocked_users b
        JOIN users u ON b.blocked_user_id = u.id
        WHERE b.user_id = ?
        ORDER BY b.created_at DESC
    ''', (user['id'],)).fetchall()

    conn.close()

    result = []
    for blocked_user in blocked_users:
        result.append({
            'id': blocked_user['id'],
            'username': blocked_user['username'],
            'first_name': blocked_user['first_name'],
            'last_name': blocked_user['last_name'],
            'phone': blocked_user['phone']
        })

    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({
    'type': str,
    'title': str
})
def create_chat(user: sqlite3.Row) -> JSONResponse:
    """Create a new chat."""
    chat_type = request.json['type']
    title = request.json['title']
    description = request.json.get('description', '')

    if chat_type not in ['private', 'group', 'channel', 'supergroup']:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid chat type'
        }), 400

    conn = get_db_connection()

    invite_link = str(uuid.uuid4())

    conn.execute('''
        INSERT INTO chats (type, title, description, invite_link, created_by)
        VALUES (?, ?, ?, ?, ?)
    ''', (chat_type, title, description, invite_link, user['id']))

    chat_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    conn.execute('''
        INSERT INTO chat_members (chat_id, user_id, status)
        VALUES (?, ?, 'creator')
    ''', (chat_id, user['id']))

    conn.commit()

    new_chat = conn.execute(
        'SELECT * FROM chats WHERE id = ?',
        (chat_id,)
    ).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'id': new_chat['id'],
            'type': new_chat['type'],
            'title': new_chat['title'],
            'description': new_chat['description'],
            'invite_link': new_chat['invite_link'],
            'created_by': new_chat['created_by'],
            'created_at': new_chat['created_at']
        }
    })

@token_required
def get_chat(user: sqlite3.Row) -> JSONResponse:
    """Get information about a chat."""
    chat_id = request.args.get('chat_id')
    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

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

    members_count = conn.execute(
        'SELECT COUNT(*) FROM chat_members WHERE chat_id = ? AND status != "left" AND status != "kicked"',
        (chat_id,)
    ).fetchone()[0]

    online_count = conn.execute('''
        SELECT COUNT(*)
        FROM chat_members cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.chat_id = ? AND u.is_online = TRUE
    ''', (chat_id,)).fetchone()[0]

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'id': chat['id'],
            'type': chat['type'],
            'title': chat['title'],
            'description': chat['description'],
            'invite_link': chat['invite_link'],
            'created_by': chat['created_by'],
            'created_at': chat['created_at'],
            'is_public': bool(chat['is_public']),
            'members_count': members_count,
            'online_count': online_count
        }
    })

@token_required
@validate_json({'chat_id': int})
def join_chat(user: sqlite3.Row) -> JSONResponse:
    """Join a chat by ID or invite link."""
    chat_id = request.json.get('chat_id')
    invite_link = request.json.get('invite_link')

    conn = get_db_connection()

    if chat_id:
        chat = conn.execute(
            'SELECT * FROM chats WHERE id = ?',
            (chat_id,)
        ).fetchone()
    elif invite_link:
        chat = conn.execute(
            'SELECT * FROM chats WHERE invite_link = ?',
            (invite_link,)
        ).fetchone()
    else:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Either chat_id or invite_link is required'
        }), 400

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found'
        }), 404

    if not chat['is_public'] and not invite_link:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'This chat is private and requires an invite link'
        }), 403

    existing_member = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat['id'], user['id'])
    ).fetchone()

    if existing_member:
        if existing_member['status'] in ['left', 'kicked']:
            conn.execute('''
                UPDATE chat_members
                SET status = 'member', joined_date = CURRENT_TIMESTAMP
                WHERE chat_id = ? AND user_id = ?
            ''', (chat['id'], user['id']))
        else:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 400,
                'description': 'Already a member of this chat'
            }), 400
    else:
        conn.execute('''
            INSERT INTO chat_members (chat_id, user_id, status)
            VALUES (?, ?, 'member')
        ''', (chat['id'], user['id']))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Joined chat successfully'
    })

@token_required
@validate_json({'chat_id': int})
def leave_chat(user: sqlite3.Row) -> JSONResponse:
    """Leave a chat."""
    chat_id = request.json['chat_id']

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Not a member of this chat'
        }), 400

    conn.execute('''
        UPDATE chat_members
        SET status = 'left'
        WHERE chat_id = ? AND user_id = ?
    ''', (chat_id, user['id']))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Left chat successfully'
    })

@token_required
@validate_json({'chat_id': int})
def delete_chat(user: sqlite3.Row) -> JSONResponse:
    """Delete a chat (only for creators)."""
    chat_id = request.json['chat_id']

    conn = get_db_connection()

    chat = conn.execute(
        'SELECT * FROM chats WHERE id = ? AND created_by = ?',
        (chat_id, user['id'])
    ).fetchone()

    if not chat:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Chat not found or you are not the creator'
        }), 404

    conn.execute('DELETE FROM chats WHERE id = ?', (chat_id,))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat deleted successfully'
    })

@token_required
@validate_json({'chat_id': int, 'text': str})
def send_message(user: sqlite3.Row) -> JSONResponse:
    """Send a text message to a chat."""
    chat_id = request.json['chat_id']
    text = request.json['text']
    reply_to_message_id = request.json.get('reply_to_message_id')

    if len(text) > 4096:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Message is too long (max 4096 characters)'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_messages = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send messages in this chat'
        }), 403

    if reply_to_message_id:
        replied_message = conn.execute(
            'SELECT * FROM messages WHERE chat_id = ? AND message_id = ?',
            (chat_id, reply_to_message_id)
        ).fetchone()

        if not replied_message:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 400,
                'description': 'Replied message not found'
            }), 400

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, text, message_id, reply_to_message_id, media_type)
        VALUES (?, ?, ?, ?, ?, 'text')
    ''', (chat_id, user['id'], text, new_message_id, reply_to_message_id))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
def get_messages(user: sqlite3.Row) -> JSONResponse:
    """Get messages from a chat."""
    chat_id = request.args.get('chat_id')
    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))

    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

    messages = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ?
        ORDER BY m.date DESC
        LIMIT ? OFFSET ?
    ''', (chat_id, limit, offset)).fetchall()

    result = [format_message(msg) for msg in messages]

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'message_id': int, 'text': str})
def edit_message_text(user: sqlite3.Row) -> JSONResponse:
    """Edit a text message."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']
    new_text = request.json['text']

    if len(new_text) > 4096:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Message is too long (max 4096 characters)'
        }), 400

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
            'description': 'Message not found or not authorized to edit'
        }), 404

    conn.execute('''
        UPDATE messages
        SET text = ?, edit_date = CURRENT_TIMESTAMP
        WHERE chat_id = ? AND message_id = ?
    ''', (new_text, chat_id, message_id))

    conn.commit()

    updated_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(updated_message)
    })

@token_required
@validate_json({'chat_id': int, 'message_id': int})
def delete_message(user: sqlite3.Row) -> JSONResponse:
    """Delete a message."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']

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

    is_author = message['from_user_id'] == user['id']

    if not is_author:
        user_permissions = conn.execute('''
            SELECT can_delete_messages FROM chat_members
            WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
        ''', (chat_id, user['id'])).fetchone()

        if not user_permissions or not user_permissions['can_delete_messages']:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 403,
                'description': 'Not authorized to delete this message'
            }), 403

    conn.execute(
        'DELETE FROM messages WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Message deleted successfully'
    })

@token_required
def get_contacts(user: sqlite3.Row) -> JSONResponse:
    """Get user's contact list."""
    conn = get_db_connection()

    contacts = conn.execute('''
        SELECT u.id, u.username, u.first_name, u.last_name, u.phone, u.is_online, u.last_seen
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ?
        ORDER BY u.first_name, u.last_name
    ''', (user['id'],)).fetchall()

    result = []
    for contact in contacts:
        result.append({
            'id': contact['id'],
            'username': contact['username'],
            'first_name': contact['first_name'],
            'last_name': contact['last_name'],
            'phone': contact['phone'],
            'is_online': bool(contact['is_online']),
            'last_seen': contact['last_seen']
        })

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'user_id': int})
def add_contact(user: sqlite3.Row) -> JSONResponse:
    """Add a user to contacts."""
    contact_user_id = request.json['user_id']

    if user['id'] == contact_user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Cannot add yourself as a contact'
        }), 400

    conn = get_db_connection()

    contact_user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
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
        'SELECT * FROM contacts WHERE user_id = ? AND contact_user_id = ?',
        (user['id'], contact_user_id)
    ).fetchone()

    if existing_contact:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'User is already in contacts'
        }), 400

    conn.execute('''
        INSERT INTO contacts (user_id, contact_user_id, first_name, last_name, phone)
        VALUES (?, ?, ?, ?, ?)
    ''', (user['id'], contact_user_id, contact_user['first_name'],
          contact_user['last_name'], contact_user['phone']))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Contact added successfully'
    })

@token_required
def get_updates(user: sqlite3.Row) -> JSONResponse:
    """Get updates (new messages, etc.) for the user."""
    offset = int(request.args.get('offset', 0))
    limit = min(int(request.args.get('limit', 100)), 100)

    conn = get_db_connection()

    unread_messages = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name, c.title as chat_title
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        JOIN chats c ON m.chat_id = c.id
        WHERE m.chat_id IN (
            SELECT chat_id FROM chat_members
            WHERE user_id = ? AND status NOT IN ('left', 'kicked')
        )
        AND m.id NOT IN (
            SELECT message_id FROM message_read_status
            WHERE user_id = ?
        )
        AND m.from_user_id != ?
        ORDER BY m.date DESC
        LIMIT ? OFFSET ?
    ''', (user['id'], user['id'], user['id'], limit, offset)).fetchall()

    result = [format_message(msg) for msg in unread_messages]

    for message in unread_messages:
        conn.execute('''
            INSERT OR IGNORE INTO message_read_status (message_id, user_id)
            VALUES (?, ?)
        ''', (message['id'], user['id']))

    conn.commit()
    conn.close()

    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'action': str})
def send_chat_action(user: sqlite3.Row) -> JSONResponse:
    """Send a chat action (typing, uploading photo, etc.)."""
    chat_id = request.json['chat_id']
    action = request.json['action']

    valid_actions = ['typing', 'upload_photo', 'record_video', 'upload_video',
                    'record_voice', 'upload_voice', 'upload_document', 'find_location']

    if action not in valid_actions:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid action'
        }), 400

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

    conn.close()
    return jsonify({
        'ok': True,
        'result': 'Action sent successfully'
    })

@token_required
@validate_json({'chat_id': int, 'user_id': int})
def ban_chat_member(user: sqlite3.Row) -> JSONResponse:
    """Ban a user from a chat."""
    chat_id = request.json['chat_id']
    user_id_to_ban = request.json['user_id']

    if user['id'] == user_id_to_ban:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Cannot ban yourself'
        }), 400

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_restrict_members FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_restrict_members']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to ban members'
        }), 403

    target_member = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user_id_to_ban)
    ).fetchone()

    if not target_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not a member of this chat'
        }), 404

    conn.execute('''
        UPDATE chat_members
        SET status = 'kicked'
        WHERE chat_id = ? AND user_id = ?
    ''', (chat_id, user_id_to_ban))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'User banned successfully'
    })

@token_required
@validate_json({'chat_id': int, 'user_id': int})
def unban_chat_member(user: sqlite3.Row) -> JSONResponse:
    """Unban a user from a chat."""
    chat_id = request.json['chat_id']
    user_id_to_unban = request.json['user_id']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_restrict_members FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_restrict_members']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to unban members'
        }), 403

    target_member = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status = "kicked"',
        (chat_id, user_id_to_unban)
    ).fetchone()

    if not target_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not banned from this chat'
        }), 404

    conn.execute(
        'DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, user_id_to_unban)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'User unbanned successfully'
    })

@app.route('/api/file/upload', methods=['POST'])
@rate_limit
@token_required
def upload_file(user: sqlite3.Row) -> JSONResponse:
    """Upload a file."""
    if 'file' not in request.files:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No file provided'
        }), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'No file selected'
        }), 400

    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > app.config['MAX_FILE_SIZE']:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': f'File too large. Max size is {app.config["MAX_FILE_SIZE"]} bytes'
        }), 400

    file_id = str(uuid.uuid4())
    file_extension = os.path.splitext(file.filename)[1]
    filename = f"{file_id}{file_extension}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(file_path)

    conn = get_db_connection()
    conn.execute('''
        INSERT INTO files (id, original_name, mime_type, size, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (file_id, file.filename, file.mimetype, file_size, user['id']))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'file_id': file_id,
            'file_size': file_size,
            'file_path': file_path
        }
    })

@app.route('/api/file/download/<file_id>')
@rate_limit
@token_required
def download_file(user: sqlite3.Row, file_id: str) -> Any:
    """Download a file."""
    conn = get_db_connection()

    file_info = conn.execute(
        'SELECT * FROM files WHERE id = ?',
        (file_id,)
    ).fetchone()

    if not file_info:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'File not found'
        }), 404

    file_extension = os.path.splitext(file_info['original_name'])[1]
    filename = f"{file_id}{file_extension}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'File not found on server'
        }), 404

    conn.close()
    return send_file(file_path, as_attachment=True, download_name=file_info['original_name'])

def format_message(message: sqlite3.Row) -> Dict[str, Any]:
    """Format a message for API response."""
    return {
        'message_id': message['message_id'],
        'from': {
            'id': message['from_user_id'],
            'is_bot': False,
            'first_name': message['first_name'],
            'last_name': message['last_name'],
            'username': message['username']
        },
        'chat': {
            'id': message['chat_id']
        },
        'date': message['date'],
        'edit_date': message['edit_date'],
        'text': message['text'],
        'media_type': message['media_type'],
        'media_caption': message['media_caption'],
        'reply_to_message_id': message['reply_to_message_id'],
        'is_pinned': bool(message['is_pinned']),
        'views': message['views']
    }

def check_if_blocked(user_id: int, target_user_id: int) -> bool:
    """Check if a user has blocked another user."""
    conn = get_db_connection()
    block = conn.execute(
        'SELECT id FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
        (user_id, target_user_id)
    ).fetchone()
    conn.close()
    return bool(block)

@token_required
def send_notification(user: sqlite3.Row) -> JSONResponse:
    """Send a notification (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Notification sent'
    })

@token_required
def send_document(user: sqlite3.Row) -> JSONResponse:
    """Send a document (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Document sent'
    })

@token_required
def fetch_messages(user: sqlite3.Row) -> JSONResponse:
    """Fetch messages (alias for getMessages)."""
    return get_messages(user)

@token_required
def close(user: sqlite3.Row) -> JSONResponse:
    """Close connection (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Connection closed'
    })

@token_required
def connect(user: sqlite3.Row) -> JSONResponse:
    """Connect (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Connected'
    })

@token_required
def disconnect(user: sqlite3.Row) -> JSONResponse:
    """Disconnect (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Disconnected'
    })

@token_required
def refresh(user: sqlite3.Row) -> JSONResponse:
    """Refresh (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Refreshed'
    })

@token_required
def update(user: sqlite3.Row) -> JSONResponse:
    """Update (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Updated'
    })

@token_required
def upgrade(user: sqlite3.Row) -> JSONResponse:
    """Upgrade (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Upgraded'
    })

@token_required
def get_user_profile_photos(user: sqlite3.Row) -> JSONResponse:
    """Get user profile photos (placeholder)."""
    return jsonify({
        'ok': True,
        'result': {
            'total_count': 0,
            'photos': []
        }
    })

@token_required
@validate_json({'chat_id': int, 'permissions': dict})
def set_chat_permissions(user: sqlite3.Row) -> JSONResponse:
    """Set chat permissions (placeholder)."""
    return jsonify({
        'ok': True,
        'result': 'Permissions updated'
    })

@token_required
def get_chat_members_count(user: sqlite3.Row) -> JSONResponse:
    """Get chat members count."""
    chat_id = request.args.get('chat_id')
    if not chat_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id parameter is required'
        }), 400

    conn = get_db_connection()

    count = conn.execute(
        'SELECT COUNT(*) FROM chat_members WHERE chat_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id,)
    ).fetchone()[0]

    conn.close()

    return jsonify({
        'ok': True,
        'result': count
    })

@token_required
def get_chat_member(user: sqlite3.Row) -> JSONResponse:
    """Get information about a chat member."""
    chat_id = request.args.get('chat_id')
    user_id = request.args.get('user_id')

    if not chat_id or not user_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id and user_id parameters are required'
        }), 400

    conn = get_db_connection()

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

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'user': {
                'id': member['user_id'],
                'username': member['username'],
                'first_name': member['first_name'],
                'last_name': member['last_name']
            },
            'status': member['status'],
            'until_date': member['until_date'],
            'joined_date': member['joined_date'],
            'can_send_messages': bool(member['can_send_messages']),
            'can_send_media_messages': bool(member['can_send_media_messages']),
            'can_send_polls': bool(member['can_send_polls']),
            'can_send_other_messages': bool(member['can_send_other_messages']),
            'can_add_web_page_previews': bool(member['can_add_web_page_previews']),
            'can_change_info': bool(member['can_change_info']),
            'can_invite_users': bool(member['can_invite_users']),
            'can_pin_messages': bool(member['can_pin_messages'])
        }
    })

@token_required
@validate_json({'chat_id': int, 'photo': str})
def set_chat_photo(user: sqlite3.Row) -> JSONResponse:
    """Set chat photo."""
    chat_id = request.json['chat_id']
    photo_file_id = request.json['photo']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_change_info FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_change_info']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to change chat photo'
        }), 403

    conn.execute(
        'UPDATE chats SET photo_file_id = ? WHERE id = ?',
        (photo_file_id, chat_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat photo updated successfully'
    })

@token_required
@validate_json({'chat_id': int})
def delete_chat_photo(user: sqlite3.Row) -> JSONResponse:
    """Delete chat photo."""
    chat_id = request.json['chat_id']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_change_info FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_change_info']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to delete chat photo'
        }), 403

    conn.execute(
        'UPDATE chats SET photo_file_id = NULL WHERE id = ?',
        (chat_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat photo deleted successfully'
    })

@token_required
@validate_json({'chat_id': int, 'title': str})
def set_chat_title(user: sqlite3.Row) -> JSONResponse:
    """Set chat title."""
    chat_id = request.json['chat_id']
    title = request.json['title']

    if len(title) > 255:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Title is too long (max 255 characters)'
        }), 400

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_change_info FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_change_info']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to change chat title'
        }), 403

    conn.execute(
        'UPDATE chats SET title = ? WHERE id = ?',
        (title, chat_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat title updated successfully'
    })

@token_required
@validate_json({'chat_id': int, 'description': str})
def set_chat_description(user: sqlite3.Row) -> JSONResponse:
    """Set chat description."""
    chat_id = request.json['chat_id']
    description = request.json['description']

    if len(description) > 255:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Description is too long (max 255 characters)'
        }), 400

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_change_info FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_change_info']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to change chat description'
        }), 403

    conn.execute(
        'UPDATE chats SET description = ? WHERE id = ?',
        (description, chat_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat description updated successfully'
    })

@token_required
@validate_json({'chat_id': int, 'message_id': int})
def pin_chat_message(user: sqlite3.Row) -> JSONResponse:
    """Pin a message in chat."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_pin_messages FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_pin_messages']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to pin messages'
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

    conn.execute(
        'UPDATE messages SET is_pinned = FALSE WHERE chat_id = ? AND is_pinned = TRUE',
        (chat_id,)
    )

    conn.execute(
        'UPDATE messages SET is_pinned = TRUE WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Message pinned successfully'
    })

@token_required
@validate_json({'chat_id': int, 'message_id': int})
def unpin_chat_message(user: sqlite3.Row) -> JSONResponse:
    """Unpin a message in chat."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_pin_messages FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_pin_messages']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to unpin messages'
        }), 403

    result = conn.execute(
        'UPDATE messages SET is_pinned = FALSE WHERE chat_id = ? AND message_id = ?',
        (chat_id, message_id)
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found or not pinned'
        }), 404

    return jsonify({
        'ok': True,
        'result': 'Message unpinned successfully'
    })

@token_required
@validate_json({'chat_id': int})
def unpin_all_chat_messages(user: sqlite3.Row) -> JSONResponse:
    """Unpin all messages in chat."""
    chat_id = request.json['chat_id']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status, can_pin_messages FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions or not user_permissions['can_pin_messages']:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to unpin messages'
        }), 403

    conn.execute(
        'UPDATE messages SET is_pinned = FALSE WHERE chat_id = ?',
        (chat_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'All messages unpinned successfully'
    })

@token_required
@validate_json({'callback_query_id': str, 'text': str})
def answer_callback_query(user: sqlite3.Row) -> JSONResponse:
    """Answer a callback query."""
    callback_query_id = request.json['callback_query_id']
    text = request.json.get('text', '')

    return jsonify({
        'ok': True,
        'result': 'Callback query answered successfully'
    })

@token_required
@validate_json({'chat_id': int, 'message_id': int, 'reaction': str})
def set_message_reaction(user: sqlite3.Row) -> JSONResponse:
    """Set reaction to a message."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']
    reaction = request.json['reaction']

    if len(reaction) > 10:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Reaction is too long'
        }), 400

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
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
        'result': 'Reaction set successfully'
    })

@token_required
def get_message_reactions(user: sqlite3.Row) -> JSONResponse:
    """Get reactions for a message."""
    chat_id = request.args.get('chat_id')
    message_id = request.args.get('message_id')

    if not chat_id or not message_id:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'chat_id and message_id parameters are required'
        }), 400

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
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
               GROUP_CONCAT(u.username) as usernames
        FROM reactions r
        JOIN users u ON r.user_id = u.id
        WHERE r.message_id = ?
        GROUP BY r.emoji
    ''', (message['id'],)).fetchall()

    result = []
    for reaction in reactions:
        result.append({
            'emoji': reaction['emoji'],
            'count': reaction['count'],
            'usernames': reaction['usernames'].split(',') if reaction['usernames'] else []
        })

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'from_chat_id': int, 'message_id': int})
def forward_message(user: sqlite3.Row) -> JSONResponse:
    """Forward a message to another chat."""
    chat_id = request.json['chat_id']
    from_chat_id = request.json['from_chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    target_membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    source_membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (from_chat_id, user['id'])
    ).fetchone()

    if not target_membership or not source_membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of one or both chats'
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

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, text, message_id, media_type,
                             media_caption, file_id, file_size, mime_type,
                             reply_to_message_id, forwarded_from, forwarded_from_chat_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (chat_id, user['id'], message['text'], new_message_id, message['media_type'],
          message['media_caption'], message['file_id'], message['file_size'],
          message['mime_type'], message['reply_to_message_id'],
          message['from_user_id'], from_chat_id))

    conn.commit()

    forwarded_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(forwarded_message)
    })

@token_required
@validate_json({'chat_id': int, 'from_chat_id': int, 'message_id': int})
def copy_message(user: sqlite3.Row) -> JSONResponse:
    """Copy a message to another chat."""
    chat_id = request.json['chat_id']
    from_chat_id = request.json['from_chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    target_membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    source_membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (from_chat_id, user['id'])
    ).fetchone()

    if not target_membership or not source_membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of one or both chats'
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

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, text, message_id, media_type,
                             media_caption, file_id, file_size, mime_type,
                             reply_to_message_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (chat_id, user['id'], message['text'], new_message_id, message['media_type'],
          message['media_caption'], message['file_id'], message['file_size'],
          message['mime_type'], message['reply_to_message_id']))

    conn.commit()

    copied_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(copied_message)
    })

@token_required
@validate_json({'chat_id': int, 'photo': str})
def send_photo(user: sqlite3.Row) -> JSONResponse:
    """Send a photo to a chat."""
    chat_id = request.json['chat_id']
    photo_file_id = request.json['photo']
    caption = request.json.get('caption', '')

    if len(caption) > 1024:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Caption is too long (max 1024 characters)'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_media_messages = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send media in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, media_caption, file_id)
        VALUES (?, ?, ?, 'photo', ?, ?)
    ''', (chat_id, user['id'], new_message_id, caption, photo_file_id))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'audio': str})
def send_audio(user: sqlite3.Row) -> JSONResponse:
    """Send an audio file to a chat."""
    chat_id = request.json['chat_id']
    audio_file_id = request.json['audio']
    caption = request.json.get('caption', '')
    duration = request.json.get('duration', 0)

    if len(caption) > 1024:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Caption is too long (max 1024 characters)'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_media_messages = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send media in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, media_caption, file_id, file_size)
        VALUES (?, ?, ?, 'audio', ?, ?, ?)
    ''', (chat_id, user['id'], new_message_id, caption, audio_file_id, duration))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'video': str})
def send_video(user: sqlite3.Row) -> JSONResponse:
    """Send a video to a chat."""
    chat_id = request.json['chat_id']
    video_file_id = request.json['video']
    caption = request.json.get('caption', '')
    duration = request.json.get('duration', 0)

    if len(caption) > 1024:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Caption is too long (max 1024 characters)'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_media_messages = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send media in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, media_caption, file_id, file_size)
        VALUES (?, ?, ?, 'video', ?, ?, ?)
    ''', (chat_id, user['id'], new_message_id, caption, video_file_id, duration))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'voice': str})
def send_voice(user: sqlite3.Row) -> JSONResponse:
    """Send a voice message to a chat."""
    chat_id = request.json['chat_id']
    voice_file_id = request.json['voice']
    caption = request.json.get('caption', '')
    duration = request.json.get('duration', 0)

    if len(caption) > 1024:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Caption is too long (max 1024 characters)'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_media_messages = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send media in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, media_caption, file_id, file_size)
        VALUES (?, ?, ?, 'voice', ?, ?, ?)
    ''', (chat_id, user['id'], new_message_id, caption, voice_file_id, duration))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'latitude': float, 'longitude': float})
def send_location(user: sqlite3.Row) -> JSONResponse:
    """Send a location to a chat."""
    chat_id = request.json['chat_id']
    latitude = request.json['latitude']
    longitude = request.json['longitude']

    if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid coordinates'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send messages in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    location_data = json.dumps({'latitude': latitude, 'longitude': longitude})
    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, text)
        VALUES (?, ?, ?, 'location', ?)
    ''', (chat_id, user['id'], new_message_id, location_data))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'phone_number': str, 'first_name': str})
def send_contact(user: sqlite3.Row) -> JSONResponse:
    """Send a contact to a chat."""
    chat_id = request.json['chat_id']
    phone_number = request.json['phone_number']
    first_name = request.json['first_name']
    last_name = request.json.get('last_name', '')

    if not phone_number.replace('+', '').replace(' ', '').isdigit():
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid phone number'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send messages in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    contact_data = json.dumps({
        'phone_number': phone_number,
        'first_name': first_name,
        'last_name': last_name
    })
    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, text)
        VALUES (?, ?, ?, 'contact', ?)
    ''', (chat_id, user['id'], new_message_id, contact_data))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'question': str, 'options': list})
def send_poll(user: sqlite3.Row) -> JSONResponse:
    """Send a poll to a chat."""
    chat_id = request.json['chat_id']
    question = request.json['question']
    options = request.json['options']

    if len(question) > 300:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Question is too long (max 300 characters)'
        }), 400

    if len(options) < 2 or len(options) > 10:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Poll must have between 2 and 10 options'
        }), 400

    for option in options:
        if len(option) > 100:
            return jsonify({
                'ok': False,
                'error_code': 400,
                'description': 'Option text is too long (max 100 characters)'
            }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
        AND can_send_polls = TRUE
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send polls in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    poll_data = json.dumps({
        'question': question,
        'options': options,
        'votes': {}
    })
    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, text)
        VALUES (?, ?, ?, 'poll', ?)
    ''', (chat_id, user['id'], new_message_id, poll_data))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
@validate_json({'chat_id': int, 'emoji': str})
def send_dice(user: sqlite3.Row) -> JSONResponse:
    """Send a dice throw to a chat."""
    chat_id = request.json['chat_id']
    emoji = request.json.get('emoji', '🎲')

    valid_emojis = ['🎲', '🎯', '🏀', '⚽', '🎳', '🎰']
    if emoji not in valid_emojis:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Invalid emoji. Must be one of: 🎲, 🎯, 🏀, ⚽, 🎳, 🎰'
        }), 400

    conn = get_db_connection()

    membership = conn.execute('''
        SELECT * FROM chat_members
        WHERE chat_id = ? AND user_id = ?
        AND status NOT IN ('kicked', 'left')
    ''', (chat_id, user['id'])).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not allowed to send messages in this chat'
        }), 403

    last_message = conn.execute(
        'SELECT MAX(message_id) FROM messages WHERE chat_id = ?',
        (chat_id,)
    ).fetchone()

    new_message_id = last_message[0] + 1 if last_message[0] else 1

    import random
    if emoji == '🎲':
        value = random.randint(1, 6)
    elif emoji == '🎯':
        value = random.randint(1, 6)
    elif emoji in ['🏀', '⚽']:
        value = random.randint(1, 5)
    elif emoji == '🎳':
        value = random.randint(1, 6)
    elif emoji == '🎰':
        value = random.randint(1, 64)

    dice_data = json.dumps({'emoji': emoji, 'value': value})
    conn.execute('''
        INSERT INTO messages (chat_id, from_user_id, message_id, media_type, text)
        VALUES (?, ?, ?, 'dice', ?)
    ''', (chat_id, user['id'], new_message_id, dice_data))

    conn.commit()

    sent_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, new_message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': format_message(sent_message)
    })

@token_required
def search_messages(user: sqlite3.Row) -> JSONResponse:
    """Search for messages in all chats."""
    query = request.args.get('query')
    if not query:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'query parameter is required'
        }), 400

    limit = min(int(request.args.get('limit', 100)), 1000)
    offset = int(request.args.get('offset', 0))

    conn = get_db_connection()

    messages = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name, c.title as chat_title
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        JOIN chats c ON m.chat_id = c.id
        WHERE m.chat_id IN (
            SELECT chat_id FROM chat_members
            WHERE user_id = ? AND status NOT IN ('left', 'kicked')
        )
        AND m.text LIKE ?
        ORDER BY m.date DESC
        LIMIT ? OFFSET ?
    ''', (user['id'], f'%{query}%', limit, offset)).fetchall()

    result = []
    for msg in messages:
        message_data = format_message(msg)
        message_data['chat_title'] = msg['chat_title']
        result.append(message_data)

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'message_id': int})
def read_message(user: sqlite3.Row) -> JSONResponse:
    """Mark a message as read."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
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

    conn.execute('''
        INSERT OR REPLACE INTO message_read_status (message_id, user_id)
        VALUES (?, ?)
    ''', (message['id'], user['id']))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Message marked as read'
    })

@token_required
def get_unread_count(user: sqlite3.Row) -> JSONResponse:
    """Get count of unread messages."""
    conn = get_db_connection()

    unread_count = conn.execute('''
        SELECT COUNT(*) as count
        FROM messages m
        WHERE m.chat_id IN (
            SELECT chat_id FROM chat_members
            WHERE user_id = ? AND status NOT IN ('left', 'kicked')
        )
        AND m.from_user_id != ?
        AND m.id NOT IN (
            SELECT message_id FROM message_read_status
            WHERE user_id = ?
        )
    ''', (user['id'], user['id'], user['id'])).fetchone()['count']

    unread_per_chat = conn.execute('''
        SELECT m.chat_id, c.title, COUNT(*) as count
        FROM messages m
        JOIN chats c ON m.chat_id = c.id
        WHERE m.chat_id IN (
            SELECT chat_id FROM chat_members
            WHERE user_id = ? AND status NOT IN ('left', 'kicked')
        )
        AND m.from_user_id != ?
        AND m.id NOT IN (
            SELECT message_id FROM message_read_status
            WHERE user_id = ?
        )
        GROUP BY m.chat_id
    ''', (user['id'], user['id'], user['id'])).fetchall()

    result = {
        'total': unread_count,
        'by_chat': [{'chat_id': row['chat_id'], 'title': row['title'], 'count': row['count']}
                   for row in unread_per_chat]
    }

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'message_id': int, 'caption': str})
def edit_message_caption(user: sqlite3.Row) -> JSONResponse:
    """Edit the caption of a media message."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']
    new_caption = request.json['caption']

    if len(new_caption) > 1024:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Caption is too long (max 1024 characters)'
        }), 400

    conn = get_db_connection()

    message = conn.execute('''
        SELECT * FROM messages
        WHERE chat_id = ? AND message_id = ?
    ''', (chat_id, message_id)).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found'
        }), 404

    if not message['media_type'] or message['media_type'] == 'text':
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Message is not a media message'
        }), 400

    is_author = message['from_user_id'] == user['id']

    if not is_author:
        user_permissions = conn.execute('''
            SELECT status FROM chat_members
            WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
        ''', (chat_id, user['id'])).fetchone()

        if not user_permissions:
            conn.close()
            return jsonify({
                'ok': False,
                'error_code': 403,
                'description': 'Not authorized to edit this message'
            }), 403

    conn.execute('''
        UPDATE messages
        SET media_caption = ?, edit_date = CURRENT_TIMESTAMP
        WHERE chat_id = ? AND message_id = ?
    ''', (new_caption, chat_id, message_id))

    conn.commit()

    updated_message = conn.execute('''
        SELECT m.*, u.username, u.first_name, u.last_name
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.message_id = ?
    ''', (chat_id, message_id)).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'message_id': updated_message['message_id'],
            'from': {
                'id': updated_message['from_user_id'],
                'is_bot': False,
                'first_name': updated_message['first_name'],
                'last_name': updated_message['last_name'],
                'username': updated_message['username']
            },
            'chat': {'id': updated_message['chat_id']},
            'date': updated_message['date'],
            'edit_date': updated_message['edit_date'],
            'media_type': updated_message['media_type'],
            'media_caption': updated_message['media_caption'],
            'file_id': updated_message['file_id']
        }
    })

@token_required
@validate_json({'photo': str})
def set_user_profile_photo(user: sqlite3.Row) -> JSONResponse:
    """Set user profile photo."""
    photo_file_id = request.json['photo']

    conn = get_db_connection()

    conn.execute(
        'UPDATE user_profile_photos SET is_current = FALSE WHERE user_id = ?',
        (user['id'],)
    )

    conn.execute('''
        INSERT INTO user_profile_photos (user_id, file_id, is_current)
        VALUES (?, ?, TRUE)
    ''', (user['id'], photo_file_id))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Profile photo updated successfully'
    })

@token_required
def get_user_profile_photos(user: sqlite3.Row) -> JSONResponse:
    """Get user profile photos."""
    target_user_id = request.args.get('user_id', user['id'])
    limit = min(int(request.args.get('limit', 10)), 100)
    offset = int(request.args.get('offset', 0))

    conn = get_db_connection()

    photos = conn.execute('''
        SELECT * FROM user_profile_photos
        WHERE user_id = ?
        ORDER BY is_current DESC, created_at DESC
        LIMIT ? OFFSET ?
    ''', (target_user_id, limit, offset)).fetchall()

    result = []
    for photo in photos:
        result.append({
            'file_id': photo['file_id'],
            'file_size': photo['file_size'],
            'width': photo['width'],
            'height': photo['height'],
            'is_current': bool(photo['is_current']),
            'created_at': photo['created_at']
        })

    conn.close()
    return jsonify({'ok': True, 'result': result})

@token_required
@validate_json({'chat_id': int, 'permissions': dict})
def set_chat_permissions(user: sqlite3.Row) -> JSONResponse:
    """Set chat permissions."""
    chat_id = request.json['chat_id']
    permissions = request.json['permissions']

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to change chat permissions'
        }), 403

    conn.execute('''
        INSERT OR REPLACE INTO chat_permissions
        (chat_id, can_send_messages, can_send_media_messages, can_send_polls,
         can_send_other_messages, can_add_web_page_previews, can_change_info,
         can_invite_users, can_pin_messages, can_manage_chat, can_manage_video_chats,
         can_restrict_members, can_promote_members)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        chat_id,
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
        permissions.get('can_promote_members', False)
    ))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Chat permissions updated successfully'
    })

@token_required
@validate_json({'chat_id': int, 'title': str})
def start_video_chat(user: sqlite3.Row) -> JSONResponse:
    """Start a video chat."""
    chat_id = request.json['chat_id']
    title = request.json['title']

    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

    conn.execute('''
        INSERT INTO video_chats (chat_id, title, created_by)
        VALUES (?, ?, ?)
    ''', (chat_id, title, user['id']))

    video_chat_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    conn.execute('''
        INSERT INTO video_chat_participants (video_chat_id, user_id)
        VALUES (?, ?)
    ''', (video_chat_id, user['id']))

    conn.commit()

    video_chat = conn.execute(
        'SELECT * FROM video_chats WHERE id = ?',
        (video_chat_id,)
    ).fetchone()

    conn.close()

    return jsonify({
        'ok': True,
        'result': {
            'id': video_chat['id'],
            'chat_id': video_chat['chat_id'],
            'title': video_chat['title'],
            'created_by': video_chat['created_by'],
            'start_date': video_chat['start_date'],
            'is_active': bool(video_chat['is_active'])
        }
    })

@token_required
@validate_json({'video_chat_id': int})
def join_video_chat(user: sqlite3.Row) -> JSONResponse:
    """Join a video chat."""
    video_chat_id = request.json['video_chat_id']

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

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (video_chat['chat_id'], user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

    existing_participant = conn.execute(
        'SELECT * FROM video_chat_participants WHERE video_chat_id = ? AND user_id = ? AND leave_time IS NULL',
        (video_chat_id, user['id'])
    ).fetchone()

    if existing_participant:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Already in this video chat'
        }), 400

    conn.execute('''
        INSERT INTO video_chat_participants (video_chat_id, user_id)
        VALUES (?, ?)
    ''', (video_chat_id, user['id']))

    conn.execute('''
        UPDATE video_chats
        SET participant_count = participant_count + 1
        WHERE id = ?
    ''', (video_chat_id,))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Joined video chat successfully'
    })

@token_required
@validate_json({'message_id': int})
def get_message_statistics(user: sqlite3.Row) -> JSONResponse:
    """Get message statistics."""
    message_id = request.json['message_id']

    conn = get_db_connection()

    message = conn.execute('''
        SELECT m.* FROM messages m
        JOIN chat_members cm ON m.chat_id = cm.chat_id
        WHERE m.id = ? AND cm.user_id = ? AND cm.status NOT IN ("left", "kicked")
    ''', (message_id, user['id'])).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found or access denied'
        }), 404

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

    conn.close()

    return jsonify({
        'ok': True,
        'result': stats
    })

@token_required
def get_user_statistics(user: sqlite3.Row) -> JSONResponse:
    """Get user statistics."""
    target_user_id = request.args.get('user_id', user['id'])

    if target_user_id != user['id']:
        pass

    conn = get_db_connection()

    stats = conn.execute(
        'SELECT * FROM user_stats WHERE user_id = ?',
        (target_user_id,)
    ).fetchone()

    if not stats:
        conn.execute('''
            INSERT INTO user_stats (user_id) VALUES (?)
        ''', (target_user_id,))
        conn.commit()

        stats = conn.execute(
            'SELECT * FROM user_stats WHERE user_id = ?',
            (target_user_id,)
        ).fetchone()

    group_count = conn.execute(
        'SELECT COUNT(*) FROM chat_members WHERE user_id = ? AND status NOT IN ("left", "kicked") AND chat_id IN (SELECT id FROM chats WHERE type != "private")',
        (target_user_id,)
    ).fetchone()[0]

    conn.close()

    result = dict(stats)
    result['group_count'] = group_count

    return jsonify({
        'ok': True,
        'result': result
    })

@token_required
@validate_json({'chat_id': int, 'user_id': int, 'custom_title': str})
def set_member_custom_title(user: sqlite3.Row) -> JSONResponse:
    """Set custom title for a chat member."""
    chat_id = request.json['chat_id']
    target_user_id = request.json['user_id']
    custom_title = request.json['custom_title']

    if len(custom_title) > 16:
        return jsonify({
            'ok': False,
            'error_code': 400,
            'description': 'Custom title is too long (max 16 characters)'
        }), 400

    conn = get_db_connection()

    user_permissions = conn.execute('''
        SELECT status FROM chat_members
        WHERE chat_id = ? AND user_id = ? AND status IN ('creator', 'administrator')
    ''', (chat_id, user['id'])).fetchone()

    if not user_permissions:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not authorized to set custom titles'
        }), 403

    target_member = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?',
        (chat_id, target_user_id)
    ).fetchone()

    if not target_member:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'User is not a member of this chat'
        }), 404

    conn.execute('''
        UPDATE chat_members
        SET custom_title = ?
        WHERE chat_id = ? AND user_id = ?
    ''', (custom_title, chat_id, target_user_id))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Custom title set successfully'
    })

@token_required
@validate_json({'chat_id': int, 'message_id': int})
def view_message(user: sqlite3.Row) -> JSONResponse:
    """Increment message view count."""
    chat_id = request.json['chat_id']
    message_id = request.json['message_id']

    conn = get_db_connection()

    message = conn.execute('''
        SELECT m.* FROM messages m
        JOIN chat_members cm ON m.chat_id = cm.chat_id
        WHERE m.chat_id = ? AND m.message_id = ? AND cm.user_id = ? AND cm.status NOT IN ("left", "kicked")
    ''', (chat_id, message_id, user['id'])).fetchone()

    if not message:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 404,
            'description': 'Message not found or access denied'
        }), 404

    conn.execute('''
        INSERT INTO message_stats (message_id, view_count)
        VALUES (?, 1)
        ON CONFLICT(message_id) DO UPDATE SET view_count = view_count + 1
    ''', (message['id'],))

    conn.execute('''
        INSERT INTO user_stats (user_id, message_count)
        VALUES (?, 1)
        ON CONFLICT(user_id) DO UPDATE SET message_count = message_count + 1
    ''', (message['from_user_id'],))

    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'result': 'Message view recorded'
    })

@token_required
@validate_json({'chat_id': int, 'days': int})
def get_chat_activity_stats(user: sqlite3.Row) -> JSONResponse:
    """Get chat activity statistics."""
    chat_id = request.json['chat_id']
    days = min(request.json.get('days', 7), 30)
    conn = get_db_connection()

    membership = conn.execute(
        'SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND status NOT IN ("left", "kicked")',
        (chat_id, user['id'])
    ).fetchone()

    if not membership:
        conn.close()
        return jsonify({
            'ok': False,
            'error_code': 403,
            'description': 'Not a member of this chat'
        }), 403

    daily_stats = conn.execute('''
        SELECT DATE(date) as day, COUNT(*) as message_count
        FROM messages
        WHERE chat_id = ? AND date >= datetime('now', ? || ' days')
        GROUP BY DATE(date)
        ORDER BY day DESC
    ''', (chat_id, f'-{days}')).fetchall()

    top_users = conn.execute('''
        SELECT u.id, u.username, u.first_name, u.last_name, COUNT(*) as message_count
        FROM messages m
        JOIN users u ON m.from_user_id = u.id
        WHERE m.chat_id = ? AND m.date >= datetime('now', ? || ' days')
        GROUP BY m.from_user_id
        ORDER BY message_count DESC
        LIMIT 10
    ''', (chat_id, f'-{days}')).fetchall()

    conn.close()

    result = {
        'period_days': days,
        'daily_stats': [{'day': stat['day'], 'message_count': stat['message_count']} for stat in daily_stats],
        'top_users': [{
            'id': user['id'],
            'username': user['username'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'message_count': user['message_count']
        } for user in top_users]
    }

    return jsonify({'ok': True, 'result': result})

init_db()

if __name__ == '__main__':
    app.run()
