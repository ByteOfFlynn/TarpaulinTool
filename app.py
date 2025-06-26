import os
import json
from functools import wraps

import requests
from flask import Flask, request, jsonify, url_for, make_response
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from six.moves.urllib.request import urlopen
from google.cloud import datastore, storage

# Auth0 stuff
AUTH0_DOMAIN        = os.environ.get('AUTH0_DOMAIN')
API_AUDIENCE        = os.environ.get('API_AUDIENCE')
AUTH0_CLIENT_ID     = os.environ.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
ALGORITHMS          = ["RS256"]

# Cloud Stuff
dc             = datastore.Client()
storage_client = storage.Client()
BUCKET_NAME    = os.environ.get('BUCKET_NAME')
bucket         = storage_client.bucket(BUCKET_NAME)

app = Flask(__name__)

# Errors 
ERROR_MESSAGES = {
    400: "The request body is invalid",
    401: "Unauthorized",
    403: "You don't have permission on this resource",
    404: "Not found",
    409: "Enrollment data is invalid",
    502: "Bad gateway"
}

# Send the errors
def error_response(status_code):
    resp = jsonify({ "Error": ERROR_MESSAGES[status_code] })
    resp.status_code = status_code
    return resp

# CITATION: Source code for token auth and auth decorator adapted from auth0.com
# Token Auth
def get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        return None, error_response(401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        return None, error_response(401)
    elif len(parts) == 1:
        return None, error_response(401)
    elif len(parts) > 2:
        return None, error_response(401)

    token = parts[1]
    return token, None

# Auth Decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token, err = get_token_auth_header()
        if err:
            return err

        # Get Auth0 JWKS
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        try:
            jwks_response = urlopen(jwks_url)
            jwks = json.loads(jwks_response.read())
        except Exception:
            # If unable, error
            return error_response(401)

        # Get key from header
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError:
            return error_response(401)

        # Keys
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header.get("kid"):
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n":   key["n"],
                    "e":   key["e"]
                }
                break
        if not rsa_key:
            # Otherwise error
            return error_response(401)

        # Verify payload
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/"
            )
        except ExpiredSignatureError:
            return error_response(401)
        except JWTClaimsError:
            return error_response(401)
        except JWTError:
            return error_response(401)

        # Attach payload on request
        request.jwt_payload = payload
        return f(*args, **kwargs)

    # Ship it
    return decorated

# Helpers for users and courses
def get_current_user():
    payload = getattr(request, 'jwt_payload', None)
    if not payload or 'sub' not in payload:
        return None
    sub = payload['sub']
    q = dc.query(kind='users')
    q.add_filter('sub', '=', sub)
    users = list(q.fetch())
    if not users:
        return None
    ent = users[0]
    user = dict(ent)
    user['id'] = ent.key.id
    return user

def get_user_entity(user_id):
    key = dc.key('users', user_id)
    return dc.get(key)

def get_course_entity(course_id):
    key = dc.key('courses', course_id)
    return dc.get(key)

# Logging into Auth0
@app.route('/users/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}

    # 400 if missing keys
    if 'username' not in data or 'password' not in data:
        return error_response(400)

    # Send that payload
    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    payload = {
        # Using the realm grant because of custom database
        "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
        "username":   data['username'],
        "password":   data['password'],
        "audience":   API_AUDIENCE,
        "client_id":  AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "realm":      os.environ.get('AUTH0_REALM'),
        "scope":      "openid profile email"
    }

    # Get the token from Auth0 and handle errors
    resp = requests.post(token_url, json=payload)
    if resp.status_code != 200:
        return error_response(401)

    body = resp.json()
    access_token = body.get('access_token')
    if not access_token:
        return error_response(401)

    return jsonify({"token": access_token}), 200

# GET all users
@app.route('/users', methods=['GET'])
@requires_auth
def list_users():
    me = get_current_user()
    if not me or me['role'] != 'admin':
        return error_response(403)
    q = dc.query(kind='users')
    result = []
    for ent in q.fetch():
        result.append({
            "id":   ent.key.id,
            "role": ent['role'],
            "sub":  ent['sub']
        })
    return jsonify(result), 200

# GET only one user
@app.route('/users/<int:user_id>', methods=['GET'])
@requires_auth
def get_user(user_id):
    me = get_current_user()
    if not me:
        return error_response(403)
    ent = get_user_entity(user_id)
    # 403 if user not exist or permitted
    if not ent or (me['role'] != 'admin' and me['id'] != user_id):
        return error_response(403)
    out = {
        "id":   user_id,
        "role": ent['role'],
        "sub":  ent['sub']
    }
    if ent.get('avatar'):
        out["avatar_url"] = url_for('get_avatar', user_id=user_id, _external=True)
    if ent['role'] in ('instructor','student'):
        courses = []
        if ent['role'] == 'instructor':
            cq = dc.query(kind='courses')
            cq.add_filter('instructor_id','=',user_id)
            for c in cq.fetch():
                courses.append(url_for('get_course', course_id=c.key.id, _external=True))
        else:
            eq = dc.query(kind='enrollments')
            eq.add_filter('student_id','=',user_id)
            for e in eq.fetch():
                courses.append(url_for('get_course', course_id=e['course_id'], _external=True))
        out["courses"] = courses
    return jsonify(out), 200

# POST an avatar from ID
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def upload_avatar(user_id):
    # Check for the file
    if 'file' not in request.files or len(request.files) != 1:
        return error_response(400)
    file = request.files['file']
    if file.filename == "":
        return error_response(400)

    # Then verify
    token, err = get_token_auth_header()
    if err:
        return err

    # Get Auth0 JWKS
    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    try:
        jwks_response = urlopen(jwks_url)
        jwks = json.loads(jwks_response.read())
    except Exception:
        # If unable, error
        return error_response(401)

    # Get key from header
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        return error_response(401)

    # Keys
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header.get("kid"):
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n":   key["n"],
                "e":   key["e"]
            }
            break
    if not rsa_key:
        # Otherwise error
        return error_response(401)

    # Verify payload
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
    except ExpiredSignatureError:
        return error_response(401)
    except JWTClaimsError:
        return error_response(401)
    except JWTError:
        return error_response(401)

    request.jwt_payload = payload

    # Now get user
    me = get_current_user()
    if not me or me['id'] != user_id:
        return error_response(403)

    # Check if exists
    ent = get_user_entity(user_id)
    if not ent:
        return error_response(404)

    # Upload to the bucket
    try:
        blob = bucket.blob(f"avatars/{user_id}.png")
        blob.upload_from_file(file.stream, content_type="image/png")
    except Exception:
        return error_response(502)

    # Set in datastore
    ent['avatar'] = True
    dc.put(ent)

    return jsonify({
        "avatar_url": url_for('get_avatar', user_id=user_id, _external=True)
    }), 200

# GET an avatar from ID
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
@requires_auth
def get_avatar(user_id):
    me = get_current_user()
    if not me or me['id'] != user_id:
        return error_response(403)

    ent = get_user_entity(user_id)
    if not ent.get('avatar', False):
        return error_response(404)

    blob = bucket.blob(f"avatars/{user_id}.png")
    if not blob.exists():
        return error_response(404)
    data = blob.download_as_bytes()
    return (data, 200, {'Content-Type': 'image/png'})

# DELETE an avatar from ID
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
@requires_auth
def delete_avatar(user_id):
    me = get_current_user()
    if not me or me['id'] != user_id:
        return error_response(403)

    ent = get_user_entity(user_id)
    if not ent.get('avatar', False):
        return error_response(404)

    blob = bucket.blob(f"avatars/{user_id}.png")
    if not blob.exists():
        return error_response(404)
    blob.delete()

    ent.pop('avatar', None)
    dc.put(ent)

    return ('', 204)

# POST a course
@app.route('/courses', methods=['POST'])
@requires_auth
def create_course():
    me = get_current_user()
    if not me or me['role'] != 'admin':
        return error_response(403)
    data = request.get_json(silent=True)
    required = ['subject','number','title','term','instructor_id']
    if not data or not all(k in data for k in required):
        return error_response(400)

    # Set up length checking
    if len(data['subject']) > 4 or len(data['title']) > 50 or len(data['term']) > 10:
        return error_response(400)

    instr = get_user_entity(data['instructor_id'])
    if not instr or instr['role'] != 'instructor':
        return error_response(400)
    key = dc.key('courses')
    ent = datastore.Entity(key)
    ent.update({k: data[k] for k in required})
    dc.put(ent)
    out = dict(ent)
    out['id'] = ent.key.id
    out['self'] = url_for('get_course', course_id=out['id'], _external=True)
    return jsonify(out), 201

# GET all courses
@app.route('/courses', methods=['GET'])
def list_courses():
    offset = request.args.get('offset', default=0, type=int)
    limit  = 3

    q = dc.query(kind='courses')
    q.order = ['subject']
    it = q.fetch(offset=offset, limit=limit)
    ents = list(it)

    courses = []
    for e in ents:
        courses.append({
            "id":            e.key.id,
            "instructor_id": e['instructor_id'],
            "number":        e['number'],
            "self":          url_for('get_course', course_id=e.key.id, _external=True),
            "subject":       e['subject'],
            "term":          e['term'],
            "title":         e['title']
        })

    resp = {"courses": courses}

    if len(courses) == limit:
        next_off = offset + limit
        # Add limit and offset
        resp["next"] = url_for('list_courses',
                               offset=next_off,
                               limit=3,
                               _external=True)

    return jsonify(resp), 200

# GET only one course
@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    ent = get_course_entity(course_id)
    if not ent:
        return error_response(404)
    out = {
        "id":            course_id,
        "instructor_id": ent['instructor_id'],
        "number":        ent['number'],
        "self":          url_for('get_course', course_id=course_id, _external=True),
        "subject":       ent['subject'],
        "term":          ent['term'],
        "title":         ent['title']
    }
    return jsonify(out), 200

# PATCH a course
@app.route('/courses/<int:course_id>', methods=['PATCH'])
@requires_auth
def update_course(course_id):
    me = get_current_user()
    if not me or me['role'] != 'admin':
        return error_response(403)
    ent = get_course_entity(course_id)
    if not ent:
        return error_response(403)
    data = request.get_json(silent=True)
    if data is None:
        return error_response(400)

    # Set up length checking if exists
    if 'subject' in data and len(data['subject']) > 4:
        return error_response(400)
    if 'title' in data and len(data['title']) > 50:
        return error_response(400)
    if 'term' in data and len(data['term']) > 10:
        return error_response(400)

    if 'instructor_id' in data:
        instr = get_user_entity(data['instructor_id'])
        if not instr or instr['role'] != 'instructor':
            return error_response(400)
    for field in ['subject','number','title','term','instructor_id']:
        if field in data:
            ent[field] = data[field]
    dc.put(ent)
    return get_course(course_id)

# DELETE a course
@app.route('/courses/<int:course_id>', methods=['DELETE'])
@requires_auth
def delete_course(course_id):
    me = get_current_user()
    if not me or me['role'] != 'admin':
        return error_response(403)
    key = dc.key('courses', course_id)
    if not dc.get(key):
        return error_response(403)
    # Remove enrollments
    eq = dc.query(kind='enrollments')
    eq.add_filter('course_id','=',course_id)
    for e in eq.fetch():
        dc.delete(e.key)
    dc.delete(key)
    return ('', 204)

# PATCH enrollments
@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
@requires_auth
def update_enrollment(course_id):
    me = get_current_user()
    course = get_course_entity(course_id)
    if not me or not course:
        return error_response(403)
    if me['role'] != 'admin' and me['id'] != course['instructor_id']:
        return error_response(403)
    data = request.get_json(silent=True)
    if data is None or 'add' not in data or 'remove' not in data:
        return error_response(400)

    add    = set(data.get('add', []))
    remove = set(data.get('remove', []))

    # At least one add or remove
    if not add and not remove:
        return error_response(409)

    # 409 on overlap
    if add & remove:
        return error_response(409)

    # Match ID to student
    for sid in add | remove:
        u = get_user_entity(sid)
        if not u or u['role'] != 'student':
            return error_response(409)

    # Apply add
    for sid in add:
        key = dc.key('enrollments', f"{course_id}_{sid}")
        if not dc.get(key):
            e = datastore.Entity(key)
            e.update({'course_id': course_id, 'student_id': sid})
            dc.put(e)
    # Apply remove
    for sid in remove:
        key = dc.key('enrollments', f"{course_id}_{sid}")
        if dc.get(key):
            dc.delete(key)
    return ('', 200)

# GET enrollments
@app.route('/courses/<int:course_id>/students', methods=['GET'])
@requires_auth
def get_enrollment(course_id):
    me = get_current_user()
    course = get_course_entity(course_id)
    if not me or not course:
        return error_response(403)
    if me['role'] != 'admin' and me['id'] != course['instructor_id']:
        return error_response(403)
    eq = dc.query(kind='enrollments')
    eq.add_filter('course_id','=',course_id)
    students = [e['student_id'] for e in eq.fetch()]
    return jsonify(students), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
