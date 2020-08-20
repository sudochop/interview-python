import datetime
from time import mktime

from flask import Flask, request
import jwt
import requests

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time
from business import get_user_by_email

app = Flask(__name__)


def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work
    return jwt.decode(auth_token, jwt_secret_key)


def encode_auth_token(user_id, name, email, scopes):
    # use jwt and jwt_secret_key imported above, and the payload defined below
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the result of jwt.encode to a string
    # make sure to use .decode("utf-8") rather than str() for this
    payload = {
        'sub': user_id,
        'name': name,
        'email': email,
        'scope': scopes,
        'exp': mktime(
            (datetime.datetime.now() + datetime.timedelta(days=1)).timetuple()
        ),
    }

    return jwt.encode(payload, jwt_secret_key).decode('UTF-8')


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route
    _, token = request.headers.get('Authorization', '').split()
    return decode_auth_token(token)


def filter_widget(widget, widget_type, created_start, created_end):
    if widget_type is not None and widget['type'] != widget_type:
        return False

    created = parse_date_time(widget['created'])

    if created_start is not None and created_start > created:
        return False
    if created_end is not None and created > created_end:
        return False

    return True


def format_widget(widget):
    return {
        'id': widget['id'],
        'type': widget['type'],
        'type_label': widget['type'].replace('-', ' ').title(),
        'created': widget['created'],
    }


@app.route('/')
def status():
    return 'API Is Up\n'


@app.route('/user', methods=['GET'])
def user():
    # get the user data from the auth/header/jwt
    user = get_user_from_token()
    return {'user_id': user['sub'], 'name': user['name'], 'email': user['email']}


@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the get_user_by_email function to get the user data
    # return a the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity
    body = request.get_json()
    email = body.get('email')
    scopes = body.get('scopes')

    # I Would normaly use something like flask-inputs here.
    # For brevity I'm going to assume the correct data is provided.

    user = get_user_by_email(email)

    return {'token': encode_auth_token(user['id'], user['name'], user['email'], scopes)}


@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    # get the user ID from the auth/header
    # verify that the token has the widgets scope in the list of scopes

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}

    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function

    # filter the results by the query parameters
    # return the data in the format below
    token = get_user_from_token()

    if 'widgets' not in token.get('scope', []):
        return 'Unauthorized\n', 401

    r = requests.get(
        'https://us-central1-interview-d93bf.cloudfunctions.net/widgets',
        headers={'Authorization': f'apiKey {api_auth_token}'},
        params={'user_id': token['sub']},
    )
    response = r.json()

    widget_type = request.args.get('type')
    start = request.args.get('created_start')
    end = request.args.get('created_end')

    start = parse_date_time(start) if start is not None else None
    end = parse_date_time(end) if end is not None else None

    # Could be optimized by checking if any query params at all first.
    matching_items = filter(lambda w: filter_widget(w, widget_type, start, end), response)
    matching_items = map(format_widget, matching_items)

    return {
        'total_widgets_own_by_user': len(response),
        'matching_items': list(matching_items),
    }


if __name__ == '__main__':
    app.run()
