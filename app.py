from flask import Flask, render_template, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build  # Ensure this import is here
import json
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'
app.debug = False

# Load client secrets from the JSON file
with open('client_secrets.json', 'r') as json_file:
    client_info = json.load(json_file)

# Configure the OAuth object
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_info['web']['client_id'],
    client_secret=client_info['web']['client_secret'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'https://www.googleapis.com/auth/calendar.events'}
)

@app.route('/')
def index():
    return render_template('invite.html')

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

# what's the autorize page for?
@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    session['token'] = token
    return redirect(url_for('index'))

@app.route('/invite', methods=['GET', 'POST'])
def create_invite():
    if 'token' not in session:
        # User is not logged in
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Extract form data
        event_name = request.form.get('eventname')
        location = request.form.get('location')
        date = request.form.get('date')
        time = request.form.get('time')
        emails = request.form.get('emails')
        description = request.form.get('description')

        # Prepare the event data
        attendees = [{'email': email.strip()} for email in emails.split(',')]
        start_datetime = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M").isoformat() + 'Z'  # 'Z' indicates UTC time
        end_datetime = (datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M") + timedelta(hours=1)).isoformat() + 'Z'  # Assuming 1 hour event duration

        event_body = {
            'summary': event_name,
            'location': location,
            'description': description,
            'start': {'dateTime': start_datetime, 'timeZone': 'UTC'},
            'end': {'dateTime': end_datetime, 'timeZone': 'UTC'},
            'attendees': attendees,
        }
        print(event_body)

        # Create the event on Google Calendar
        creds = Credentials(
            token=session['token'].get('access_token'),
            refresh_token=session['token'].get('refresh_token'),
            token_uri=session['token'].get('token_uri'),
            client_id=session['token'].get('client_id'),
            client_secret=session['token'].get('client_secret'),
            scopes=['https://www.googleapis.com/auth/calendar.events']
        )
        service = build('calendar', 'v3', credentials=creds)
        event = service.events().insert(calendarId='primary', body=event_body).execute()

        return 'Invite Sent!'
    else:
        # GET request - Show the invite creation form
        return render_template('invite.html')

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
