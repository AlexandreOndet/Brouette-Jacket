from flask import Flask, redirect, request, render_template
import os
import json
from datetime import datetime
from collections import Counter
import plotly.express as px
import pandas as pd
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

config_file = 'config.json'
log_file = 'logs.json'

with open(config_file, 'r') as f:
    config = json.load(f)
users = config['users']

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

def load_logs():
    if os.path.exists(log_file) and os.stat(log_file).st_size > 0:
        with open(log_file, 'r') as f:
            return json.load(f)
    return {}


def save_logs(logs):
    with open(log_file, 'w') as f:
        json.dump(logs, f)

def log_visit(ip_address, visited_route):
    if visited_route == 'favicon.ico':
        return 
    
    logs = load_logs()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    visit_data = {'visited_route': visited_route, 'timestamp': timestamp, 'ip_address': ip_address}
    
    if visited_route in logs:
        logs[visited_route].append(visit_data)
    else:
        logs[visited_route] = [visit_data]
    
    save_logs(logs)



@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def rickroll_redirect(path):
    if path == 'rickrollcounter':
        return 'Counter path cannot be redirected.'
    
    ip_address = request.remote_addr
    log_visit(ip_address, path)

    if path == 'nsec':
        return redirect('https://youtu.be/SPlQpGeTbIE')

    return redirect('https://youtu.be/dQw4w9WgXcQ')

@app.route('/rickrollcounter')
@auth.login_required
def dashboard():
    logs = load_logs()

    if not logs:
        rickroll_count = 0
        unique_ips = 0
        total_pages = 0
        total_solves = 0
        route_names = []
        visit_counts = []
        ip_addresses = []
        interaction_counts = []
    else:
        rickroll_count = sum(len(sublist) for route, sublist in logs.items() if route != 'nsec')
        unique_ips = len(set(log['ip_address'] for sublist in logs.values() for log in sublist))
        total_pages = sum(len(sublist) for sublist in logs.values())
        total_solves = sum(len(sublist) for route, sublist in logs.items() if route == 'nsec')

        all_routes = [item['visited_route'] for sublist in logs.values() for item in sublist]
        route_counts = Counter(all_routes)
        top_routes = route_counts.most_common(10)
        route_names = [route[0] for route in top_routes]
        visit_counts = [route[1] for route in top_routes]

        all_ips = [log['ip_address'] for sublist in logs.values() for log in sublist]
        ip_counts = Counter(all_ips)
        top_ips = ip_counts.most_common(10)
        ip_addresses = [ip[0] for ip in top_ips]
        interaction_counts = [ip[1] for ip in top_ips]

    fig_routes = px.bar(x=route_names, y=visit_counts, labels={'x': 'Route', 'y': 'Visits'}, title='Top Visited Routes')
    chart_div_routes = fig_routes.to_html(full_html=False)

    fig_ips = px.bar(x=ip_addresses, y=interaction_counts, labels={'x': 'IP Address', 'y': 'Interactions'}, title='Top IPs with Most Interactions')
    chart_div_ips = fig_ips.to_html(full_html=False)

    # List of all logs
    log_list = [{'timestamp': log['timestamp'], 'ip_address': log['ip_address'], 'visited_route': log['visited_route']} for sublist in logs.values() for log in sublist]
    log_list_sorted = sorted(log_list, key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'), reverse=True)

    return render_template('dashboard.html', chart_div_routes=chart_div_routes, chart_div_ips=chart_div_ips, log_list=log_list_sorted, rickroll_count=rickroll_count, unique_ips=unique_ips, total_pages=total_pages, total_solves=total_solves)



if __name__ == '__main__':
    app.run(debug=True)