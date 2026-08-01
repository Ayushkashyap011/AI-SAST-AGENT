import type { PresetRepo } from '../types/sast';

export const PRESET_REPOSITORIES: PresetRepo[] = [
  {
    id: 'multi-service-app',
    name: 'CloudPay Platform (Python & Node.js)',
    description: 'Multi-service microservice architecture featuring FastAPI payment service and Node.js auth service.',
    files: [
      {
        name: 'payment_service.py',
        path: 'services/payment/payment_service.py',
        language: 'python',
        content: `import os
import sqlite3
import pickle
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: Hardcoded Sensitive Secret
JWT_SECRET_KEY = "sk_live_9928374102938401928340"
DATABASE_PATH = "/var/db/payments.db"

@app.route("/api/v1/payments/search", methods=["GET"])
def search_payments():
    user_id = request.args.get("user_id")
    status = request.args.get("status")
    
    # Vulnerability 2: SQL Injection via Raw String Formatting
    query = f"SELECT * FROM transactions WHERE user_id = '{user_id}' AND status = '{status}'"
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(query) # Unsanitized execution
    results = cursor.fetchall()
    
    return jsonify({"transactions": results})

@app.route("/api/v1/webhook/fetch", methods=["POST"])
def trigger_webhook():
    data = request.get_json()
    target_url = data.get("callback_url")
    
    # Vulnerability 3: Server-Side Request Forgery (SSRF)
    # Accepts arbitrary external URLs without IP range/domain validation
    response = requests.get(target_url, timeout=5)
    return jsonify({"status": response.status_code, "data": response.text[:200]})

@app.route("/api/v1/export/session", methods=["POST"])
def restore_session():
    serialized_session = request.data
    # Vulnerability 4: Insecure Deserialization via Python pickle
    session_obj = pickle.loads(serialized_session)
    return jsonify({"user": session_obj.get("username")})

@app.route("/api/v1/system/ping", methods=["GET"])
def system_ping():
    host = request.args.get("host", "127.0.0.1")
    # Vulnerability 5: Remote Command Injection via os.system
    cmd = f"ping -c 1 {host}"
    os.system(cmd)
    return jsonify({"message": f"Ping sent to {host}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
`
      },
      {
        name: 'auth_controller.ts',
        path: 'services/auth/auth_controller.ts',
        language: 'typescript',
        content: `import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { exec } from 'child_process';
import { db } from '../database';

// False positive test: Secret in comment should NOT trigger secret detector
// HARDCODED_KEY_EXAMPLE = "do_not_flag_this_comment"

export class AuthController {
  // Vulnerability 6: Hardcoded Secret fallback
  private static JWT_SECRET = process.env.JWT_SECRET || 'fallback_hardcoded_jwt_secret_key_2026';

  public async getUserProfile(req: Request, res: Response) {
    const { userId } = req.params;

    // Vulnerability 7: Broken Access Control (IDOR) - No session ownership check
    // Directly queries DB by URL param without checking if req.user.id === userId
    const user = await db.query(\`SELECT id, email, role, balance FROM users WHERE id = '\${userId}'\`);
    
    return res.json(user);
  }

  public async executeUserScript(req: Request, res: Response) {
    const { scriptName } = req.body;
    
    // Vulnerability 8: Command Injection in Node.js child_process
    exec(\`sh /opt/scripts/\${scriptName}.sh\`, (error, stdout, stderr) => {
      if (error) {
        return res.status(500).json({ error: stderr });
      }
      return res.json({ output: stdout });
    });
  }

  public async evaluateRule(req: Request, res: Response) {
    const { ruleExpression } = req.body;

    // Vulnerability 9: Arbitrary Code Execution via eval()
    const isEligible = eval(ruleExpression);
    return res.json({ result: isEligible });
  }
}
`
      },
      {
        name: 'UserDashboard.tsx',
        path: 'services/frontend/src/UserDashboard.tsx',
        language: 'typescript',
        content: `import React from 'react';

interface Props {
  userBioHtml: string;
  avatarUrl: string;
}

export const UserDashboard: React.FC<Props> = ({ userBioHtml, avatarUrl }) => {
  return (
    <div className="user-profile">
      <h2>User Profile</h2>
      <img src={avatarUrl} alt="Avatar" />
      
      {/* Vulnerability 10: Reflected/DOM Cross-Site Scripting (XSS) */}
      <div 
        className="bio-container"
        dangerouslySetInnerHTML={{ __html: userBioHtml }}
      />
    </div>
  );
};
`
      }
    ]
  },
  {
    id: 'dvwa-benchmark',
    name: 'DVWA Python/JS Security Benchmark',
    description: 'Inspired by Damn Vulnerable Web App benchmarks targeting SQLi, Command Injection, and Insecure Storage.',
    files: [
      {
        name: 'vulnerable_db.py',
        path: 'dvwa/vulnerable_db.py',
        language: 'python',
        content: `import mysql.connector

def authenticate_user(username, password):
    db = mysql.connector.connect(host="localhost", user="root", password="", database="dvwa")
    cursor = db.cursor()
    
    # Vulnerability: SQL Injection in Login Authentication Bypass
    query = "SELECT * FROM users WHERE user='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    return user
`
      },
      {
        name: 'api_router.js',
        path: 'dvwa/api_router.js',
        language: 'javascript',
        content: `const express = require('express');
const router = express.Router();
const http = require('http');

router.get('/proxy', (req, res) => {
  const targetHost = req.query.url;
  
  // Vulnerability: SSRF via unvalidated HTTP proxy
  http.get(targetHost, (response) => {
    let body = '';
    response.on('data', chunk => body += chunk);
    response.on('end', () => res.send(body));
  });
});

module.exports = router;
`
      }
    ]
  }
];
