import sqlite3
import json


DATABASE_NAME = "talentai.db"


# ==========================================
# 1. CONNECT TO DATABASE
# ==========================================

def get_connection():

    connection = sqlite3.connect(DATABASE_NAME)

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# 2. INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            candidate_name TEXT,

            job_position TEXT,

            email TEXT,

            phone TEXT,

            match_score REAL,

            status TEXT,

            technical_skills REAL,

            job_similarity REAL,

            practical_experience REAL,

            project_experience REAL,

            problem_solving REAL,

            matched_skills TEXT,

            missing_skills TEXT,

            experience_evidence TEXT,

            project_evidence TEXT,

            problem_evidence TEXT,

            explanation TEXT,

            resume_text TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    connection.commit()

    connection.close()


# ==========================================
# 3. SAVE CANDIDATE
# ==========================================

def save_candidate(candidate):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO candidates (

            candidate_name,
            job_position,
            email,
            phone,
            match_score,
            status,
            technical_skills,
            job_similarity,
            practical_experience,
            project_experience,
            problem_solving,
            matched_skills,
            missing_skills,
            experience_evidence,
            project_evidence,
            problem_evidence,
            explanation,
            resume_text

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        candidate["Candidate"],
        candidate["Job Position"],
        candidate["Email"],
        candidate["Phone"],
        candidate["Match Score"],
        candidate["Status"],
        candidate["Technical Skills"],
        candidate["Job Similarity"],
        candidate["Practical Experience"],
        candidate["Project Experience"],
        candidate["Problem-Solving"],

        json.dumps(candidate["Matched Skills"]),
        json.dumps(candidate["Missing Skills"]),

        json.dumps(candidate["Experience Evidence"]),
        json.dumps(candidate["Project Evidence"]),
        json.dumps(candidate["Problem Evidence"]),

        candidate["Explanation"],
        candidate["Resume Text"]

    ))

    connection.commit()

    connection.close()


# ==========================================
# 4. RETRIEVE ALL CANDIDATES
# ==========================================

def get_all_candidates():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM candidates
        ORDER BY match_score DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    candidates = []

    list_columns = [
        "matched_skills",
        "missing_skills",
        "experience_evidence",
        "project_evidence",
        "problem_evidence"
    ]

    for row in rows:

        candidate = dict(row)

        for column in list_columns:

            candidate[column] = json.loads(
                candidate[column] or "[]"
            )

        candidates.append(candidate)

    return candidates


# ==========================================
# 5. DELETE A CANDIDATE
# ==========================================

def delete_candidate(candidate_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM candidates WHERE id = ?",
        (candidate_id,)
    )

    connection.commit()

    connection.close()


# ==========================================
# 6. DATABASE STATISTICS
# ==========================================

def get_candidate_count():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM candidates"
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count