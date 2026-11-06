import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from utils.resume_parser import (
    extract_skills,
    extract_experience_indicators,
    extract_project_indicators
)


# ==========================================
# 1. TEXT PREPROCESSING
# ==========================================

def preprocess_text(text):

    text = text.lower()

    text = re.sub(r'[^a-z0-9+#.\s]', ' ', text)

    text = re.sub(r'\s+', ' ', text)

    return text.strip()


# ==========================================
# 2. TF-IDF AND COSINE SIMILARITY
# ==========================================

def calculate_similarity(resume_text, job_description):

    resume_text = preprocess_text(resume_text)
    job_description = preprocess_text(job_description)

    if not resume_text or not job_description:
        return 0

    vectorizer = TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        sublinear_tf=True
    )

    try:

        vectors = vectorizer.fit_transform([
            resume_text,
            job_description
        ])

        similarity = cosine_similarity(
            vectors[0:1],
            vectors[1:2]
        )[0][0]

        return round(similarity * 100, 2)

    except ValueError:

        return 0


# ==========================================
# 3. EVIDENCE SCORING
# ==========================================

def calculate_evidence_score(text, keywords):

    text = preprocess_text(text)

    found = []

    for keyword in keywords:

        pattern = (
            r'(?<!\w)'
            + re.escape(keyword.lower())
            + r'(?!\w)'
        )

        if re.search(pattern, text):

            found.append(keyword)

    if not keywords:
        return 0, []

    score = (
        len(found) / len(keywords)
    ) * 100

    return round(score, 2), found


# ==========================================
# 4. MAIN RESUME ANALYSIS
# ==========================================

def analyze_resume(resume_text, job_description):

    if not resume_text.strip():
        raise ValueError("Resume text is empty.")

    if not job_description.strip():
        raise ValueError("Job description is empty.")

    # Technical skill assessment

    candidate_skills = extract_skills(resume_text)

    required_skills = extract_skills(job_description)

    candidate_skill_set = {
        skill.lower() for skill in candidate_skills
    }

    matched_skills = [
        skill for skill in required_skills
        if skill.lower() in candidate_skill_set
    ]

    missing_skills = [
        skill for skill in required_skills
        if skill.lower() not in candidate_skill_set
    ]

    if required_skills:

        skill_score = (
            len(matched_skills) /
            len(required_skills)
        ) * 100

    else:

        skill_score = 0

    skill_score = round(skill_score, 2)

    # Resume and job similarity

    similarity_score = calculate_similarity(
        resume_text,
        job_description
    )

    # Practical experience indicators

    experience_keywords = [

        "internship",
        "work experience",
        "professional experience",
        "employment",
        "worked as",
        "developer",
        "engineer",
        "team leader",
        "freelance"
    ]

    experience_score, experience_evidence = (
        calculate_evidence_score(
            resume_text,
            experience_keywords
        )
    )

    # Project indicators

    project_keywords = [

        "project",
        "developed",
        "built",
        "implemented",
        "designed",
        "application",
        "system",
        "deployed",
        "github"
    ]

    project_score, project_evidence = (
        calculate_evidence_score(
            resume_text,
            project_keywords
        )
    )

    # Problem-solving indicators

    problem_keywords = [

        "problem solving",
        "optimized",
        "debugged",
        "tested",
        "improved",
        "analyzed",
        "solution",
        "automation",
        "performance"
    ]

    problem_score, problem_evidence = (
        calculate_evidence_score(
            resume_text,
            problem_keywords
        )
    )

    # ==========================================
    # 5. WEIGHTED FINAL SCORE
    # ==========================================

    final_score = (

        skill_score * 0.30 +

        similarity_score * 0.25 +

        experience_score * 0.20 +

        project_score * 0.15 +

        problem_score * 0.10

    )

    final_score = round(final_score, 2)

    # ==========================================
    # 6. CANDIDATE CLASSIFICATION
    # ==========================================

    if final_score >= 80:

        status = "Strong Match"

    elif final_score >= 60:

        status = "Potential Match"

    elif final_score >= 40:

        status = "Average Match"

    else:

        status = "Weak Match"

    # ==========================================
    # 7. RETURN COMPLETE ANALYSIS
    # ==========================================

    return {

        "candidate_skills": candidate_skills,

        "required_skills": required_skills,

        "matched_skills": matched_skills,

        "missing_skills": missing_skills,

        "match_score": final_score,

        "status": status,

        "skill_score": skill_score,

        "similarity_score": similarity_score,

        "experience_score": experience_score,

        "project_score": project_score,

        "problem_score": problem_score,

        "experience_evidence": experience_evidence,

        "project_evidence": project_evidence,

        "problem_evidence": problem_evidence

    }