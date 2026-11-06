import re
from pypdf import PdfReader


# ==========================================
# 1. EXTRACT TEXT FROM PDF
# ==========================================

def extract_text_from_pdf(file):

    try:
        reader = PdfReader(file)

        text = ""

        for page in reader.pages:

            extracted = page.extract_text()

            if extracted:
                text += extracted + "\n"

        return text.strip()

    except Exception as e:

        print(f"PDF extraction error: {e}")

        return ""


# ==========================================
# 2. CLEAN RESUME TEXT
# ==========================================

def clean_text(text):

    text = text.lower()

    # Remove email addresses
    text = re.sub(
        r'[\w.+-]+@[\w-]+\.[\w.-]+',
        ' ',
        text
    )

    # Remove phone numbers
    text = re.sub(
        r'\+?\d[\d\s()-]{8,15}\d',
        ' ',
        text
    )

    # Remove special characters
    text = re.sub(
        r'[^a-z0-9+#.\s]',
        ' ',
        text
    )

    # Remove extra spaces
    text = re.sub(
        r'\s+',
        ' ',
        text
    )

    return text.strip()


# ==========================================
# 3. EXTRACT EMAIL
# ==========================================

def extract_email(text):

    pattern = r'[\w.+-]+@[\w-]+\.[\w.-]+'

    match = re.search(pattern, text)

    return match.group(0) if match else "Not Found"


# ==========================================
# 4. EXTRACT PHONE NUMBER
# ==========================================

def extract_phone(text):

    pattern = r'\+?\d[\d\s()-]{8,15}\d'

    match = re.search(pattern, text)

    return match.group(0) if match else "Not Found"


# ==========================================
# 5. EXTRACT TECHNICAL SKILLS
# ==========================================

def extract_skills(text):

    skills = [

        "Python",
        "Java",
        "C++",
        "C",
        "JavaScript",

        "HTML",
        "CSS",
        "SQL",

        "Machine Learning",
        "Deep Learning",
        "Artificial Intelligence",
        "Data Science",

        "React",
        "Node.js",
        "Django",
        "Flask",
        "Streamlit",

        "TensorFlow",
        "PyTorch",
        "Pandas",
        "NumPy",
        "Scikit-learn",

        "Excel",
        "Power BI",
        "Tableau",

        "Git",
        "GitHub",

        "AWS",
        "Azure",
        "Cloud Computing",

        "Data Structures",
        "Algorithms",
        "OOP",
        "Computer Networks",
        "Operating Systems",

        "MongoDB",
        "MySQL",
        "PostgreSQL",

        "REST API",
        "Docker",
        "Linux"
    ]

    found_skills = []

    text = text.lower()

    for skill in skills:

        pattern = (
            r'(?<!\w)'
            + re.escape(skill.lower())
            + r'(?!\w)'
        )

        if re.search(pattern, text):

            found_skills.append(skill)

    return found_skills


# ==========================================
# 6. EXTRACT EDUCATION INFORMATION
# ==========================================

def extract_education(text):

    education_keywords = [

        "bachelor",
        "master",
        "b.tech",
        "m.tech",
        "b.e",
        "m.e",
        "bca",
        "mca",
        "b.sc",
        "m.sc",
        "computer science",
        "engineering",
        "diploma",
        "university",
        "college"
    ]

    found = []

    text = text.lower()

    for keyword in education_keywords:

        if keyword in text:

            found.append(keyword.title())

    return list(dict.fromkeys(found))


# ==========================================
# 7. EXTRACT EXPERIENCE INDICATORS
# ==========================================

def extract_experience_indicators(text):

    keywords = [

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

    text = text.lower()

    found = []

    for keyword in keywords:

        if keyword in text:

            found.append(keyword.title())

    return found


# ==========================================
# 8. EXTRACT PROJECT INDICATORS
# ==========================================

def extract_project_indicators(text):

    keywords = [

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

    text = text.lower()

    found = []

    for keyword in keywords:

        if keyword in text:

            found.append(keyword.title())

    return found