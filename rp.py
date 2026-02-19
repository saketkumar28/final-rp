import streamlit as st
import pdfplumber
from PIL import Image
import pytesseract
import re
import io

def extract_text_pdfplumber(file_bytes):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                t = page.extract_text(x_tolerance=2, y_tolerance=3)
                if t:
                    text += t + "\n"
    except Exception:
        pass
    return text.replace('\xa0', ' ').strip()

def is_scanned_pdf(file_bytes):
    return len(extract_text_pdfplumber(file_bytes)) < 80

def ocr_pdf(file_bytes):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                img = page.to_image(resolution=300).original
                text += pytesseract.image_to_string(img, lang="eng") + "\n"
    except Exception:
        pass
    return text.strip()

def ocr_image_file(file_bytes):
    try:
        img = Image.open(io.BytesIO(file_bytes))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        return pytesseract.image_to_string(img, lang="eng").strip()
    except Exception:
        return ""

def get_text(file_bytes, ext):
    if ext == "pdf":
        if is_scanned_pdf(file_bytes):
            return ocr_pdf(file_bytes)
        return extract_text_pdfplumber(file_bytes)
    return ocr_image_file(file_bytes)

def extract_all_hyperlinks(file_bytes):
    urls = []
    def to_str(val):
        if isinstance(val, bytes): return val.decode("utf-8", errors="ignore")
        if isinstance(val, str): return val
        return ""
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                for link in page.hyperlinks:
                    uri = to_str(link.get("uri", "")).strip()
                    if uri: urls.append(uri)
    except Exception:
        pass
    return list(set(urls))

DURATION_PATTERN = re.compile(
    r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4}\s*[-–—]\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4}\b|'
    r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s*\d{4}\s*[-–—]\s*(?:Present|Current|Ongoing|Now)\b|'
    r'\b\d{4}\s*[-–—]\s*\d{4}\b',
    re.IGNORECASE
)

GRADE_PATTERN = re.compile(
    r'(?:cgpa|gpa|cpi|sgpa)\s*[:\-]?\s*(\d+\.\d+)|(\d+\.\d+)\s*(?:cgpa|gpa)|(\d{2,3}\.?\d*)\s*%',
    re.IGNORECASE
)

def get_section_text(text, header_regex):
    headers_pattern = r'\n\s*(?:[IVX\d]+[\.\-\s]+)?(?:education|academic|qualifications|experience|employment|work history|projects|skills|technical skills|technologies|achievements|certifications|interests|profile|objective|summary|positions of responsibility|leadership|activities)\b.*?\n'
    
    header_search = r'\b(?:[IVX\d]+[\.\-\s]+)?(' + header_regex + r')\b'
    match = re.search(header_search, text, re.IGNORECASE)
    if not match: return ""
    
    start_idx = match.end()
    rest_of_text = text[start_idx:]
    
    next_match = re.search(headers_pattern, '\n' + rest_of_text, re.IGNORECASE)
    if next_match:
        end_idx = next_match.start()
        return rest_of_text[:end_idx].strip()
    return rest_of_text.strip()

def extract_name(text):
    NON_NAME = re.compile(r'resume|curriculum|cv|objective|skills|contact|email|phone|github|linkedin|address', re.IGNORECASE)
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    for line in lines[:8]:
        if NON_NAME.search(line): continue
        words = line.split()
        if 2 <= len(words) <= 5 and all(re.match(r"^[A-Za-z'\-\.]+$", w) for w in words):
            return line
    return ""

def extract_emails(text):
    return list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)))

def extract_phones(text):
    clean_text = re.sub(r'[\(\)\[\]\{\}]', ' ', text)
    pattern = re.compile(r'(?:(?:\+|0{0,2})91[\s-]?)?([6789]\d{2}[\s-]?\d{3}[\s-]?\d{4})')
    matches = pattern.findall(clean_text)
    
    unique = []
    for m in matches:
        digits = re.sub(r'\D', '', m)
        if len(digits) == 10:
            formatted = f"+91 {digits}"
            if formatted not in unique: unique.append(formatted)
    return unique

def extract_profile_link(text, all_hyperlinks, domain, pattern):
    for url in all_hyperlinks:
        if domain in url.lower(): return url if url.startswith("http") else "https://" + url
    m = pattern.search(text)
    if m: return m.group(0) if m.group(0).startswith("http") else "https://" + m.group(0)
    return None

def extract_skills(text):
    skills_text = get_section_text(text, r'technical\s+skills|skills|technologies|tech\s+stack')
    if not skills_text: return ""
    
    skills_text = re.sub(r'[A-Za-z]+:\s*', ',', skills_text)
    raw_skills = re.split(r'[,|•·▪▸\*\n]', skills_text)
    
    cleaned = [re.sub(r'^[^\w\+]+|[^\w\+]+$', '', s.strip()) for s in raw_skills]
    cleaned = [s for s in cleaned if 1 < len(s) < 40]
    
    unique = []
    for c in cleaned:
        if c.lower() not in [u.lower() for u in unique]: unique.append(c)
    return ", ".join(unique)

# --- THE FIX: FLAWLESS EDUCATION PARSER ---
def extract_education(text):
    edu_text = get_section_text(text, r'education|academic|qualifications|educational background')
    result = {"phd": None, "pg": None, "ug": None, "class12": None, "class10": None}
    
    # Fully patched to explicitly catch standalone parenthesis formats
    DEGREE_PATTERNS = {
        'phd': re.compile(r'(?i)\bph\.?\s*d\.?\b|\bdoctorate\b'),
        'pg': re.compile(r'(?i)\bm\.?\s*tech\b|\bm\.?\s*e\.?\b|\bmba\b|\bm\.?\s*s\.?\b|\bm\.?\s*sc\.?\b|\bmca\b|\bmaster\b|\bpost\s*grad\b'),
        'ug': re.compile(r'(?i)\bb\.?\s*tech\b|\bb\.?\s*e\.?\b|\bbsc\b|\bb\.?\s*sc\.?\b|\bbca\b|\bb\.?\s*com\b|\bbba\b|\bbachelor\b|\bunder\s*grad\b'),
        'class12': re.compile(r'(?i)\b12th\b|\bxii\b|\(xii\)|\bclass\s*12\b|\bhsc\b|\bintermediate\b|\+2|\bhigher\s*secondary\b'),
        'class10': re.compile(r'(?i)\b10th\b|\bclass\s*10\b|\bclass\s*x\b|\(x\)|\bssc\b|\bmatriculation\b|\bx\s*(?:th|std)\b|\bsecondary\s*school\b|\bhigh\s*school\b'),
    }

    INSTITUTION_KEYWORDS = re.compile(r'(?i)\b(university|college|school|institute|academy|iit|nit|iiit|bits)\b')

    if not edu_text: return result
    lines = [l.strip() for l in edu_text.split('\n') if l.strip()]
    used_indices = set()

    for level, pattern in DEGREE_PATTERNS.items():
        for i, line in enumerate(lines):
            if i in used_indices: continue
            
            if pattern.search(line):
                used_indices.add(i)
                context_lines = [line]
                
                # Context grabber
                for j in range(1, 4):
                    if i + j < len(lines) and i + j not in used_indices and not any(p.search(lines[i+j]) for p in DEGREE_PATTERNS.values()):
                        context_lines.append(lines[i+j])
                        used_indices.add(i+j)
                    else:
                        break
                
                full_context = " | ".join(context_lines)

                grade = None
                grade_match = GRADE_PATTERN.search(full_context)
                if grade_match:
                    raw_grade = next((g for g in grade_match.groups() if g), None)
                    if raw_grade:
                        grade = f"{raw_grade} CGPA" if float(raw_grade) <= 10 else f"{raw_grade}%"

                duration = None
                dur_match = DURATION_PATTERN.search(full_context)
                if dur_match:
                    duration = dur_match.group(0).strip()
                else:
                    year_match = re.search(r'\b(19|20)\d{2}\b', full_context)
                    if year_match: duration = year_match.group(0)

                clean_text = full_context
                if grade_match: clean_text = clean_text.replace(grade_match.group(0), '')
                if duration: clean_text = clean_text.replace(duration, '')
                
                clean_text = re.sub(r'\(\s*(?:CGPA|GPA|%|Marks)?\s*[:\-]?\s*(?:/\s*10|100)?\s*\)', '', clean_text, flags=re.IGNORECASE)
                clean_text = re.sub(r'(?i)cgpa|gpa', '', clean_text)
                
                # FIX: Splitting by comma so "Asansol Engineering College" perfectly detaches from "B.Tech"
                parts = [p.strip() for p in re.split(r'\||\s{3,}|\n|,', clean_text) if p.strip()]
                
                degree = ""
                institution = ""
                
                for part in parts:
                    if INSTITUTION_KEYWORDS.search(part):
                        institution = part
                        break
                
                for part in parts:
                    if pattern.search(part) and part != institution:
                        degree = part
                        break
                
                if not degree:
                    match = pattern.search(full_context)
                    degree = match.group(0) if match else ""

                # Eradicate residual characters from the degree and institution
                degree = re.sub(r'^[^a-zA-Z0-9+]+|[^a-zA-Z0-9+]+$', '', degree).strip()
                if institution:
                    # Snip off lingering (XII) or (X) from the school name
                    institution = re.sub(r'(?i)\s*\((?:xii|x|12th|10th)\)\s*$', '', institution)
                    institution = re.sub(r'^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$', '', institution).strip()
                    # Strip lingering geo-locations
                    institution = re.sub(r'(?i)\s*(WB|West Bengal|India|Asansol)$', '', institution).strip(' ,-')
                    
                degree = re.sub(r'(?i)\s*(WB|West Bengal|India|Asansol)$', '', degree).strip(' ,-')

                result[level] = {
                    "degree": degree.upper() if len(degree) <= 4 else degree,
                    "institution": institution if institution else None,
                    "duration": duration,
                    "grade": grade
                }
                break

    return result

def extract_projects(text, all_hyperlinks):
    proj_text = get_section_text(text, r'projects|academic projects|personal projects')
    if not proj_text: return []
    
    lines = [l.strip() for l in proj_text.split('\n') if l.strip()]
    projects = []
    current_proj = None
    
    for line in lines:
        if re.match(r'^[\-\•\*\–]', line):
            if current_proj:
                current_proj["points"].append(re.sub(r'^[\-\•\*\–]\s*', '', line))
        elif len(line) > 5 and "github.com" not in line.lower() and "live" not in line.lower():
            if current_proj:
                projects.append(current_proj)
            current_proj = {"name": line, "duration": None, "github": None, "points": []}
            
    if current_proj:
        projects.append(current_proj)
        
    github_links = [l for l in all_hyperlinks if 'github.com' in l.lower()]
    
    formatted_projects = []
    for p in projects:
        filtered_points = [pt for pt in p["points"] if not re.search(r'\b(Live\s*\|\s*GitHub|Live|GitHub)\b', pt, re.IGNORECASE)]
        points_dict = {chr(97 + i): pt for i, pt in enumerate(filtered_points)}
        
        proj_github = None
        for link in github_links:
            words = re.sub(r'[^a-zA-Z0-9]', ' ', p["name"].lower()).split()
            if any(w in link.lower() for w in words if len(w) > 4):
                proj_github = link
                break
                
        combined_text = p["name"] + " " + " ".join(filtered_points)
        dur_match = DURATION_PATTERN.search(combined_text)
        
        formatted_projects.append({
            "name": DURATION_PATTERN.sub('', p["name"]).strip(' |,-'),
            "duration": dur_match.group(0).strip() if dur_match else None,
            "github": proj_github,
            "points": points_dict
        })
    return formatted_projects

def fix_squished_text(text):
    if " " not in text and len(text) > 10:
        text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
        text = re.sub(r'([a-zA-Z])(\d)', r'\1 \2', text)
        text = re.sub(r'(\d)([a-zA-Z])', r'\1 \2', text)
    return text

def extract_achievements(text):
    ach_text = get_section_text(text, r'achievements?|scholastic achievements?|awards?|honors?|recognitions?')
    if not ach_text: return {"points": {}}
    
    lines = [l.strip() for l in ach_text.split('\n') if l.strip()]
    points = []
    
    for line in lines:
        cleaned = re.sub(r'^[\-\•\*\–\d\.]+\s*', '', line).strip()
        if cleaned and "github.com" not in cleaned.lower() and "linkedin.com" not in cleaned.lower():
            cleaned = fix_squished_text(cleaned)
            points.append(cleaned)
            
    formatted_points = {chr(97 + i): pt for i, pt in enumerate(points) if i < 26}
    return {"points": formatted_points}

def extract_responsibilities(text):
    resp_text = get_section_text(text, r'positions? of responsibility|leadership(?:[\s&]*activities)?|activities|por|responsibilities')
    if not resp_text: return {"points": {}}
    
    lines = [l.strip() for l in resp_text.split('\n') if l.strip()]
    points = []
    
    for line in lines:
        cleaned = re.sub(r'^[\-\•\*\–\d\.]+\s*', '', line).strip()
        if cleaned and not re.match(r'^&?\s*activities$', cleaned, re.IGNORECASE):
            cleaned = fix_squished_text(cleaned)
            points.append(cleaned)
            
    formatted_points = {chr(97 + i): pt for i, pt in enumerate(points) if i < 26}
    return {"points": formatted_points}

def parse_resume(file_bytes, ext):
    text = get_text(file_bytes, ext)
    all_hyperlinks = extract_all_hyperlinks(file_bytes) if ext == "pdf" else []
    
    return {
        "name": extract_name(text),
        "emails": extract_emails(text),
        "phone_numbers": extract_phones(text),
        "linkedin": extract_profile_link(text, all_hyperlinks, "linkedin.com", re.compile(r'(?:https?://)?(?:www\.)?linkedin\.com/in/[\w\-_%]+', re.IGNORECASE)),
        "github": extract_profile_link(text, all_hyperlinks, "github.com", re.compile(r'(?:https?://)?(?:www\.)?github\.com/[\w\-]+(?:/[\w\-\.]+)*', re.IGNORECASE)),
        "skills": extract_skills(text),
        "education": extract_education(text),
        "projects": extract_projects(text, all_hyperlinks),
        "achievements": extract_achievements(text),
        "responsibilities": extract_responsibilities(text)
    }

st.title("Resume Parser - Production (Gold Master v2)")
uploaded = st.file_uploader("Upload Resume (PDF, JPG, PNG)", type=["pdf", "jpg", "jpeg", "png"], key="resume_uploader")
if uploaded:
    if st.button("Parse Resume"):
        with st.spinner("Extracting all information..."):
            ext = uploaded.name.rsplit(".", 1)[-1].lower()
            file_bytes = uploaded.read()
            result = parse_resume(file_bytes, ext)
        st.success("✅ Parsing Complete!")
        st.json(result)