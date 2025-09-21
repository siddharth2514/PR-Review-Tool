
from flask import Flask, render_template, request, redirect, url_for, send_file
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from github import Github
import re
import tempfile
import subprocess
import openai
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
def analyze_pr(pr_url):
    # --- Track PR history (simple in-memory for now) ---
    if not hasattr(analyze_pr, 'history'):
        analyze_pr.history = []

    # Only handle GitHub PRs for now
    github_match = re.match(r'https://github.com/([^/]+)/([^/]+)/pull/(\d+)', pr_url)
    if not github_match:
        return {
            'pr_url': pr_url,
            'pr_title': 'Unsupported PR provider',
            'author': '',
            'repo': '',
            'quality_score': 0,
            'metrics': {},
            'summary': {'strengths': [], 'areas_for_improvement': ['Only GitHub PRs are supported in this demo.']},
            'issues': [],
            'markdown': 'Only GitHub PRs are supported.'
        }
    owner, repo, pr_num = github_match.groups()
    github_token = os.getenv('GITHUB_TOKEN')
    if github_token:
        g = Github(github_token)
    else:
        g = Github()  # fallback to unauthenticated, limited rate
    repo_obj = g.get_repo(f"{owner}/{repo}")
    pr = repo_obj.get_pull(int(pr_num))
    files = list(pr.get_files())
    comments = list(pr.get_review_comments())
    # Advanced metrics
    pep8_total = 0
    pep8_violations = 0
    doc_coverage = 0
    js_total = 0
    js_comment_lines = 0
    js_total_lines = 0
    js_complexity_scores = []
    md_total = 0
    md_heading_lines = 0
    md_total_lines = 0
    todos = 0
    warnings = 0
    strengths = []
    areas = []
    issues = []
    complexity_scores = []
    per_file = []
    changed_files = [f for f in files if f.filename.endswith(('.py','.js','.ts','.md'))]
    for f in changed_files:
        ext = os.path.splitext(f.filename)[1]
        try:
            file_content = repo_obj.get_contents(f.filename, ref=pr.head.ref).decoded_content.decode()
        except Exception:
            file_content = ''
        try:
            base_content = repo_obj.get_contents(f.filename, ref=pr.base.ref).decoded_content.decode()
        except Exception:
            base_content = ''

        # --- Get changed lines (diff) ---
        diff_lines = set()
        for patch_line in (f.patch or '').split('\n'):
            if patch_line.startswith('+') and not patch_line.startswith('+++'):
                diff_lines.add(patch_line[1:].strip())

        # --- Python analysis ---
        if ext == '.py':
            # Cyclomatic complexity using radon
            with tempfile.NamedTemporaryFile('w+', suffix=ext, delete=False) as tmp:
                tmp.write(file_content)
                tmp.flush()
                radon_result = subprocess.run(['radon', 'cc', '-s', tmp.name], capture_output=True, text=True)
                for line in radon_result.stdout.split('\n'):
                    if '(' in line and ')' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            func = parts[3]
                            score = parts[5].strip('()')
                            try:
                                score = int(score)
                                complexity_scores.append(score)
                                if score > 10:
                                    suggestion = ai_suggest_fix(file_content, None, f'High complexity in {func}')
                                    issues.append({
                                        'type': 'warning',
                                        'text': f'High cyclomatic complexity in {func}',
                                        'file': f.path,
                                        'line': None,
                                        'pr_link': pr_url,
                                        'suggestion': suggestion
                                    })
                            except Exception:
                                pass
            # ...existing Python analysis code for doc coverage, TODOs, etc...
            # (You can add the rest of the Python analysis logic here as needed)

        # --- JS/TS analysis ---
        elif ext in ('.js', '.ts'):
            js_total += 1
            lines = file_content.split('\n')
            js_total_lines += len(lines)
            js_comment_lines += sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('/*') or l.strip().startswith('*'))
            # Use ESLint for complexity (if cyclomatic complexity rule enabled)
            with tempfile.NamedTemporaryFile('w+', suffix=ext, delete=False) as tmp:
                tmp.write(file_content)
                tmp.flush()
                result = subprocess.run(['eslint', tmp.name, '-f', 'json'], capture_output=True, text=True)
                try:
                    import json
                    eslint_report = json.loads(result.stdout)
                    for res in eslint_report:
                        for msg in res.get('messages', []):
                            suggestion = ai_suggest_fix(file_content, msg.get('line'), msg.get('message'))
                            issues.append({
                                'type': 'critical' if msg.get('severity', 1) == 2 else 'warning',
                                'text': f"ESLint: {msg.get('message')}",
                                'file': f.filename,
                                'line': msg.get('line'),
                                'pr_link': pr_url,
                                'suggestion': suggestion
                            })
                            # If ESLint message is about complexity, extract score
                            if 'complexity' in msg.get('ruleId', '') and 'value' in msg:
                                try:
                                    js_complexity_scores.append(int(msg['value']))
                                except Exception:
                                    pass
                except Exception:
                    pass

        # --- Markdown analysis ---
        elif ext == '.md':
            md_total += 1
            lines = file_content.split('\n')
            md_total_lines += len(lines)
            md_heading_lines += sum(1 for l in lines if l.strip().startswith('#'))
            with tempfile.NamedTemporaryFile('w+', suffix=ext, delete=False) as tmp:
                tmp.write(file_content)
                tmp.flush()
                result = subprocess.run(['markdownlint', tmp.name, '-j'], capture_output=True, text=True)
                try:
                    import json
                    md_report = json.loads(result.stdout)
                    for msg in md_report:
                        suggestion = ai_suggest_fix(file_content, msg.get('lineNumber'), msg.get('ruleDescription'))
                        issues.append({
                            'type': 'warning',
                            'text': f"Markdownlint: {msg.get('ruleDescription')}",
                            'file': f.filename,
                            'line': msg.get('lineNumber'),
                            'pr_link': pr_url,
                            'suggestion': suggestion
                        })
                except Exception:
                    pass

    # --- Test coverage detection ---
    # (Simple: look for test_*.py or tests/ folder, warn if no test file changed)
    test_files = [f for f in files if 'test' in f.filename or f.filename.startswith('tests/')]
    if not test_files:
        issues.append({
            'type': 'warning',
            'text': 'No test files were changed in this PR. Consider adding or updating tests.',
            'file': '',
            'line': None,
            'pr_link': pr_url,
            'suggestion': 'Add or update tests to cover your changes.'
        })

    # --- Changelog and doc coverage ---
    changelog_files = [f for f in files if 'CHANGELOG' in f.filename or 'CHANGES' in f.filename]
    doc_files = [f for f in files if 'README' in f.filename or 'docs/' in f.filename]
    if not changelog_files:
        issues.append({
            'type': 'warning',
            'text': 'No changelog file was updated in this PR. Consider updating CHANGELOG/CHANGES.',
            'file': '',
            'line': None,
            'pr_link': pr_url,
            'suggestion': 'Document your changes in the changelog.'
        })
    if not doc_files:
        issues.append({
            'type': 'warning',
            'text': 'No documentation file was updated in this PR. Consider updating README or docs/.',
            'file': '',
            'line': None,
            'pr_link': pr_url,
            'suggestion': 'Document your changes in the documentation.'
        })

    # --- Breaking change detection (simple: look for removed functions/classes) ---
    # (Advanced: use semver to suggest version bump)
    # ...could be implemented with AST diff or regex...

    # --- Calculate metrics (ensure quality_score is always set) ---
    total_py = pep8_total if 'pep8_total' in locals() else 0
    pep8_score = int(100 * (1 - (pep8_violations / (total_py * 10) if total_py else 0)))
    # JS/TS comment coverage
    js_comment_coverage = int(100 * js_comment_lines / js_total_lines) if js_total_lines else 0
    js_avg_complexity = int(sum(js_complexity_scores) / len(js_complexity_scores)) if js_complexity_scores else 0
    # Markdown heading coverage (as a proxy for doc coverage)
    md_heading_coverage = int(100 * md_heading_lines / md_total_lines) if md_total_lines else 0
    # Aggregate doc coverage and complexity across all file types
    doc_coverage_val = 0
    avg_complexity = 0
    doc_covs = []
    complexities = []
    if total_py:
        doc_covs.append(int(100 * doc_coverage / total_py))
        if complexity_scores:
            complexities.append(int(sum(complexity_scores) / len(complexity_scores)))
    if js_total:
        doc_covs.append(js_comment_coverage)
        if js_complexity_scores:
            complexities.append(js_avg_complexity)
    if md_total:
        doc_covs.append(md_heading_coverage)
    if doc_covs:
        doc_coverage_val = int(sum(doc_covs) / len(doc_covs))
    if complexities:
        avg_complexity = int(sum(complexities) / len(complexities))
    quality_score = max(pep8_score - 10 * len(issues), 0)

    # --- Historical PR scoring/trends ---
    analyze_pr.history.append({'pr_url': pr_url, 'score': quality_score})
    if len(analyze_pr.history) > 5:
        analyze_pr.history.pop(0)
        try:
            file_content = repo_obj.get_contents(f.path, ref=pr.head.ref).decoded_content.decode()
        except Exception:
            file_content = ''
        try:
            base_content = repo_obj.get_contents(f.path, ref=pr.base.ref).decoded_content.decode()
        except Exception:
            base_content = ''

        # --- Advanced Bug & Security Checks ---
        bug_patterns = [
            (r'\bexcept\s*:\b', 'Bare except detected (should catch specific exceptions)'),
            (r'eval\(', 'Use of eval() is dangerous'),
            (r'exec\(', 'Use of exec() is dangerous'),
            (r'os\.system\(', 'Use of os.system() can be unsafe'),
            (r'subprocess\.Popen\(', 'Use of subprocess.Popen() can be unsafe'),
            (r'pickle\.load\(', 'Untrusted pickle.load() is a security risk'),
            (r'assert\s+\w+\s*==\s*\w+', 'Use of assert for data validation (should raise exception)'),
        ]
        for pat, msg in bug_patterns:
            for m in re.finditer(pat, file_content):
                lineno = file_content[:m.start()].count('\n') + 1
                suggestion = ai_suggest_fix(file_content, lineno, msg)
                issues.append({
                    'type': 'critical' if 'danger' in msg or 'security' in msg else 'warning',
                    'text': f'Bug/Security: {msg}',
                    'file': f.path,
                    'line': lineno,
                    'pr_link': pr_url,
                    'suggestion': suggestion
                })

        # --- PEP8 linting using pycodestyle ---
        with tempfile.NamedTemporaryFile('w+', suffix='.py', delete=False) as tmp:
            tmp.write(file_content)
            tmp.flush()
            result = subprocess.run(['pycodestyle', tmp.name], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n') if result.stdout else []
            pep8_violations += len(lines)
            pep8_total += 1
            for l in lines:
                parts = l.split(':')
                if len(parts) >= 4:
                    lineno = int(parts[1])
                    msg = ':'.join(parts[3:]).strip()
                    suggestion = ai_suggest_fix(file_content, lineno, msg)
                    issues.append({
                        'type': 'warning',
                        'text': f'PEP8: {msg}',
                        'file': f.path,
                        'line': lineno,
                        'pr_link': pr_url,
                        'suggestion': suggestion
                    })

        # --- Pylint for advanced static analysis ---
        with tempfile.NamedTemporaryFile('w+', suffix='.py', delete=False) as tmp:
            tmp.write(file_content)
            tmp.flush()
            result = subprocess.run(['pylint', '--disable=all', '--enable=E,W,C,R', tmp.name, '-rn', '--output-format=text'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ':' in line and ('error' in line.lower() or 'warning' in line.lower() or 'refactor' in line.lower()):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        lineno = int(parts[1])
                        msg = ':'.join(parts[3:]).strip()
                        suggestion = ai_suggest_fix(file_content, lineno, msg)
                        issues.append({
                            'type': 'critical' if 'error' in line.lower() else 'warning',
                            'text': f'Pylint: {msg}',
                            'file': f.path,
                            'line': lineno,
                            'pr_link': pr_url,
                            'suggestion': suggestion
                        })

        # --- Bandit for security analysis ---
        with tempfile.NamedTemporaryFile('w+', suffix='.py', delete=False) as tmp:
            tmp.write(file_content)
            tmp.flush()
            result = subprocess.run(['bandit', '-r', tmp.name, '-f', 'json'], capture_output=True, text=True)
            # Always populate strengths before report generation
            if not strengths or all(not s.strip() for s in strengths):
                strengths.append('No major issues detected in the PR diff.')
            report = {
                'pr_url': pr_url,
                'pr_title': pr.title,
                'author': pr.user.login,
                'repo': f"{owner}/{repo}",
                'quality_score': quality_score,
                'metrics': {
                    'pep8': pep8_score,
                    'complexity': avg_complexity,
                    'doc_coverage': doc_coverage_val,
                    'todos': todos,
                    'warnings': warnings
                },
                'summary': {
                    'strengths': strengths,
                    'areas_for_improvement': areas
                },
                'issues': issues,
                'markdown': ''
            }
            for line in radon_result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        func = parts[3]
                        score = parts[5].strip('()')
                        try:
                            score = int(score)
                            complexity_scores.append(score)
                            if score > 10:
                                suggestion = ai_suggest_fix(file_content, None, f'High complexity in {func}')
                                issues.append({
                                    'type': 'warning',
                                    'text': f'High cyclomatic complexity in {func}',
                                    'file': f.path,
                                    'line': None,
                                    'pr_link': pr_url,
                                    'suggestion': suggestion
                                })
                        except Exception:
                            pass
    # removed stray except/pass

        # --- Docstring and Comment Coverage ---
        doc_count = 0
        func_count = 0
        removed_docstrings = 0
        missing_docstrings = 0
        for line in file_content.split('\n'):
            if line.strip().startswith('def ') or line.strip().startswith('class '):
                func_count += 1
                idx = file_content.split('\n').index(line)
                next_lines = file_content.split('\n')[idx+1:idx+3]
                if not any('"""' in l or "'''" in l for l in next_lines):
                    missing_docstrings += 1
                    suggestion = ai_suggest_fix(file_content, idx+2, 'Missing docstring')
                    issues.append({
                        'type': 'warning',
                        'text': f'Missing docstring for: {line.strip()}',
                        'file': f.path,
                        'line': idx+2,
                        'pr_link': pr_url,
                        'suggestion': suggestion
                    })
            if '"""' in line or "'''" in line:
                doc_count += 1
        for line in base_content.split('\n'):
            if (line.strip().startswith('def ') or line.strip().startswith('class ')) and ('"""' in line or "'''" in line):
                if line not in file_content:
                    removed_docstrings += 1
                    suggestion = ai_suggest_fix(base_content, None, 'Docstring removed')
                    issues.append({
                        'type': 'critical',
                        'text': f'Docstring removed for: {line.strip()}',
                        'file': f.path,
                        'line': None,
                        'pr_link': pr_url,
                        'suggestion': suggestion
                    })
        doc_coverage += doc_count

        # --- TODO/FIXME ---
        todo_count = file_content.count('TODO') + file_content.count('FIXME')
        todos += todo_count
        if todo_count > 0:
            suggestion = ai_suggest_fix(file_content, None, 'TODO or FIXME found')
            issues.append({
                'type': 'warning',
                'text': f'TODO/FIXME found in {f.path}',
                'file': f.path,
                'line': None,
                'pr_link': pr_url,
                'suggestion': suggestion
            })

        # --- Long Function Detection ---
        for m in re.finditer(r'def\s+\w+\s*\(.*\):', file_content):
            start = m.start()
            func_header_lineno = file_content[:start].count('\n') + 1
            func_body = file_content[start:].split('\n')
            body_lines = 0
            for l in func_body[1:]:
                if l.strip() == '' or l.startswith(' '):
                    body_lines += 1
                else:
                    break
            if body_lines > 50:
                suggestion = ai_suggest_fix(file_content, func_header_lineno, 'Function >50 lines')
                issues.append({
                    'type': 'warning',
                    'text': f'Function at line {func_header_lineno} is longer than 50 lines',
                    'file': f.path,
                    'line': func_header_lineno,
                    'pr_link': pr_url,
                    'suggestion': suggestion
                })
    # Add PR review comments as issues
    for c in comments:
        suggestion = ai_suggest_fix(c.body, None, 'PR review comment')
        issues.append({
            'type': 'critical' if 'bug' in c.body.lower() else 'warning',
            'text': c.body,
            'file': c.path,
            'line': c.original_position,
            'pr_link': c.html_url,
            'suggestion': suggestion
        })
    # Summarize all issues into areas for improvement
    if not issues:
        strengths.append('No issues detected in PR diff.')
        areas.append('Double-check that all changes are covered by tests and documentation.')
        issues.append({
            'type': 'best-practice',
            'text': 'No code issues detected. Consider reviewing test coverage, documentation, and changelog accuracy for this PR.',
            'file': '',
            'line': None,
            'pr_link': pr_url,
            'suggestion': 'Even for non-code changes, ensure tests and docs are up to date.'
        })
    else:
        seen = set()
        for issue in issues:
            summary = issue['text']
            if summary not in seen:
                areas.append(summary)
                seen.add(summary)
    # Calculate metrics
    total_py = pep8_total
    pep8_score = int(100 * (1 - (pep8_violations / (total_py * 10) if total_py else 0)))
    doc_coverage = int(100 * doc_coverage / total_py) if total_py else 0
    avg_complexity = int(sum(complexity_scores) / len(complexity_scores)) if complexity_scores else 0
    quality_score = max(pep8_score - 10 * len(issues), 0)
    report = {
        'pr_url': pr_url,
        'pr_title': pr.title,
        'author': pr.user.login,
        'repo': f"{owner}/{repo}",
        'quality_score': quality_score,
        'metrics': {
            'pep8': pep8_score,
            'complexity': avg_complexity,
            'doc_coverage': doc_coverage,
            'todos': todos,
            'warnings': warnings
        },
        'summary': {
            'strengths': strengths,
            'areas_for_improvement': areas
        },
        'issues': issues
    }
    # Generate Markdown for the report
    md = f"""# PR Review Report\n**Title:** {report['pr_title']}\n**Repository:** {report['repo']}\n**Author:** {report['author']}\n**Quality Score:** {report['quality_score']}/100\n\n## Strengths\n"""
    for s in report['summary']['strengths']:
        md += f"- {s}\n"
    md += "\n## Areas for Improvement\n"
    for s in report['summary']['areas_for_improvement']:
        md += f"- {s}\n"
    md += "\n## AI-Powered Review Comments\n"
    for issue in report['issues']:
        md += f"- {issue['text']}\n"
    report['markdown'] = md
    return report

# AI suggestion helper
def ai_suggest_fix(code, lineno, msg):
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        return 'Set OPENAI_API_KEY in .env for AI suggestions.'
    openai.api_key = api_key
    prompt = f"You are an expert code reviewer. Given the following code and issue, suggest a concrete fix or improvement.\n\nCode:\n{code}\n\nIssue: {msg}\n"
    if lineno:
        prompt += f"Line: {lineno}\n"
    prompt += "\nSuggestion:"
    try:
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=80,
            temperature=0.2
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"AI suggestion unavailable: {e}"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        pr_url = request.form.get('pr_url')
        report = analyze_pr(pr_url)
        return render_template('report.html', pr_url=pr_url, report=report)
    return render_template('index.html')

# PDF download route
@app.route('/download_pdf', methods=['POST'])
def download_pdf():
    pr_url = request.form.get('pr_url')
    report = analyze_pr(pr_url)
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    y = 750
    p.setFont("Helvetica-Bold", 16)
    p.drawString(30, y, "PR Review Report")
    y -= 30
    p.setFont("Helvetica", 12)
    p.drawString(30, y, f"Title: {report['pr_title']}")
    y -= 20
    p.drawString(30, y, f"Repository: {report['repo']}")
    y -= 20
    p.drawString(30, y, f"Author: {report['author']}")
    y -= 20
    p.drawString(30, y, f"Quality Score: {report['quality_score']}/100")
    y -= 30
    p.setFont("Helvetica-Bold", 12)
    p.drawString(30, y, "Strengths:")
    y -= 18
    p.setFont("Helvetica", 12)
    for s in report['summary']['strengths']:
        p.drawString(40, y, f"- {s}")
        y -= 16
    y -= 8
    p.setFont("Helvetica-Bold", 12)
    p.drawString(30, y, "Areas for Improvement:")
    y -= 18
    p.setFont("Helvetica", 12)
    for s in report['summary']['areas_for_improvement']:
        p.drawString(40, y, f"- {s}")
        y -= 16
    y -= 8
    p.setFont("Helvetica-Bold", 12)
    p.drawString(30, y, "AI-Powered Review Comments:")
    y -= 18
    p.setFont("Helvetica", 12)
    for issue in report['issues']:
        p.drawString(40, y, f"- {issue['text']}")
        y -= 16
        if y < 50:
            p.showPage()
            y = 750
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="pr-review-report.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)
