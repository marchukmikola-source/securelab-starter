"""Export verified LR06 PDF/source ZIP outside Git, without modifying tracked files.

--preview permits visual QA before creating the immutable tag. It is visibly marked
and does not create a submission ZIP. Final export requires an annotated v1.0.0.
"""
import argparse
import datetime
import hashlib
import html
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, check=True).stdout.decode('utf-8').strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--verification', default='tmp/lab06/release/verification.json')
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    if output == ROOT or ROOT in output.parents:
        raise SystemExit('Output directory must be outside the Git project.')
    if git('status', '--porcelain=v1', '-uall'):
        raise SystemExit('Export requires a clean release worktree.')
    proof_path = (ROOT / args.verification).resolve()
    proof = json.loads(proof_path.read_text(encoding='utf-8'))
    commit = git('rev-parse', 'HEAD')
    assert proof['status'] == 'PASS' and proof['checks']['verified-git-state']['commit'] == commit
    assert proof['checks']['verified-git-state']['cleanBefore'] and proof['checks']['verified-git-state']['cleanAfter']
    assert int(proof['checks']['tests']['failed']) == 0 and int(proof['checks']['tests']['notExecuted']) == 0
    if not args.preview:
        assert git('cat-file', '-t', 'v1.0.0') == 'tag', 'v1.0.0 must be annotated.'
        assert git('rev-list', '-n', '1', 'v1.0.0') == commit
    output.mkdir(parents=True, exist_ok=True)
    pdf_path = output / ('security-review-preview.pdf' if args.preview else 'security-review.pdf')
    build_pdf(pdf_path, proof, commit, args.preview)
    if args.preview:
        print('Preview PDF created outside Git; tag not required; not a submission.')
        return
    tree_paths = subprocess.run(['git', 'ls-tree', '-rz', '--name-only', 'v1.0.0'],
                                cwd=ROOT, check=True, capture_output=True).stdout.decode('utf-8')
    files = tree_paths.rstrip('\0').split('\0')
    # Legacy binary reports and raw old TRX are unnecessary for reproducing LR06.
    omitted = [name for name in files if name.lower().endswith(('.docx', '.trx', '.bundle', '.log'))]
    included = [name for name in files if name not in omitted]
    archive = output / 'security-review-source.zip'
    entries = []
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name in included:
            data = subprocess.run(['git', 'show', f'{commit}:{name}'], cwd=ROOT, check=True, capture_output=True).stdout
            package.writestr('securelab/' + name, data)
            entries.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest()})
    assert zipfile.ZipFile(archive).testzip() is None
    shutil.copyfile(proof_path, output / 'release-verification.json')
    for name in ('dependency-audit.txt', 'secret-review.json', 'secret-matches.csv'):
        shutil.copyfile(proof_path.parent / name, output / name)
    screenshots = proof_path.parent / 'screenshots'
    if screenshots.is_dir():
        shutil.copytree(screenshots, output / 'screenshots', dirs_exist_ok=True)
    manifest = {'exportedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'verifiedCommit': commit, 'annotatedTag': 'v1.0.0', 'tagObject': git('rev-parse', 'v1.0.0'),
        'tree': git('rev-parse', 'HEAD^{tree}'), 'finalRun': 'PASS', 'tests': proof['checks']['tests']['total'],
        'delivery': 'local private ZIP fallback; remote privacy/permission not confirmed; no push/Moodle upload',
        'sourceArchive': {'files': entries, 'omittedInheritedBinaryReportsOrRawTrx': omitted},
        'pdfSources': pdf_sources(), 'credentials': 'runtime password/cookie/CSRF/stamp values omitted'}
    (output / 'submission-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    checksums = [f'{sha256(file)}  {file.name}' for file in sorted(output.iterdir())
                 if file.is_file() and file.name not in {'SHA256SUMS.txt', 'security-review-preview.pdf'}]
    checksums += [f'Git commit: {commit}', f'Annotated tag object: {manifest["tagObject"]}', 'Tag: v1.0.0']
    (output / 'SHA256SUMS.txt').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
    assert not git('status', '--porcelain=v1', '-uall'), 'Export changed source tree.'
    print(json.dumps({'result': 'PASS', 'verifiedCommit': commit, 'pdf': str(pdf_path),
                      'zip': str(archive), 'sourceFiles': len(included)}, ensure_ascii=False))


def pdf_sources():
    return ['docs/security-review.md', 'docs/threat-model.md',
            'docs/findings/F-01-cookie-csrf.md', 'docs/findings/F-02-error-path-headers.md',
            'docs/findings/F-03-concurrent-triage.md', 'docs/advanced-variant-proposal.md',
            'docs/evidence/lab06-advanced-approval.md', 'docs/lab-06-regression-pack.md',
            'docs/lab-06-stage4.md', 'docs/lab-06-defense.md']


def build_pdf(path, proof, commit, preview):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, LongTable, TableStyle, Image
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
    font_dir = Path('C:/Windows/Fonts')
    for name, file in [('Body', 'arial.ttf'), ('BodyBold', 'arialbd.ttf'), ('BodyItalic', 'ariali.ttf')]:
        pdfmetrics.registerFont(TTFont(name, str(font_dir / file)))
    pdfmetrics.registerFontFamily('Body', normal='Body', bold='BodyBold', italic='BodyItalic', boldItalic='BodyBold')
    width = A4[0] - 84
    styles = {
        'body': ParagraphStyle('body', fontName='Body', fontSize=9, leading=12.5, spaceAfter=5, splitLongWords=True),
        'small': ParagraphStyle('small', fontName='Body', fontSize=7.4, leading=10, spaceAfter=3, splitLongWords=True),
        'code': ParagraphStyle('code', fontName='Body', fontSize=7.3, leading=10, backColor=colors.HexColor('#f1f5f9'), spaceAfter=4, splitLongWords=True),
        'h1': ParagraphStyle('h1', fontName='BodyBold', fontSize=18, leading=22, spaceBefore=6, spaceAfter=12, keepWithNext=True),
        'h2': ParagraphStyle('h2', fontName='BodyBold', fontSize=12, leading=16, spaceBefore=10, spaceAfter=6, keepWithNext=True),
        'h3': ParagraphStyle('h3', fontName='BodyBold', fontSize=10, leading=14, spaceBefore=8, spaceAfter=5, keepWithNext=True),
        'title': ParagraphStyle('title', fontName='BodyBold', fontSize=28, leading=34, spaceAfter=18),
    }
    def inline(text):
        text = html.escape(text).replace('\u2011', '-').replace('\u2013', '-').replace('\u2014', '-')
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', lambda m: m[1] + ' (' + m[2] + ')', text)
        text = re.sub(r'`([^`]+)`', r'<font color="#334155">\1</font>', text)
        text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
        return text
    def para(text, style='body'):
        return Paragraph(inline(str(text)), styles[style])
    def table(rows):
        columns = len(rows[0])
        rendered = [[para(cell, 'small') for cell in row] for row in rows]
        item = LongTable(rendered, colWidths=[width/columns]*columns, repeatRows=1, hAlign='LEFT')
        item.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'), ('GRID', (0,0), (-1,-1), 0.35, colors.HexColor('#cbd5e1')),
            ('LEFTPADDING', (0,0), (-1,-1), 5), ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5), ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        return item
    def diagram():
        d = Drawing(width, 245)
        def box(x,y,w,label):
            d.add(Rect(x,y,w,38,rx=5, fillColor=colors.HexColor('#eef2ff'),strokeColor=colors.HexColor('#64748b')))
            d.add(String(x+8,y+15,label,fontName='Body',fontSize=8))
        def arrow(x,y,xx,yy):
            d.add(Line(x,y,xx,yy,strokeColor=colors.HexColor('#475569')))
            d.add(Polygon([xx,yy,xx-3,yy+7,xx+3,yy+7],fillColor=colors.HexColor('#475569')))
        box(90,204,330,'Користувач / Browser Client: недовірений input')
        box(90,132,330,'ASP.NET Core API: Identity, CSRF, authorization')
        arrow(255,204,255,170)
        d.add(String(267,185,'HTTP localhost / automatic cookie',fontName='Body',fontSize=7))
        box(0,58,240,'Git + NuGet / process environment')
        box(275,58,235,'PostgreSQL: state + history')
        arrow(380,132,380,96)
        d.add(String(285,113,'EF Core / parameterized SQL',fontName='Body',fontSize=7))
        d.add(Line(120,96,150,132,strokeColor=colors.HexColor('#475569')))
        box(90,0,330,'Мінімальні DTO -> Client; trace / audit -> log sink')
        arrow(255,132,255,38)
        return d
    def markdown(text):
        lines = text.splitlines(); out=[]; i=0
        while i < len(lines):
            line=lines[i].strip()
            if not line: i+=1; continue
            if line.startswith('```'):
                language=line[3:]; block=[]; i+=1
                while i<len(lines) and not lines[i].strip().startswith('```'):
                    block.append(lines[i]); i+=1
                if language=='mermaid': out.append(diagram())
                else:
                    for code_line in block: out.append(para(code_line or ' ', 'code'))
                i+=1; continue
            if line.startswith('|'):
                rows=[]
                while i<len(lines) and lines[i].strip().startswith('|'):
                    cells=[cell.strip() for cell in lines[i].strip().strip('|').split('|')]
                    if not all(re.fullmatch(r':?-+:?', cell or ' ') for cell in cells): rows.append(cells)
                    i+=1
                if rows:
                    n=len(rows[0]); rows=[row+['']*(n-len(row)) if len(row)<n else row[:n] for row in rows]
                    out.extend([table(rows),Spacer(1,8)])
                continue
            heading=re.match(r'^(#{1,3})\s+(.+)',line)
            if heading:
                out.append(para(heading[2], 'h'+str(len(heading[1])))); i+=1; continue
            if re.match(r'^[-*]\s|^\d+\.\s',line):
                out.append(para(line)); i+=1; continue
            group=[line]; i+=1
            while i<len(lines) and lines[i].strip() and not re.match(r'^(#|\||```|[-*]\s|\d+\.\s)',lines[i].strip()):
                group.append(lines[i].strip()); i+=1
            out.append(para(' '.join(group)))
        return out
    story=[Spacer(1,65),para('SecureLab', 'title'),para('Лабораторна робота 6: hardening та security review','h1'),
           para('Микола Марчук · baseline 2-A · рівень «Відмінно»'),
           Spacer(1,18),para('PREVIEW - перевірка верстки, не подання' if preview else 'ПЕРЕВІРЕНИЙ RELEASE · v1.0.0','h2'),
           para('Прийнятий commit: '+commit),para('Final run: PASS · '+proof['finishedAtUtc']),
           para('Release build: 0 warnings / 0 errors; tests '+proof['checks']['tests']['passed']+'/'+proof['checks']['tests']['total']+'; failed 0; skipped 0.'),
           para('Git state до/після run: clean. Нормальний seed і browser flow відновлено.'),
           Spacer(1,15),para('Пакет DEL-01–DEL-03: модель загроз, 3 виправлені findings, review, автоматизований REG-CSRF-01, approved advanced variant, очищені докази та private source ZIP.'),
           para('Межі: власний localhost і synthetic дані. Реальний TLS, production deployment, full history та зовнішні CI не перевірялися.'),
           para('AI: OpenAI Codex використано для коду, аналізу й документів; особисте розуміння та захист виконує автор.'),PageBreak()]
    for source in pdf_sources():
        story.append(para('Джерело: '+source,'small'))
        story.extend(markdown((ROOT/source).read_text(encoding='utf-8')))
        story.append(PageBreak())
    story.append(para('Фактичні докази фінального run','h1'))
    c=proof['checks']
    story.append(table([['Контроль','Результат'],['Verified commit',commit],['Locked restore / build','0 / 0; warnings 0; errors 0'],
        ['Tests',f"{c['tests']['passed']}/{c['tests']['total']}, failed {c['tests']['failed']}, skipped {c['tests']['notExecuted']}"],
        ['Dependency advisory',str(c['dependencies']['advisoryCount'])+' у налаштованих джерелах'],
        ['Secret review',f"{c['secret-review']['matches']} matches / {c['secret-review']['matchedFiles']} files; real credential discovered: {c['secret-review']['realCredentialDiscovered']}"],
        ['Logs sensitive matches',f"normal {c['log-audit-normal']['exactSensitiveValueMatches']}; exception {c['log-audit-unexpected']['exactSensitiveValueMatches']}"],
        ['Production trace linkage',str(c['log-audit-unexpected']['traceMatches'])],
        ['Production fallback',json.dumps(c['production-normal'],ensure_ascii=False)]]))
    story.append(para('REG-CSRF-01 та browser controls','h2'))
    for key in ('regCsrf01','searchRateLimit','ui'):
        story.append(para(key+': '+json.dumps(c['browser-regression'][key],ensure_ascii=False)))
    story.append(para('Advanced variant: фактичні результати','h2'))
    for item in c['advanced-integration']:
        safe=dict(item); safe.pop('audit',None)
        story.append(para(json.dumps(safe,ensure_ascii=False)))
    story.append(para('F-03 після fix: '+json.dumps(c['triage-concurrency-after'],ensure_ascii=False)))
    story.append(para('Safe production error / trace','h2'))
    story.append(para(json.dumps(c['log-audit-unexpected']['response'],ensure_ascii=False)))
    for line in c['log-audit-unexpected']['exceptionLogExcerpt']: story.append(para(line,'small'))
    story.append(para('Мінімальні audit-події','h2'))
    for line in c['log-audit-normal']['safeEventExcerpts']: story.append(para(line,'small'))
    screenshots = ROOT/'tmp/lab06/release/screenshots/advanced'
    for file in sorted(screenshots.glob('*.png')):
        story.append(PageBreak()); story.append(para('Actual Chrome: '+file.stem,'h2'))
        img=Image(str(file)); scale=min(width/img.imageWidth,610/img.imageHeight)
        img.drawWidth=img.imageWidth*scale; img.drawHeight=img.imageHeight*scale; story.append(img)
        story.append(para('Знімок фактичного browser flow під час final run. Поля паролів очищені; cookie/token/stamp values не показані.','small'))
    def footer(canvas,doc):
        canvas.setFont('Body',8); canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(42,26,'SecureLab · ЛР6 · '+('preview' if preview else 'v1.0.0'))
        canvas.drawRightString(A4[0]-42,26,str(doc.page))
    document=SimpleDocTemplate(str(path),pagesize=A4,rightMargin=42,leftMargin=42,topMargin=40,bottomMargin=42,
        title='SecureLab LR06 Security Review',author='Микола Марчук')
    document.build(story,onFirstPage=footer,onLaterPages=footer)
    from pypdf import PdfReader
    text='\n'.join(page.extract_text() or '' for page in PdfReader(path).pages)
    assert commit in text and 'REG-CSRF-01' in text
    assert not re.search(r'\bCfDJ[A-Za-z0-9_-]{80,}\b',text)
    settings=ROOT/'tmp/lab06/local.runsettings'
    if settings.exists():
        password=ET.parse(settings).findtext('.//SeedUsers__Password')
        assert not password or password not in text, 'Runtime credential in export (value omitted).'


if __name__=='__main__':
    main()
