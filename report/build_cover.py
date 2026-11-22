"""MAIT-style prelim pages matching the attached industrial-training cover."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "cover.pdf"
LOGO = ROOT / "mait_logo.png"
WIDTH, HEIGHT = A4

FONTS = Path(r"C:\Windows\Fonts")
pdfmetrics.registerFont(TTFont("Times", str(FONTS / "times.ttf")))
pdfmetrics.registerFont(TTFont("Times-Bold", str(FONTS / "timesbd.ttf")))
pdfmetrics.registerFont(TTFont("Times-Italic", str(FONTS / "timesi.ttf")))
pdfmetrics.registerFont(TTFont("Times-BoldItalic", str(FONTS / "timesbi.ttf")))


def _center(c: canvas.Canvas, text: str, y: float, font: str, size: float) -> None:
    c.setFont(font, size)
    c.drawCentredString(WIDTH / 2, y, text)


def _wrapped_center(
    c: canvas.Canvas, text: str, y: float, font: str, size: float, leading: float, max_width: float
) -> float:
    c.setFont(font, size)
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        trial = (current + " " + word).strip()
        if c.stringWidth(trial, font, size) <= max_width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    for line in lines:
        _center(c, line, y, font, size)
        y -= leading
    return y


def cover_page(c: canvas.Canvas) -> None:
    y = HEIGHT - 28 * mm
    _center(c, "MINOR PROJECT REPORT", y, "Times-Bold", 22)

    y -= 22 * mm
    _center(c, "AEGISTRAP", y, "Times-Bold", 20)
    y -= 9 * mm
    _center(c, "An LLM-Powered Adaptive API Honeypot", y, "Times-Bold", 13)

    y -= 16 * mm
    y = _wrapped_center(
        c,
        "Submitted in partial fulfilment of the Requirements for the award of the",
        y,
        "Times-Italic",
        11.5,
        16,
        150 * mm,
    )
    y -= 1 * mm
    _center(c, "Degree of Bachelor of Technology", y, "Times-Italic", 11.5)
    y -= 6 * mm
    _center(c, "in Electronics and Communication Engineering", y, "Times-Italic", 11.5)

    y -= 14 * mm
    _center(c, "Submitted By", y, "Times-Bold", 13)

    y -= 10 * mm
    _center(c, "Name: Arnav Chopra", y, "Times-Bold", 12)
    y -= 6.2 * mm
    _center(c, "University Roll No.: 00414815923", y, "Times-Bold", 12)

    y -= 8 * mm
    _center(c, "Name: Anshika Chaubey", y, "Times-Bold", 12)
    y -= 6.2 * mm
    _center(c, "University Roll No.: 20514815923", y, "Times-Bold", 12)

    y -= 12 * mm
    _center(c, "Department of Electronics and Communication Engineering", y, "Times-Bold", 13)
    y -= 7 * mm
    _center(c, "Branch / Section: ECE (ACT)", y, "Times-Bold", 12.5)
    y -= 7 * mm
    _center(c, "Semester: VII", y, "Times-Bold", 12.5)

    y -= 11 * mm
    _center(c, "Under the Guidance of", y, "Times", 12)
    y -= 7 * mm
    _center(c, "Mr. Lalit Agarwal", y, "Times-Bold", 12.5)
    y -= 6 * mm
    _center(c, "Assistant Professor", y, "Times", 11.5)

    logo_w = 48 * mm
    img = __import__("PIL.Image", fromlist=["Image"]).Image.open(LOGO)
    aspect = img.size[1] / img.size[0]
    logo_h = logo_w * aspect
    y -= logo_h + 8 * mm
    c.drawImage(
        str(LOGO),
        (WIDTH - logo_w) / 2,
        y,
        width=logo_w,
        height=logo_h,
        mask="auto",
        preserveAspectRatio=True,
        anchor="c",
    )

    y -= 10 * mm
    _center(c, "MAHARAJA AGRASEN INSTITUTE OF TECHNOLOGY", y, "Times-Bold", 13.5)
    y -= 7 * mm
    _center(c, "GGSIPU, DELHI", y, "Times-Bold", 13.5)
    y -= 8 * mm
    _center(c, "2026", y, "Times", 12)


def _body_text(c: canvas.Canvas, text: str, x: float, y: float, font: str, size: float, leading: float, width: float) -> float:
    c.setFont(font, size)
    words = text.split()
    line = ""
    for word in words:
        trial = (line + " " + word).strip()
        if c.stringWidth(trial, font, size) <= width:
            line = trial
        else:
            c.drawString(x, y, line)
            y -= leading
            line = word
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y


def certificate_page(c: canvas.Canvas) -> None:
    _center(c, "CERTIFICATE", HEIGHT - 30 * mm, "Times-Bold", 18)
    x = 25 * mm
    width = WIDTH - 50 * mm
    y = HEIGHT - 55 * mm
    paras = [
        "This is to certify that the Minor Project Report entitled “AegisTrap” submitted by Arnav Chopra (University Roll No. 00414815923) and Anshika Chaubey (University Roll No. 20514815923) of the Department of Electronics and Communication Engineering, Branch / Section ECE (ACT), in partial fulfilment of the requirements for the award of the Degree of Bachelor of Technology in Electronics and Communication Engineering of Guru Gobind Singh Indraprastha University, Delhi, is a bona fide record of the work carried out by them under my guidance and supervision during the Seventh Semester, academic year 2025–26.",
        "The work embodied in this report has not been submitted, in part or in full, to any other University or Institute for the award of any degree or diploma. The students have completed the work to my satisfaction, and the report is forwarded for evaluation.",
    ]
    for para in paras:
        y = _body_text(c, para, x, y, "Times", 12, 18, width)
        y -= 8
    y -= 8 * mm
    c.setFont("Times", 12)
    c.drawString(x, y, "Date: ____________________")
    y -= 22 * mm
    c.setFont("Times-Bold", 12)
    c.drawString(x, y, "Mr. Lalit Agarwal")
    y -= 5.5 * mm
    c.setFont("Times", 11)
    c.drawString(x, y, "Assistant Professor")
    y -= 5 * mm
    c.drawString(x, y, "Project Guide")
    y -= 5 * mm
    c.drawString(x, y, "Department of Electronics and")
    y -= 5 * mm
    c.drawString(x, y, "Communication Engineering")

    right = WIDTH - 25 * mm
    y_sig = y + 20 * mm
    c.setFont("Times-Bold", 12)
    c.drawRightString(right, y_sig, "Head of Department")
    y_sig -= 5.5 * mm
    c.setFont("Times", 11)
    c.drawRightString(right, y_sig, "Department of Electronics and")
    y_sig -= 5 * mm
    c.drawRightString(right, y_sig, "Communication Engineering")
    y_sig -= 5 * mm
    c.drawRightString(right, y_sig, "MAIT, GGSIPU, Delhi")

    y = 40 * mm
    _center(c, "Maharaja Agrasen Institute of Technology, GGSIPU, Delhi", y, "Times-Italic", 10)


def declaration_page(c: canvas.Canvas) -> None:
    _center(c, "DECLARATION", HEIGHT - 30 * mm, "Times-Bold", 18)
    x = 25 * mm
    width = WIDTH - 50 * mm
    y = HEIGHT - 55 * mm
    paras = [
        "We, Arnav Chopra (University Roll No. 00414815923) and Anshika Chaubey (University Roll No. 20514815923), students of Bachelor of Technology, Seventh Semester, Department of Electronics and Communication Engineering, Branch / Section ECE (ACT), Maharaja Agrasen Institute of Technology, affiliated to Guru Gobind Singh Indraprastha University, Delhi, hereby declare that the Minor Project Report entitled “AegisTrap” submitted in partial fulfilment of the requirements for the award of the Degree of Bachelor of Technology is our original work.",
        "The matter presented in this report has been carried out under the guidance of Mr. Lalit Agarwal, Assistant Professor. We further declare that the work has not been submitted, either in part or in full, to any other University or Institute for the award of any degree, diploma, or certificate. Information derived from published and unpublished sources has been duly acknowledged.",
    ]
    for para in paras:
        y = _body_text(c, para, x, y, "Times", 12, 18, width)
        y -= 10
    y -= 16 * mm
    c.setFont("Times", 12)
    c.drawString(x, y, "Place: Delhi")
    y -= 6 * mm
    c.drawString(x, y, "Date: ____________________")
    y -= 22 * mm
    c.setFont("Times-Bold", 12)
    c.drawString(x, y, "Arnav Chopra")
    y -= 5.5 * mm
    c.setFont("Times", 11)
    c.drawString(x, y, "00414815923")
    y2 = y + 5.5 * mm
    c.setFont("Times-Bold", 12)
    c.drawRightString(WIDTH - 25 * mm, y2, "Anshika Chaubey")
    c.setFont("Times", 11)
    c.drawRightString(WIDTH - 25 * mm, y2 - 5.5 * mm, "20514815923")


def acknowledgement_page(c: canvas.Canvas) -> None:
    _center(c, "ACKNOWLEDGEMENT", HEIGHT - 30 * mm, "Times-Bold", 18)
    x = 25 * mm
    width = WIDTH - 50 * mm
    y = HEIGHT - 55 * mm
    paras = [
        "We express our sincere gratitude to Mr. Lalit Agarwal, Assistant Professor, Department of Electronics and Communication Engineering, Maharaja Agrasen Institute of Technology, for his guidance, critical feedback, and constant encouragement during the course of this Minor Project.",
        "We thank the Head of the Department and the faculty of the Department of Electronics and Communication Engineering, MAIT, for providing the academic environment in which this work was carried out. We are also grateful to Guru Gobind Singh Indraprastha University, Delhi, for the curriculum framework of the Bachelor of Technology programme.",
        "The design of AegisTrap builds upon published work in deception technology, LLM-powered honeypots, and API security. Those contributions are cited in the body of this report. Any remaining errors are our own.",
        "Finally, we thank our families for their support during the Seventh Semester.",
    ]
    for para in paras:
        y = _body_text(c, para, x, y, "Times", 12, 18, width)
        y -= 8
    y -= 14 * mm
    c.setFont("Times-Bold", 12)
    c.drawString(x, y, "Arnav Chopra")
    c.drawRightString(WIDTH - 25 * mm, y, "Anshika Chaubey")
    y -= 6 * mm
    c.setFont("Times", 11)
    c.drawString(x, y, "ECE (ACT), VII Semester")
    c.drawRightString(WIDTH - 25 * mm, y, "ECE (ACT), VII Semester")


def main() -> None:
    c = canvas.Canvas(str(OUT), pagesize=A4)
    cover_page(c)
    c.showPage()
    certificate_page(c)
    c.showPage()
    declaration_page(c)
    c.showPage()
    acknowledgement_page(c)
    c.save()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
