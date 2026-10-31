"""
RISE-Phish Documentation Generation Utilities
Helper functions for creating professionally styled Word (.docx) documents.
"""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

# Color Palette
COLOR_PRIMARY_NAVY = RGBColor(16, 42, 77)       # #102A4D - Headings, Main brand
COLOR_SECONDARY_BLUE = RGBColor(43, 90, 140)    # #2B5A8C - Subheadings, Accents
COLOR_TEAL = RGBColor(0, 128, 128)              # #008080 - Tertiary headers, Highlights
COLOR_BODY = RGBColor(51, 51, 51)               # #333333 - Body text
COLOR_MUTED = RGBColor(100, 116, 139)           # #64748B - Captions, Metadata
COLOR_ALERT_BORDER = "2B5A8C"
COLOR_ALERT_BG = "F0F4F8"
COLOR_WARN_BORDER = "D97706"
COLOR_WARN_BG = "FEF3C7"
COLOR_DANGER_BORDER = "DC2626"
COLOR_DANGER_BG = "FEE2E2"
COLOR_SUCCESS_BORDER = "16A34A"
COLOR_SUCCESS_BG = "DCFCE7"

HEX_HEADER_BG = "102A4D"
HEX_ZEBRA_LIGHT = "F8F9FA"
HEX_WHITE = "FFFFFF"
HEX_BORDER = "D1D5DB"


def create_base_document():
    """Create a new Document with standardized academic margins, fonts, and styles."""
    doc = docx.Document()
    
    # Configure 1-inch margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        section.header_distance = Inches(0.5)
        section.footer_distance = Inches(0.5)

    # Base Normal Style
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = COLOR_BODY
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(6)
    normal_style.paragraph_format.space_before = Pt(0)

    return doc


def set_cell_background(cell, hex_color):
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    # Remove existing shading if present
    for child in list(tc_pr):
        if child.tag.endswith('shd'):
            tc_pr.remove(child)
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tc_pr.append(shading)


def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    """Set internal cell padding (in twentieths of a point / dxa)."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)


def set_cell_borders(cell, top=None, bottom=None, left=None, right=None):
    """Set custom borders on a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    borders_elm = OxmlElement('w:tcBorders')
    
    borders = {'top': top, 'bottom': bottom, 'left': left, 'right': right}
    for side, border in borders.items():
        if border:
            val, sz, space, color = border
            b_elm = parse_xml(f'<w:{side} {nsdecls("w")} w:val="{val}" w:sz="{sz}" w:space="{space}" w:color="{color}"/>')
            borders_elm.append(b_elm)
        else:
            b_elm = parse_xml(f'<w:{side} {nsdecls("w")} w:val="none"/>')
            borders_elm.append(b_elm)
            
    tc_pr.append(borders_elm)


def add_heading_1(doc, text):
    """Add styled Level 1 Heading (Chapter/Main Section)."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(17)
    run.font.bold = True
    run.font.color.rgb = COLOR_PRIMARY_NAVY
    return p


def add_heading_2(doc, text):
    """Add styled Level 2 Heading (Sub-section)."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(13.5)
    run.font.bold = True
    run.font.color.rgb = COLOR_SECONDARY_BLUE
    return p


def add_heading_3(doc, text):
    """Add styled Level 3 Heading."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(11.5)
    run.font.bold = True
    run.font.color.rgb = COLOR_TEAL
    return p


def add_paragraph(doc, text="", bold_prefix=None, italic=False, space_after=6):
    """Add a body paragraph with optional bold prefix."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.15
    
    if bold_prefix:
        r_bold = p.add_run(bold_prefix)
        r_bold.font.name = 'Calibri'
        r_bold.font.size = Pt(11)
        r_bold.font.bold = True
        r_bold.font.color.rgb = COLOR_PRIMARY_NAVY
        
    if text:
        r_text = p.add_run(text)
        r_text.font.name = 'Calibri'
        r_text.font.size = Pt(11)
        r_text.font.italic = italic
        r_text.font.color.rgb = COLOR_BODY
        
    return p


def add_bullet(doc, text, bold_prefix=None, level=0):
    """Add a bullet point paragraph."""
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.15
    if level > 0:
        p.paragraph_format.left_indent = Inches(0.25 * (level + 1))
        
    if bold_prefix:
        r_bold = p.add_run(bold_prefix)
        r_bold.font.name = 'Calibri'
        r_bold.font.size = Pt(11)
        r_bold.font.bold = True
        r_bold.font.color.rgb = COLOR_PRIMARY_NAVY
        
    r_text = p.add_run(text)
    r_text.font.name = 'Calibri'
    r_text.font.size = Pt(11)
    r_text.font.color.rgb = COLOR_BODY
    return p


def add_numbered(doc, text, bold_prefix=None, num_str="1."):
    """Add a numbered item."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.25)
    p.paragraph_format.first_line_indent = Inches(-0.25)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.15
    
    r_num = p.add_run(f"{num_str} ")
    r_num.font.name = 'Calibri'
    r_num.font.bold = True
    r_num.font.color.rgb = COLOR_SECONDARY_BLUE
    
    if bold_prefix:
        r_bold = p.add_run(bold_prefix)
        r_bold.font.name = 'Calibri'
        r_bold.font.bold = True
        r_bold.font.color.rgb = COLOR_PRIMARY_NAVY
        
    r_text = p.add_run(text)
    r_text.font.name = 'Calibri'
    r_text.font.color.rgb = COLOR_BODY
    return p


def add_callout(doc, text, title=None, alert_type="NOTE"):
    """
    Add a styled callout block (table with left accent border and soft fill).
    Types: NOTE, IMPORTANT, WARNING, CAUTION, TIP
    """
    type_configs = {
        "NOTE": (COLOR_ALERT_BG, COLOR_ALERT_BORDER, "NOTE"),
        "IMPORTANT": (COLOR_ALERT_BG, "102A4D", "IMPORTANT"),
        "WARNING": (COLOR_WARN_BG, COLOR_WARN_BORDER, "WARNING"),
        "CAUTION": (COLOR_DANGER_BG, COLOR_DANGER_BORDER, "CAUTION"),
        "TIP": (COLOR_SUCCESS_BG, COLOR_SUCCESS_BORDER, "TIP"),
    }
    bg_hex, border_hex, default_title = type_configs.get(alert_type.upper(), type_configs["NOTE"])
    display_title = title if title else default_title

    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
    
    # Left thick border (24 = 3pt), no top/right/bottom
    set_cell_borders(cell, left=('single', '24', '0', border_hex))
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.15
    
    r_title = p.add_run(f"[{display_title}] ")
    r_title.font.name = 'Calibri'
    r_title.font.size = Pt(10.5)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_PRIMARY_NAVY
    
    r_text = p.add_run(text)
    r_text.font.name = 'Calibri'
    r_text.font.size = Pt(10.5)
    r_text.font.color.rgb = COLOR_BODY
    
    # Add spacing paragraph after table
    sp = doc.add_paragraph()
    sp.paragraph_format.space_before = Pt(2)
    sp.paragraph_format.space_after = Pt(4)


def add_code_block(doc, code_str, caption=None):
    """Add a shaded code block with Consolas monospace font."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F3F4F6")
    set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
    set_cell_borders(cell, 
                     top=('single', '4', '0', 'E5E7EB'),
                     bottom=('single', '4', '0', 'E5E7EB'),
                     left=('single', '12', '0', '9CA3AF'),
                     right=('single', '4', '0', 'E5E7EB'))
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.0
    
    r = p.add_run(code_str.strip())
    r.font.name = 'Consolas'
    r.font.size = Pt(9.5)
    r.font.color.rgb = RGBColor(30, 41, 59)
    
    if caption:
        cp = doc.add_paragraph()
        cp.paragraph_format.space_before = Pt(2)
        cp.paragraph_format.space_after = Pt(6)
        cr = cp.add_run(f"Listing: {caption}")
        cr.font.name = 'Calibri'
        cr.font.size = Pt(9.5)
        cr.font.italic = True
        cr.font.color.rgb = COLOR_MUTED


def add_styled_table(doc, headers, data, col_widths=None, align_cols=None):
    """
    Add a professional academic table with dark navy headers, zebra rows,
    subtle horizontal grid lines, and proper cell margins.
    """
    rows_count = len(data) + 1
    cols_count = len(headers)
    tbl = doc.add_table(rows=rows_count, cols=cols_count)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    # Table header repeating on pages & cantSplit on rows
    header_tr = tbl.rows[0]._tr.get_or_add_trPr()
    header_tr.append(OxmlElement('w:tblHeader'))
    header_tr.append(OxmlElement('w:cantSplit'))
    
    # Style Header Row
    for col_idx, header_text in enumerate(headers):
        cell = tbl.cell(0, col_idx)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, top=140, bottom=140, left=140, right=140)
        set_cell_borders(cell,
                         top=('single', '12', '0', '0A192F'),
                         bottom=('single', '16', '0', '0A192F'),
                         left=('none', '0', '0', '000000'),
                         right=('none', '0', '0', '000000'))
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        if align_cols and col_idx < len(align_cols):
            p.alignment = align_cols[col_idx]
            
        run = p.add_run(str(header_text))
        run.font.name = 'Calibri'
        run.font.size = Pt(10)
        run.font.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)

    # Style Data Rows
    for row_idx, row_data in enumerate(data):
        row_num = row_idx + 1
        tr = tbl.rows[row_num]._tr.get_or_add_trPr()
        tr.append(OxmlElement('w:cantSplit'))
        bg_hex = HEX_WHITE if row_idx % 2 == 0 else HEX_ZEBRA_LIGHT
        
        for col_idx, cell_value in enumerate(row_data):
            cell = tbl.cell(row_num, col_idx)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_background(cell, bg_hex)
            set_cell_margins(cell, top=100, bottom=100, left=120, right=120)
            set_cell_borders(cell,
                             top=('single', '4', '0', HEX_BORDER),
                             bottom=('single', '4', '0', HEX_BORDER),
                             left=('none', '0', '0', '000000'),
                             right=('none', '0', '0', '000000'))
            
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.1
            if align_cols and col_idx < len(align_cols):
                p.alignment = align_cols[col_idx]
                
            run = p.add_run(str(cell_value))
            run.font.name = 'Calibri'
            run.font.size = Pt(9.5)
            run.font.color.rgb = COLOR_BODY

    # Set Column Widths if supplied
    if col_widths:
        for row in tbl.rows:
            for idx, width in enumerate(col_widths):
                if idx < len(row.cells):
                    row.cells[idx].width = width

    # Add trailing spacing
    p_after = doc.add_paragraph()
    p_after.paragraph_format.space_before = Pt(2)
    p_after.paragraph_format.space_after = Pt(6)
    return tbl


def add_title_page(doc, title, subtitle, doc_type, project_label="FINAL YEAR B.TECH CAPSTONE PROJECT"):
    """Generate a formal academic cover page with blank placeholders."""
    p_top = doc.add_paragraph()
    p_top.paragraph_format.space_before = Pt(24)
    p_top.paragraph_format.space_after = Pt(12)
    p_top.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    r_label = p_top.add_run(project_label.upper())
    r_label.font.name = 'Calibri'
    r_label.font.size = Pt(11)
    r_label.font.bold = True
    r_label.font.color.rgb = COLOR_SECONDARY_BLUE

    # Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(16)
    p_title.paragraph_format.space_after = Pt(8)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run(title)
    r_title.font.name = 'Calibri'
    r_title.font.size = Pt(24)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_PRIMARY_NAVY

    # Subtitle
    if subtitle:
        p_sub = doc.add_paragraph()
        p_sub.paragraph_format.space_before = Pt(4)
        p_sub.paragraph_format.space_after = Pt(20)
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_sub = p_sub.add_run(subtitle)
        r_sub.font.name = 'Calibri'
        r_sub.font.size = Pt(13)
        r_sub.font.color.rgb = COLOR_SECONDARY_BLUE

    # Document Type Badge
    p_badge = doc.add_paragraph()
    p_badge.paragraph_format.space_before = Pt(10)
    p_badge.paragraph_format.space_after = Pt(36)
    p_badge.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_badge = p_badge.add_run(f"--- {doc_type.upper()} ---")
    r_badge.font.name = 'Calibri'
    r_badge.font.size = Pt(12)
    r_badge.font.bold = True
    r_badge.font.color.rgb = COLOR_TEAL

    # Meta Table: Student, Guide, Institution placeholders
    table_meta = doc.add_table(rows=5, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_rows = [
        ("Submitted By:", "[Student Name 1] (Roll No: [Roll No 1])\n[Student Name 2] (Roll No: [Roll No 2])\n[Student Name 3] (Roll No: [Roll No 3])"),
        ("Project Guide / Supervisor:", "[Project Guide Name]\n[Guide Designation & Department]"),
        ("Department:", "Department of Artificial Intelligence & Machine Learning / Computer Science"),
        ("Institution:", "[Institution / College / University Name]"),
        ("Academic Year:", "[Academic Year: 202X - 202Y]")
    ]
    for idx, (label, val) in enumerate(meta_rows):
        c0 = table_meta.cell(idx, 0)
        c1 = table_meta.cell(idx, 1)
        c0.width = Inches(2.3)
        c1.width = Inches(4.2)
        set_cell_background(c0, "F8F9FA")
        set_cell_background(c1, "FFFFFF")
        set_cell_margins(c0, top=60, bottom=60, left=80, right=80)
        set_cell_margins(c1, top=60, bottom=60, left=80, right=80)
        set_cell_borders(c0, bottom=('single', '4', '0', 'E5E7EB'))
        set_cell_borders(c1, bottom=('single', '4', '0', 'E5E7EB'))
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_after = Pt(0)
        r0 = p0.add_run(label)
        r0.font.name = 'Calibri'
        r0.font.bold = True
        r0.font.size = Pt(10)
        r0.font.color.rgb = COLOR_PRIMARY_NAVY
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_after = Pt(0)
        r1 = p1.add_run(val)
        r1.font.name = 'Calibri'
        r1.font.size = Pt(10)
        r1.font.color.rgb = COLOR_BODY

    doc.add_page_break()


def add_certificate_and_declaration(doc, project_title):
    """Add formal academic Certificate and Declaration pages with blank signature fields."""
    # Certificate Page
    add_heading_1(doc, "BONAFIDE CERTIFICATE")
    add_paragraph(doc, 
        "This is to certify that the project report entitled \"" + project_title + 
        "\" submitted by [Student Name 1] ([Roll No 1]), [Student Name 2] ([Roll No 2]), and [Student Name 3] ([Roll No 3]) "
        "in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in "
        "Artificial Intelligence & Machine Learning / Computer Science & Engineering is a bonafide record of the work carried out under my supervision.")
    
    add_paragraph(doc, "The results embodied in this report have not been submitted to any other University or Institute for the award of any degree or diploma.")
    
    # Signature block
    p_sig = doc.add_paragraph()
    p_sig.paragraph_format.space_before = Pt(40)
    p_sig.paragraph_format.space_after = Pt(6)
    
    tbl_sig = doc.add_table(rows=2, cols=2)
    tbl_sig.alignment = WD_TABLE_ALIGNMENT.CENTER
    c0 = tbl_sig.cell(0, 0)
    c1 = tbl_sig.cell(0, 1)
    c0.width = Inches(3.2)
    c1.width = Inches(3.2)
    
    p0 = c0.paragraphs[0]
    p0.add_run("_____________________________\nSignature of Internal Guide\n[Project Guide Name]\n[Guide Designation]")
    p1 = c1.paragraphs[0]
    p1.add_run("_____________________________\nSignature of Head of Department\n[HOD Name]\nHead of the Department")
    
    c2 = tbl_sig.cell(1, 0)
    c3 = tbl_sig.cell(1, 1)
    p2 = c2.paragraphs[0]
    p2.paragraph_format.space_before = Pt(30)
    p2.add_run("_____________________________\nSignature of Internal Examiner\nDate: [DD/MM/YYYY]")
    p3 = c3.paragraphs[0]
    p3.paragraph_format.space_before = Pt(30)
    p3.add_run("_____________________________\nSignature of External Examiner\nDate: [DD/MM/YYYY]")
    
    doc.add_page_break()
    
    # Declaration Page
    add_heading_1(doc, "CANDIDATE DECLARATION")
    add_paragraph(doc,
        "We hereby declare that the work presented in this project report entitled \"" + project_title + 
        "\" has been independently carried out by us under the guidance of [Project Guide Name], "
        "[Guide Designation], Department of Artificial Intelligence & Machine Learning.")
    
    add_paragraph(doc,
        "We confirm that this report does not contain any work previously submitted for any other degree, "
        "diploma, or certificate in this or any other university. Wherever other authors' materials, datasets, "
        "or open-source software libraries have been used, due acknowledgements and citations have been made.")
    
    p_decl = doc.add_paragraph()
    p_decl.paragraph_format.space_before = Pt(36)
    tbl_decl = doc.add_table(rows=3, cols=2)
    tbl_decl.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    decl_data = [
        ("Candidate 1:", "Signature: ______________________\nName: [Student Name 1] | Roll No: [Roll No 1]"),
        ("Candidate 2:", "Signature: ______________________\nName: [Student Name 2] | Roll No: [Roll No 2]"),
        ("Candidate 3:", "Signature: ______________________\nName: [Student Name 3] | Roll No: [Roll No 3]")
    ]
    for idx, (label, val) in enumerate(decl_data):
        c0 = tbl_decl.cell(idx, 0)
        c1 = tbl_decl.cell(idx, 1)
        c0.width = Inches(1.8)
        c1.width = Inches(4.7)
        set_cell_margins(c0, top=40, bottom=40, left=40, right=40)
        set_cell_margins(c1, top=40, bottom=40, left=40, right=40)
        p0 = c0.paragraphs[0]
        p0.add_run(label).font.bold = True
        p1 = c1.paragraphs[0]
        p1.add_run(val)
        
    doc.add_page_break()


def add_acknowledgements(doc):
    """Add formal Acknowledgements page."""
    add_heading_1(doc, "ACKNOWLEDGEMENTS")
    add_paragraph(doc,
        "We express our deepest gratitude to our project guide [Project Guide Name], [Guide Designation], "
        "for invaluable guidance, constant encouragement, and insightful feedback throughout the duration of this research project. "
        "Their technical vision and mentorship have been pivotal in shaping the multi-representation analysis and discrepancy-aware architecture of RISE-Phish.")
    
    add_paragraph(doc,
        "We extend our sincere thanks to [HOD Name], Head of the Department of Artificial Intelligence & Machine Learning, "
        "and [Principal Name], Principal / Dean, for providing the necessary computational infrastructure, high-performance hardware, and laboratory facilities.")
    
    add_paragraph(doc,
        "We also convey our appreciation to the faculty members, technical lab staff, and our peers for their supportive discussions, "
        "constructive critique, and cooperation during the benchmarking, system evaluation, and validation phases.")
    
    p_sig = doc.add_paragraph()
    p_sig.paragraph_format.space_before = Pt(30)
    p_sig.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p_sig.add_run("[Student Name 1]\n[Student Name 2]\n[Student Name 3]\nBatch: [202X - 202Y]")
    
    doc.add_page_break()
