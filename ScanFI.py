import customtkinter as ctk
import subprocess
import platform
import getpass
import uuid
import socket
import hashlib
import psutil
import ctypes
import sys
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import pandas as pd
import os

# ================== CONFIG ==================
CREATOR_NAME = "Sajawal Hacker"
LINKEDIN_URL = "https://www.linkedin.com/in/sajawalhacker/"
GITHUB_URL = "https://github.com/Sajawal-hacker/"

# ================= ADMIN CHECK =================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

# ================= THEME =================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

data_store = {}

# ================= SYSTEM INFO =================
def get_mac():
    mac_num = uuid.getnode()
    mac = ':'.join([f'{(mac_num >> ele) & 0xff:02x}' for ele in range(0,8*6,8)][::-1])
    return mac

def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "N/A"

def get_drives_info():
    partitions = psutil.disk_partitions()
    drives = []
    for part in partitions:
        usage = psutil.disk_usage(part.mountpoint)
        drives.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "total": f"{round(usage.total / (1024**3), 2)} GB",
            "used": f"{round(usage.used / (1024**3), 2)} GB",
            "free": f"{round(usage.free / (1024**3), 2)} GB"
        })
    return drives

# ================= WIFI =================
def get_wifi_profiles():
    try:
        result = subprocess.check_output("netsh wlan show profiles", shell=True).decode(errors="ignore")
        profiles = []
        for line in result.split("\n"):
            if "All User Profile" in line:
                profiles.append(line.split(":")[1].strip())
        return profiles
    except:
        return []

def get_wifi_details(profile):
    try:
        result = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True).decode(errors="ignore")
        password = "N/A"
        security = "Unknown"
        for line in result.split("\n"):
            if "Key Content" in line:
                password = line.split(":")[1].strip()
            if "Authentication" in line:
                security = line.split(":")[1].strip()
        return profile, password, security
    except:
        return profile, "N/A", "Unknown"

# ================= HASH =================
def generate_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# ================= SCAN =================
def start_scan():
    textbox.delete("1.0","end")
    progress.set(0)
    app.update()

    textbox.insert("end", "[*] Starting authorized forensic scan...\n\n")

    global data_store
    data_store = {}

    case_id = case_entry.get().strip() or "N/A"

    # ----- System Info -----
    data_store["case_id"] = case_id
    data_store["computer"] = platform.node()
    data_store["user"] = getpass.getuser()
    data_store["os"] = platform.platform()
    data_store["mac"] = get_mac()
    data_store["ip"] = get_ip()
    data_store["ram"] = str(round(psutil.virtual_memory().total/(1024**3),2))+" GB"
    data_store["time"] = str(datetime.now())
    data_store["drives"] = get_drives_info()

    progress.set(0.35)
    app.update()

    textbox.insert("end", "========== SYSTEM INFO ==========\n")
    for k in ["case_id","computer","user","os","mac","ip","ram","time"]:
        textbox.insert("end", f"{k}: {data_store[k]}\n")
    textbox.insert("end", "\nDrives Info:\n")
    for d in data_store["drives"]:
        textbox.insert("end", f"{d['device']} mounted at {d['mountpoint']}, Total: {d['total']}, Used: {d['used']}, Free: {d['free']}\n")
    textbox.insert("end", "\n")

    # ----- WIFI TABLE -----
    textbox.insert("end", "========== WIFI EVIDENCE ==========\n")
    wifi_list=[]
    profiles = get_wifi_profiles()
    progress.set(0.65)
    app.update()
    if not profiles:
        textbox.insert("end", "No WiFi profiles found.\n")
    table_data = [["SSID","Password"]]
    for p in profiles:
        ssid, pwd, sec = get_wifi_details(p)
        wifi_list.append({"ssid":ssid,"password":pwd})
        table_data.append([ssid,pwd])
    data_store["wifi"]=wifi_list
    for row in table_data:
        textbox.insert("end", f"{row[0]:30} {row[1]:30}\n")

    # ----- HASH -----
    evidence_hash = generate_hash(str(data_store))
    data_store["hash"] = evidence_hash
    textbox.insert("end", "\nEVIDENCE HASH:\n")
    textbox.insert("end", f"SHA256: {evidence_hash}\n")
    progress.set(1)
    app.update()
    textbox.insert("end", "\n[+] Scan Completed Successfully\n")

    # Show popup message
    messagebox.showinfo("Scan Complete", "Scan Completed Successfully!")

# ================= PDF SAVE =================
def save_pdf():
    if not data_store:
        textbox.insert("end","\n[!] No data to save\n")
        return
    file_path=filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files","*.pdf")], title="Save Forensic Report")
    if not file_path:
        return
    styles=getSampleStyleSheet()
    doc=SimpleDocTemplate(file_path)
    story=[]
    # HEADER
    story.append(Paragraph("ScanFi WiFi Password Extractor - By Sajawal Hacker", styles["Title"]))
    story.append(Paragraph(f"Created by: {CREATOR_NAME}", styles["Normal"]))
    story.append(Spacer(1,12))
    # SYSTEM INFO TABLE
    system_table=[["Key","Value"]]
    for k in ["case_id","computer","user","os","mac","ip","ram","time"]:
        system_table.append([k,data_store[k]])
    t=Table(system_table,colWidths=[150,300])
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkblue),
                           ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                           ('GRID',(0,0),(-1,-1),1,colors.black)]))
    story.append(t)
    story.append(Spacer(1,12))
    # DRIVES TABLE
    drives_table=[["Device","Mount","Total","Used","Free"]]
    for d in data_store["drives"]:
        drives_table.append([d['device'],d['mountpoint'],d['total'],d['used'],d['free']])
    dt=Table(drives_table,colWidths=[80,80,80,80,80])
    dt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkred),
                            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                            ('GRID',(0,0),(-1,-1),1,colors.black)]))
    story.append(dt)
    story.append(Spacer(1,12))
    # WIFI TABLE
    wifi_table=[["SSID","Password"]]
    for w in data_store["wifi"]:
        wifi_table.append([w['ssid'],w['password']])
    wt=Table(wifi_table,colWidths=[250,200])
    wt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkgreen),
                            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                            ('GRID',(0,0),(-1,-1),1,colors.black)]))
    story.append(wt)
    # FOOTER LINKS
    story.append(Spacer(1,12))
    story.append(Paragraph(f'Follow LinkedIn: <link href="{LINKEDIN_URL}">{LINKEDIN_URL}</link>',styles["Normal"]))
    story.append(Paragraph(f'Follow GitHub: <link href="{GITHUB_URL}">{GITHUB_URL}</link>',styles["Normal"]))
    doc.build(story)

    # PDF Save popup
    if os.path.exists(file_path):
        messagebox.showinfo("PDF Saved", f"PDF file saved successfully at:\n{file_path}")
    else:
        messagebox.showerror("Save Error", "Failed to save PDF file.")

# ================= EXCEL SAVE =================
def save_excel():
    if not data_store:
        textbox.insert("end","\n[!] No data to save\n")
        return
    file_path=filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files","*.xlsx")], title="Save Forensic Report")
    if not file_path:
        return
    try:
        # SYSTEM INFO
        sys_df=pd.DataFrame([{k:data_store[k] for k in ["case_id","computer","user","os","mac","ip","ram","time"]}])
        # DRIVES
        drives_df=pd.DataFrame(data_store["drives"])
        # WIFI
        wifi_df=pd.DataFrame(data_store["wifi"])
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            sys_df.to_excel(writer, sheet_name="System Info", index=False)
            drives_df.to_excel(writer, sheet_name="Drives Info", index=False)
            wifi_df.to_excel(writer, sheet_name="WiFi Info", index=False)
        # Check if file exists
        if os.path.exists(file_path):
            messagebox.showinfo("Excel Saved", f"Excel file saved successfully at:\n{file_path}")
        else:
            messagebox.showerror("Save Error", "Failed to save Excel file.")
    except Exception as e:
        messagebox.showerror("Save Error", f"Error saving Excel file:\n{str(e)}")

# ================= GUI =================
app=ctk.CTk()
app.title("ScanFi WiFi Password Extractor - By Sajawal Hacker")
app.geometry("980x780")

# WARNING
warning=ctk.CTkLabel(app,text="AUTHORIZED FORENSIC USE ONLY",text_color="red",font=("Consolas",16,"bold"))
warning.pack(pady=6)

# TITLE
title=ctk.CTkLabel(app,text="ScanFi WiFi Password Extractor - By Sajawal Hacker",font=("Consolas",28,"bold"))
title.pack(pady=6)

# CASE ID FRAME
case_frame=ctk.CTkFrame(app, corner_radius=10, border_width=1, border_color="gray")
case_frame.pack(pady=12)
case_label=ctk.CTkLabel(case_frame,text="Case ID:",font=("Consolas",12,"bold"))
case_label.grid(row=0,column=0,padx=5,pady=5)
case_entry=ctk.CTkEntry(case_frame,placeholder_text="e.g. CTD-2026-001",width=300,font=("Consolas",12))
case_entry.grid(row=0,column=1,padx=5,pady=5)
tooltip_label=ctk.CTkLabel(case_frame,text="Enter Case ID for this investigation",font=("Consolas",10))
tooltip_label.grid(row=1,column=0,columnspan=2,pady=2)

# SCAN BUTTON
scan_btn=ctk.CTkButton(app,text="CLICK FOR SCAN",height=42,command=start_scan)
scan_btn.pack(pady=8)

# SAVE BUTTONS FRAME
save_frame=ctk.CTkFrame(app)
save_frame.pack(pady=6)
pdf_btn=ctk.CTkButton(save_frame,text="Save as PDF",command=save_pdf)
pdf_btn.grid(row=0,column=0,padx=5)
excel_btn=ctk.CTkButton(save_frame,text="Save as Excel",command=save_excel)
excel_btn.grid(row=0,column=1,padx=5)

# FOLLOW FRAME INLINE
follow_frame=ctk.CTkFrame(app)
follow_frame.pack(pady=10)
follow_label=ctk.CTkLabel(follow_frame,text="Follow:",font=("Consolas",12))
follow_label.grid(row=0,column=0,padx=5)
linkedin_label=ctk.CTkLabel(follow_frame,text="LinkedIn",font=("Consolas",12),text_color="cyan",cursor="hand2")
linkedin_label.grid(row=0,column=1,padx=5)
linkedin_label.bind("<Button-1>",lambda e: webbrowser.open(LINKEDIN_URL))
github_label=ctk.CTkLabel(follow_frame,text="GitHub",font=("Consolas",12),text_color="cyan",cursor="hand2")
github_label.grid(row=0,column=2,padx=5)
github_label.bind("<Button-1>",lambda e: webbrowser.open(GITHUB_URL))

# PROGRESS
progress=ctk.CTkProgressBar(app,width=540)
progress.pack(pady=12)
progress.set(0)

# TEXTBOX
textbox=ctk.CTkTextbox(app,width=940,height=480)
textbox.pack(pady=10)

app.mainloop()