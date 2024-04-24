from fritzconnection.lib.fritzhosts import FritzHosts
import tkinter as tk
from tkinter import filedialog, messagebox
import csv

def show_results_window(data):
    result_window = tk.Toplevel()
    result_window.title("Verbundene Geräte")

    result_text = tk.Text(result_window)
    result_text.pack(expand=True, fill="both")

    for index, host in enumerate(data, start=1):
        status = 'aktiv' if host['status'] else 'inaktiv'
        ip = host['ip'] if host['ip'] else '-'
        mac = host['mac'] if host['mac'] else '-'
        hn = host['name']
        result_text.insert(tk.END, f"{index}: IP: {ip}, Hostname: {hn}, MAC-Adresse: {mac}, Status: {status}\n")

    def save_to_csv_from_window():
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP", "Hostname", "MAC-Adresse", "Status"])
                for host in data:
                    writer.writerow([host['ip'], host['name'], host['mac'], 'aktiv' if host['status'] else 'inaktiv'])
            messagebox.showinfo("Erfolgreich gespeichert", "Die Daten wurden erfolgreich in die CSV-Datei gespeichert.")

    save_button = tk.Button(result_window, text="Als CSV speichern", command=save_to_csv_from_window)
    save_button.pack(pady=10)

def exit_fritz_gui():
    fritzMain_gui.destroy()

def fritz_devices():
    address_ip = addressIP_entry.get()
    user_name = userName_entry.get()
    user_password = userPassword_entry.get()
    status_filter = status_var.get()
    fh = FritzHosts(address=address_ip, user=user_name, password=user_password)
    hosts = fh.get_hosts_info()
    if status_filter == "Alle":
        show_results_window(hosts)
    else:
        filtered_hosts = [host for host in hosts if (host['status'] and status_filter == "Aktiv") or (not host['status'] and status_filter == "Inaktiv")]
        show_results_window(filtered_hosts)

fritzMain_gui = tk.Tk()
fritzMain_gui.geometry("640x480")
fritzMain_gui.title("Fritzbox Devices")

tk.Label(fritzMain_gui, text="IP Addresse der Fritzbox").pack(side="top", pady=10)
addressIP_entry = tk.Entry(fritzMain_gui)
addressIP_entry.pack(side="top")

tk.Label(fritzMain_gui, text="Benutzername").pack(side="top", pady=10)
userName_entry = tk.Entry(fritzMain_gui)
userName_entry.pack(side="top")

tk.Label(fritzMain_gui, text="Passwort").pack(side="top", pady=10)
userPassword_entry = tk.Entry(fritzMain_gui)
userPassword_entry.pack(side="top")

status_var = tk.StringVar(fritzMain_gui)
status_var.set("Alle")
status_options = ["Alle", "Aktiv", "Inaktiv"]
status_menu = tk.OptionMenu(fritzMain_gui, status_var, *status_options)
tk.Label(fritzMain_gui, text="Status").pack(side="top", pady=10)
status_menu.pack(side="top")

devices_button = tk.Button(master=fritzMain_gui, text="Verbundene Geräte", command=fritz_devices)
devices_button.pack(side="left", padx=20)

exit_button = tk.Button(master=fritzMain_gui, text="Beenden", command=exit_fritz_gui)
exit_button.pack(side="right", padx=20)

fritzMain_gui.mainloop()
