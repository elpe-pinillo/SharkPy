from tkinter import ttk
import customtkinter
from scapy.all import *
from core import CoreClass

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.c = CoreClass(self)
        self.t = None
        # configure window
        self.title("WireShark PRO")
        self.geometry(f"{1100}x{580}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="PROSHARK", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        self.sniff_button = customtkinter.CTkButton(self.sidebar_frame, command=self.sniff_button_event, text="Run")
        self.sniff_button.grid(row=1, column=0, padx=20, pady=10)
        self.stop_button = customtkinter.CTkButton(self.sidebar_frame, command=self.stop_button_event, text="Stop")
        self.stop_button.grid(row=2, column=0, padx=20, pady=10)
        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, command=self.sidebar_button_event, text="Save")
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["80%", "90%", "100%", "110%", "120%"], command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

        # create main entry and button
        self.entry = customtkinter.CTkEntry(self, placeholder_text="CTkEntry")
        self.entry.grid(row=3, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")

        # create table
        self.packets_table = ttk.Treeview(self)

        # Definir estilo personalizado
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#2a2d2e",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#343638",
                        bordercolor="#343638",
                        borderwidth=0)
        style.map('Treeview', background=[('selected', '#22559b')])
        style.configure("Treeview.Heading",
                        background="#565b5e",
                        foreground="white",
                        relief="flat")
        style.map("Treeview.Heading",
                  background=[('active', '#3484F0')])

        # Configurar columnas
        self.packets_table.configure(style="Treeview", columns=("one", "two", "three", "four", "five"))
        self.packets_table.column("#0", width=50, minwidth=50, stretch=True)
        self.packets_table.column("one", width=100, minwidth=100, stretch=True)
        self.packets_table.column("two", width=100, minwidth=100, stretch=True)
        self.packets_table.column("three", width=100, minwidth=100, stretch=True)
        self.packets_table.column("four", width=100, minwidth=100, stretch=True)
        self.packets_table.column("five", width=100, minwidth=100, stretch=True)

        # Configurar encabezados de columnas
        self.packets_table.heading("#0", text="No.", anchor="w")
        self.packets_table.heading("one", text="Source", anchor="w")
        self.packets_table.heading("two", text="Destination", anchor="w")
        self.packets_table.heading("three", text="Protocol", anchor="w")
        self.packets_table.heading("four", text="Length", anchor="w")
        self.packets_table.heading("five", text="Info", anchor="w")
        self.packets_table.grid(row=0, column=1, columnspan=3, padx=(20, 20), pady=(20, 0), sticky="nsew")

        # create details table
        self.packets_details = ttk.Treeview(self)
        self.packets_details.configure(style="Treeview")
        self.packets_details.column("#0", width=50, minwidth=50, stretch=True)
        self.packets_details.grid(row=1, column=1, padx=(20, 250), pady=(20, 0), sticky="nsew")

        # create hexadecimal table
        self.packets_hex = ttk.Treeview(self)
        self.packets_hex.configure(style="Treeview")
        self.packets_hex.column("#0", width=50, minwidth=50, stretch=True)
        self.packets_hex.grid(row=1, column=1, columnspan=3 ,padx=(500,20), pady=(20, 0), sticky="nsew")

        # # create textbox2
        # self.textbox2 = customtkinter.CTkTextbox(self, width=300)
        # self.textbox2.grid(row=1, column=1, padx=(20, 20), pady=(10, 10), sticky="nsew")

        self.sidebar_button_3.configure(state="disabled", text="Disabled CTkButton")
        self.appearance_mode_optionemenu.set("Dark")
        self.scaling_optionemenu.set("100%")

    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_event(self):
        print("sidebar_button click")

    def sniff_button_event(self):
        def insert_packets():
            self.c.run()
        self.t = threading.Thread(target=insert_packets)
        self.t.start()


    def stop_button_event(self):
        # self.t.interrupt_main()
        self.c.stop()

    def push_packets(self, spacket):
        self.packets_table.insert("", "end", text="1", values=(spacket[IP].src, spacket[IP].dst, "UWU", spacket[IP].len, spacket[IP].summary()))


if __name__ == "__main__":
    app = App()
    app.mainloop()
