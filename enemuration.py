import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import validators

class WebEnumApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Enumeration Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Initialize the widgets for the application
        self.create_widgets()

        # ThreadPoolExecutor for managing threads
        self.executor = ThreadPoolExecutor(max_workers=10)

        # Placeholder for the selected wordlist file path
        self.wordlist_path = None

        # Event flag to stop the directory enumeration process
        self.stop_flag = threading.Event()

    def create_widgets(self):
        # Main frame for padding and containing other widgets
        self.frame = ttk.Frame(self.root, padding="20 20 20 20")
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Title label at the top of the GUI
        self.title_label = ttk.Label(self.frame, text="Web Enumeration Tool", font=("Helvetica", 16, "bold"))
        self.title_label.pack(pady=10)

        # Frame for entering the target URL
        self.url_frame = ttk.Frame(self.frame)
        self.url_frame.pack(pady=10, fill=tk.X)

        # Label for the URL entry
        self.label = ttk.Label(self.url_frame, text="Enter Target URL:", font=("Helvetica", 12))
        self.label.pack(side=tk.LEFT, padx=5)

        # Entry widget for user to input the target URL
        self.url_entry = ttk.Entry(self.url_frame, width=60)
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Frame to hold the buttons for different operations
        self.button_frame = ttk.Frame(self.frame)
        self.button_frame.pack(pady=10)

        # Button to get HTTP headers of the target URL
        self.header_button = ttk.Button(self.button_frame, text="Get HTTP Headers", command=self.get_http_headers)
        self.header_button.pack(side=tk.LEFT, padx=5)

        # Button to start directory brute-force enumeration
        self.dir_enum_button = ttk.Button(self.button_frame, text="Start Directory Brute-force",
                                          command=self.start_dir_enum)
        self.dir_enum_button.pack(side=tk.LEFT, padx=5)

        # Button to stop the directory enumeration process
        self.stop_button = ttk.Button(self.button_frame, text="Stop", command=self.stop_directory_enum)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state=tk.DISABLED)  # Initially disabled

        # Button to select a custom wordlist file for brute-force
        self.custom_wordlist_button = ttk.Button(self.button_frame, text="Select Wordlist",
                                                 command=self.select_wordlist)
        self.custom_wordlist_button.pack(side=tk.LEFT, padx=5)

        # Button to save the results to a file
        self.save_button = ttk.Button(self.button_frame, text="Save Results", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Progress bar to indicate ongoing processes
        self.progress = ttk.Progressbar(self.frame, mode='indeterminate', length=300)
        self.progress.pack(pady=10)

        # ScrolledText widget to display the output/results
        self.output_text = ScrolledText(self.frame, width=100, height=30, wrap=tk.WORD, font=("Courier New", 10))
        self.output_text.pack(pady=10)

        # Configuring text colors for different types of messages
        self.output_text.tag_configure("green", foreground="green")
        self.output_text.tag_configure("blue", foreground="blue")
        self.output_text.tag_configure("red", foreground="red")
        self.output_text.tag_configure("default", foreground="black")

    def get_http_headers(self):
        # Retrieve the target URL from the entry field
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        # Add 'http://' prefix if not present
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        # Validate the URL format
        if not validators.url(target_url):
            messagebox.showerror("Error", "Invalid URL format.")
            return

        # Disable the header button and start the progress bar
        self.header_button.config(state=tk.DISABLED)
        self.progress.start()

        # Submit the task to fetch HTTP headers to the thread pool
        self.executor.submit(self.fetch_http_headers, target_url)

    def fetch_http_headers(self, url):
        # Fetch HTTP headers from the target URL
        try:
            response = requests.head(url, timeout=10)
            headers = response.headers
            self.output_text.insert(tk.END, f"HTTP Headers for {url}:\n")
            for key, value in headers.items():
                self.output_text.insert(tk.END, f"{key}: {value}\n")
            self.output_text.insert(tk.END, "\n")
        except requests.RequestException as e:
            self.output_text.insert(tk.END, f"An error occurred: {e}\n")
        finally:
            # Re-enable the header button and stop the progress bar
            self.header_button.config(state=tk.NORMAL)
            self.progress.stop()

    def start_dir_enum(self):
        # Retrieve the target URL from the entry field
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        # Add 'http://' prefix if not present
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        # Validate the URL format
        if not validators.url(target_url):
            messagebox.showerror("Error", "Invalid URL format.")
            return

        # Ensure a wordlist file has been selected
        if not self.wordlist_path:
            messagebox.showerror("Error", "Please select a wordlist.")
            return

        # Clear the stop flag and configure buttons
        self.stop_flag.clear()
        self.dir_enum_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start the progress bar and submit the directory brute-force task
        self.progress.start()
        self.executor.submit(self.directory_bruteforce, target_url)

    def stop_directory_enum(self):
        # Set the stop flag to signal the directory enumeration to stop
        self.stop_flag.set()
        self.stop_button.config(state=tk.DISABLED)

    def directory_bruteforce(self, url):
        # Check if a wordlist has been selected
        if not self.wordlist_path:
            self.output_text.insert(tk.END, "No wordlist selected.\n")
            self.dir_enum_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress.stop()
            return

        # Notify user that directory brute-force has started
        self.output_text.insert(tk.END, f"Starting directory brute-force on {url}...\n")

        def check_url(word):
            # Function to check each directory or file in the wordlist
            if self.stop_flag.is_set():
                return

            test_url = f"{url}/{word}"
            try:
                response = requests.get(test_url, timeout=10)
                status_code = response.status_code
                if status_code == 200:
                    self.output_text.insert(tk.END, f"{status_code}: Found - {test_url}\n", "green")
                elif status_code == 404:
                    self.output_text.insert(tk.END, f"{status_code}: Not Found - {test_url}\n", "blue")
                else:
                    self.output_text.insert(tk.END, f"{status_code}: {test_url}\n", "default")
            except requests.RequestException as e:
                self.output_text.insert(tk.END, f"Error checking {test_url}: {e}\n", "red")

        # Read the wordlist and check each entry
        with open(self.wordlist_path, 'r') as file:
            wordlist = [line.strip() for line in file]

        # Submit each word in the wordlist to be checked in parallel
        futures = [self.executor.submit(check_url, word) for word in wordlist]
        for future in futures:
            future.result()  # Wait for all futures to complete

        # Notify user when brute-force is complete if not stopped
        if not self.stop_flag.is_set():
            self.output_text.insert(tk.END, "Directory brute-force completed.\n\n")

        # Reset buttons and stop the progress bar
        self.dir_enum_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()

    def select_wordlist(self):
        # Open a file dialog to select a wordlist file
        self.wordlist_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if self.wordlist_path:
            messagebox.showinfo("Wordlist Selected", f"Wordlist selected: {self.wordlist_path}")

    def save_results(self):
        # Retrieve the current results from the output text box
        results = self.output_text.get(1.0, tk.END)
        if results.strip():
            # Prompt user to choose a location to save the results
            save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if save_path:
                # Save the results to the specified file
                with open(save_path, 'w') as file:
                    file.write(results)
                messagebox.showinfo("Saved", "Results saved successfully.")
        else:
            # Warn user if there are no results to save
            messagebox.showwarning("No Results", "No results to save.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebEnumApp(root)
    root.mainloop()
