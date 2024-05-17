from tkinter import *
from tkinter import messagebox
import os
import binascii
from Bio.Seq import Seq
import timeit
from PIL import ImageTk, Image
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from tkinter import ttk
import os
from sec_enhance import *
from dna_mapping import *
from apply_aes import *


_root_window = Tk()


_root_window.title("Infosecure")
_root_window.geometry("1300x500")


_root_window.minsize(1300,650)
_root_window.maxsize(1300,650)


from tkinter import filedialog


from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def calculate_cosine_similarity(plaintext, obfuscated_plaintext):
    # Tokenize the texts
    vectorizer = CountVectorizer().fit([plaintext, obfuscated_plaintext])
    vectors = vectorizer.transform([plaintext, obfuscated_plaintext])

    # Calculate cosine similarity
    cosine_sim = cosine_similarity(vectors)

    return cosine_sim[0, 1]


def File_Dec(selected_file_entry,field_char):
    try:
        # Get the key
        normal_key = field_char.get()

        # Get the path of the selected encrypted file
        encrypted_file_path = selected_file_entry.get()

        # Perform decryption
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_text = encrypted_file.read()

        # Decrypt using the provided key
        dna_encrypted_key = dna_encrypt(normal_key)
        aes_key = dna_encrypted_key.encode()
        decrypted_text = aes_decrypt(aes_key, encrypted_text[:encrypted_text_length])

        # Extract secret data using steganography
        extracted_secret_data = extract_secret_data(encrypted_text, encrypted_text_length)

        # Reverse Differential Privacy
        original_plaintext = reverse_obfuscation(decrypted_text)

        # Save decrypted text to a file
        with open("decrypted_data.txt", 'w') as decrypted_file:
            decrypted_file.write(original_plaintext)

        # Save extracted secret data to a file
        
        with open("secret_data.txt", 'w') as secret_file:
            secret_file.write(extracted_secret_data)

        messagebox.showinfo("Success", "Decrypted Data and Secret message are stored as txt Files!")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")



def File_Enc(selected_file_entry, field_char, newfield_char):
    try:
        # Get the path of the selected file
        file_path = selected_file_entry.get()
        
        # Read the content of the selected file
        with open(file_path, 'r') as file:
            plaintext = file.read()

        # Get the key and secret message
        normal_key = field_char.get()
        secret_msg = newfield_char.get()

        similarity_before = calculate_cosine_similarity(plaintext, plaintext)

        # Apply differential privacy
        obfuscated_plaintext = apply_dp(plaintext)

        similarity_after = calculate_cosine_similarity(plaintext, obfuscated_plaintext)

        # Print cosine similarities for debugging
        print("Cosine Similarity before Differential Privacy:", similarity_before)
        print("Cosine Similarity after Differential Privacy:", similarity_after)

        # Check if cosine similarity is less than a threshold
        threshold = 0.5  # Adjust this threshold as needed
        if similarity_after < threshold:
            print("\n-----------------Security Evaluation---------------------")
            print("Text after Differential Privacy is significantly different from the original text.\n A cosine similarity of 0 between two texts typically means that the texts are completely dissimilar or orthogonal to each other in the vector space. \nSo the Differential Privacy helps to protect privacy.\n")
        else:
            print("\n-----------------Security Evaluation---------------------")
            print("Text after Differential Privacy is similar to the original text.\n")

        # Perform DNA encryption on the key
        dna_encrypted_key = dna_encrypt(normal_key)

        binary_key = ''.join(format(ord(char), '08b') for char in dna_encrypted_key)
        # Printing number of bits
        num_bits = len(binary_key)
        print("\nNumber of bits in DNA Encrypted Key:", num_bits)
        if num_bits >= 192:
            print("\n-----------------Security Evaluation---------------------")
            print("This key length is sufficient to resist brute-force attacks.\n")
        else:
            print("\n-----------------Security Evaluation---------------------")
            print("Warning: This key length may not be sufficient to resist brute-force attacks.\n")


        # Encode the DNA encrypted key
        aes_key = dna_encrypted_key.encode()

        # Encrypt the obfuscated plaintext using AES
        encrypted_text = aes_encrypt(aes_key, obfuscated_plaintext)

        # Embed the secret message using steganography
        encrypted_text_with_secret = embed_secret_data(encrypted_text, secret_msg)
        global encrypted_text_length
        encrypted_text_length = len(encrypted_text)

        # Save the encrypted stego data to a text file
        with open("encrypted_data.txt", 'wb') as encrypted_file:
            encrypted_file.write(encrypted_text_with_secret)

        messagebox.showinfo("Success", "Encrypted File is stored as encrypted_data.txt!")

        field_char.set("")
        newfield_char.set("")
        selected_file_entry.delete(0, END)

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")



def Dec(field_char):
    try:
        cipher_txt=e_text.get("1.0",'end')
        normal_key=field_char.get()
        dna_encrypted_key=dna_encrypt(normal_key)

        print("\nDNA Encrypted Key : ",dna_encrypted_key)

        aes_key = dna_encrypted_key.encode()

        decrypted_text = aes_decrypt(aes_key, encrypted_text_[:encrypted_text_length])

        print("Decrypted text : ",decrypted_text)

        # Step 6: Extract secret data using steganography
        extracted_secret_data = extract_secret_data(encrypted_text_, encrypted_text_length)

        print("Extracted Secret Data:", extracted_secret_data)

        # Step 7: Reverse Differential Privacy
        original_plaintext = reverse_obfuscation(decrypted_text)

        print("\nOrginial Text:", original_plaintext)
        text2.delete(1.0, END)  
        text2.insert(END, original_plaintext)

        text3.delete(1.0, END)  
        text3.insert(END, extracted_secret_data)

        messagebox.showinfo("Success", "Decryption successful!")

    except:
        messagebox.showerror("Error", "Key Error")




def Enc(t_area1,field_char,newfield_char):
    try:

        normal_key=field_char.get()
        plaintext=t_area1.get("1.0",'end')
        secret_msg=newfield_char.get()

        print("\nKey : ",normal_key)
        print("\nPlainText : ",plaintext)
        print("\nSecret Message : ",secret_msg)

        listbox.insert(END, "Loading PlainText...")
        listbox.insert(END, plaintext)
        listbox.insert(END, "Loading Key...")
        listbox.insert(END, normal_key)
        listbox.insert(END, "Loading Secret Message...")
        listbox.insert(END, secret_msg)

        similarity_before = calculate_cosine_similarity(plaintext, plaintext)
        obfuscated_plaintext = apply_dp(plaintext)
        print("\nAfter Differential Privacy: ", obfuscated_plaintext)

        similarity_after = calculate_cosine_similarity(plaintext, obfuscated_plaintext)

        # Print cosine similarities for debugging
        print("Cosine Similarity before Differential Privacy:", similarity_before)
        print("Cosine Similarity after Differential Privacy:", similarity_after)

        # Check if cosine similarity is less than a threshold
        threshold = 0.5  # Adjust this threshold as needed
        if similarity_after < threshold:
            print("\n-----------------Security Evaluation---------------------")
            print("Text after Differential Privacy is significantly different from the original text.\n A cosine similarity of 0 between two texts typically means that the texts are completely dissimilar or orthogonal to each other in the vector space. \nSo the Differential Privacy helps to protect privacy.\n")
        else:
            print("\n-----------------Security Evaluation---------------------")
            print("Text after Differential Privacy is similar to the original text.\n")

        listbox.insert(END, "Applying Differential Privacy...")
        listbox.insert(END, obfuscated_plaintext)

        dna_encrypted_key = dna_encrypt(normal_key)
        print("\nDNA Encrypted Key :",dna_encrypted_key)

        binary_key = ''.join(format(ord(char), '08b') for char in dna_encrypted_key)
        # Printing number of bits
        num_bits = len(binary_key)
        print("\nNumber of bits in DNA Encrypted Key:", num_bits)
        if num_bits >= 192:
            print("\n-----------------Security Evaluation---------------------")
            print("This key length is sufficient to resist brute-force attacks.\n")
        else:
            print("\n-----------------Security Evaluation---------------------")
            print("Warning: This key length may not be sufficient to resist brute-force attacks.\n")



        listbox.insert(END, "Perform DNA Encryption on Key...")
        listbox.insert(END, dna_encrypted_key)


        aes_key = dna_encrypted_key.encode()
        encrypted_text = aes_encrypt(aes_key, obfuscated_plaintext)

        # Step 4: Embed secret data using steganography
        global encrypted_text_,encrypted_text_length
        encrypted_text_ = embed_secret_data(encrypted_text, secret_msg)
        print("\nEncrypted Text",encrypted_text_)
        print("----------------------------------")
        
        listbox.insert(END, "After Encryption and Steganography")
        listbox.insert(END, encrypted_text)

        print("----------------------------------")

        encrypted_text_length = len(encrypted_text)
        print("\nEncrypted Text Length : ",encrypted_text_length)
        listbox.insert(END, "Length of Encrypted Text")
        listbox.insert(END, encrypted_text_length)

        e_text.config(state="normal")  # Set state to normal
        e_text.delete(1.0, END)  # Clear previous text
        e_text.insert(END, encrypted_text_)  # Insert encrypted text
        e_text.config(state="disabled")

        messagebox.showinfo("Success", "Encrypted successful!")

        field_char.set("")  # Clear entry field value
        t_area1.delete("1.0", END)  # Clear text field value
        newfield_char.set("")

    except:
        messagebox.showerror("Error", "Provide Key with correct length!")


def Go_to_home():
    global _s_new_frame
    _s_new_frame.pack_forget()
    _s_new_frame = Frame(_root_window, bg="salmon")
    _s_new_frame.pack(side="top", fill="both", expand=True)
    initial_pic = Image.open("Extras/home.jpg")
    initial_image = ImageTk.PhotoImage(initial_pic.resize((1300,650), Image.ANTIALIAS))
    start_lb = Label(_s_new_frame, image=initial_image)
    start_lb.image = initial_image
    start_lb.pack()


    # Create a themed style for a modern look
    style = ttk.Style()
    style.configure('Title.TLabel', font=('Arial', 26, 'bold'), background='white')

    # Create the label with the themed style
    tit_le = ttk.Label(_root_window, text="Welcome to Infosecure", style='Title.TLabel')
    tit_le.place(x=450, y=300)


 
def Test_Page():
    global _s_new_frame
    _s_new_frame.pack_forget()

    _s_new_frame = Frame(_root_window, bg="white")
    _s_new_frame.pack(side="top", fill="both", expand=True)

    global s1_frame
    s1_frame = Frame(_s_new_frame, bg="#AFE1AF")
    s1_frame.place(x=0, y=0, width=650, height=650)
    s1_frame.config()

    s2_title = Label(s1_frame, text="Encryption", font="arial 16 bold", bg="#AFE1AF")
    s2_title.pack(padx=0, pady=10)

    s2_title_ = Label(s1_frame, text="Key :",
                   font="arial 12 bold", bg="#AFE1AF")
    s2_title_.place(x=100, y=50)
    s21_title_ = Label(s1_frame, text="Secret Message :",
                   font="arial 12 bold", bg="#AFE1AF")
    s21_title_.place(x=350, y=50)
    my_label = Label(s1_frame, text="Plain Text:", font="arial 12 bold", bg="#AFE1AF")
    my_label.place(x=100, y=120)
    
   
    global field_char,input_filed1,newfield_char,listbox
    field_char=StringVar()
    newfield_char=StringVar()
    t_area1=Text(s1_frame,height=6,width=54)
    t_area1.place(x=100,y=150)
    input_filed1 = Entry(s1_frame, textvariable=field_char, bd=2, width=30)
    input_filed1.place(x=100, y=80)

    input_filed2 = Entry(s1_frame, textvariable=newfield_char, bd=2, width=30)
    input_filed2.place(x=350, y=80)
 
    btn_up = Button(
        s1_frame, text="Encrypt",width=20,height=2, command=lambda: Enc(t_area1,field_char,newfield_char), bg="gold3")
    btn_up.place(x=250,y=280)


    process_label = Label(s1_frame, text="Process:", font="arial 12 bold", bg="#AFE1AF")
    process_label.place(x=100, y=340)

    listbox = Listbox(s1_frame, height=12, width=70)
    listbox.place(x=100, y=380) 



    #########################################

    global widget_frame,e_text
    widget_frame = Frame(_s_new_frame, bg="#C9CC3F")
    widget_frame.place(x=650, y=0, width=650, height=650)
    widget_frame.config()

    s2_title = Label(widget_frame, text="Decryption", font="arial 16 bold", bg="#C9CC3F")
    s2_title.pack(padx=0, pady=10)

    my_label_ = Label(widget_frame, text="Encrypted Data:", font="arial 12 bold", bg="#C9CC3F")
    my_label_.place(x=140, y=70)

    e_text=Text(widget_frame,height=6,width=50)
    e_text.place(x=140,y=110)
    e_text.config(state="disabled")

    my_label = Label(widget_frame, text="Decrypted Data:", font="arial 12 bold", bg="#C9CC3F")
    my_label.place(x=140, y=330)

    s2_title_ = Label(widget_frame, text="Key :",
                   font="arial 12 bold", bg="#C9CC3F")
    s2_title_.place(x=140, y=250)

    my_label = Label(widget_frame, text="Decrypted Data:", font="arial 12 bold", bg="#C9CC3F")
    my_label.place(x=140, y=330)
   

    global field_char1,text2,text3
    field_char1=StringVar()


    input_filed1 = Entry(widget_frame, textvariable=field_char1, bd=2, width=30)
    input_filed1.place(x=200, y=250)

    text2=Text(widget_frame,height=6,width=50)
    text2.place(x=140,y=370)

    my_label_ = Label(widget_frame, text="Secret Message:", font="arial 12 bold", bg="#C9CC3F")
    my_label_.place(x=140, y=500)

    text3=Text(widget_frame,height=1,width=30)
    text3.place(x=140,y=530)
 

    btn_up = Button(
        widget_frame, text="Decrypt",width=20,height=2, command=lambda: Dec(field_char1), bg="SeaGreen3")
    btn_up.place(x=460,y=240)
  



def Test_Page2():
    global _s_new_frame
    _s_new_frame.pack_forget()

    _s_new_frame = Frame(_root_window, bg="white")
    _s_new_frame.pack(side="top", fill="both", expand=True)

    global s1_frame
    s1_frame = Frame(_s_new_frame, bg="#AFE1AF")
    s1_frame.place(x=0, y=0, width=650, height=650)
    s1_frame.config()

    s2_title = Label(s1_frame, text="Encryption", font="arial 16 bold", bg="#AFE1AF")
    s2_title.pack(padx=0, pady=10)

    s2_title_ = Label(s1_frame, text="Key :", font="arial 12 bold", bg="#AFE1AF")
    s2_title_.place(x=100, y=150)
    s21_title_ = Label(s1_frame, text="Secret Message :", font="arial 12 bold", bg="#AFE1AF")
    s21_title_.place(x=350, y=150)

    my_label = Label(s1_frame, text="Select File:", font="arial 12 bold", bg="#AFE1AF")
    my_label.place(x=100, y=280)

    # Entry box to display selected file name
    selected_file_entry = Entry(s1_frame, bd=2, width=50)
    selected_file_entry.place(x=200, y=280)

    def choose_file():
        selected_file = askopenfilename()
        # bas_name=os.path.basename(selected_file)
        selected_file_entry.delete(0, END)
        selected_file_entry.insert(END, selected_file)

    choose_file_btn = Button(s1_frame, text="Choose File", command=choose_file)
    choose_file_btn.place(x=100, y=320)

    global field_char, newfield_char, listbox
    field_char = StringVar()
    newfield_char = StringVar()

    input_filed1 = Entry(s1_frame, textvariable=field_char, bd=2, width=30)
    input_filed1.place(x=100, y=180)

    input_filed2 = Entry(s1_frame, textvariable=newfield_char, bd=2, width=30)
    input_filed2.place(x=350, y=180)

    btn_up = Button(s1_frame, text="Encrypt", width=20, height=2, command=lambda: File_Enc(selected_file_entry, field_char, newfield_char), bg="gold3")
    btn_up.place(x=250, y=380)

    ######################################################

    global widget_frame
    widget_frame = Frame(_s_new_frame, bg="#C9CC3F")
    widget_frame.place(x=650, y=0, width=650, height=650)
    widget_frame.config()

    s2_title = Label(widget_frame, text="Decryption", font="arial 16 bold", bg="#C9CC3F")
    s2_title.pack(padx=0, pady=10)

    s2_title_ = Label(widget_frame, text="Key :", font="arial 12 bold", bg="#C9CC3F")
    s2_title_.place(x=100, y=150)

    my_label = Label(widget_frame, text="Select Encrypted File:", font="arial 12 bold", bg="#C9CC3F")
    my_label.place(x=100, y=230)

    # Entry box to display selected encrypted file name
    selected_encrypted_file_entry = Entry(widget_frame, bd=2, width=50)
    selected_encrypted_file_entry.place(x=280, y=230)

    def choose_encrypted_file():
        selected_encrypted_file = askopenfilename()
        selected_encrypted_file_entry.delete(0, END)
        selected_encrypted_file_entry.insert(END, selected_encrypted_file)

    choose_encrypted_file_btn = Button(widget_frame, text="Choose File", command=choose_encrypted_file)
    choose_encrypted_file_btn.place(x=110, y=270)

    global field_char1
    field_char1 = StringVar()

    input_filed1 = Entry(widget_frame, textvariable=field_char1, bd=2, width=30)
    input_filed1.place(x=170, y=150)


    btn_up = Button(widget_frame, text="Decrypt", width=20, height=2, command=lambda: File_Dec(selected_encrypted_file_entry, field_char1), bg="SeaGreen3")
    btn_up.place(x=260, y=380)



_s_new_frame = Frame(_root_window, bg="salmon")
_s_new_frame.pack(side="top", fill="both", expand=True)
initial_pic = Image.open("Extras/home.jpg")
initial_image = ImageTk.PhotoImage(initial_pic.resize((1300,650), Image.ANTIALIAS))
start_lb = Label(_s_new_frame, image=initial_image)
start_lb.image = initial_image
start_lb.pack()

# Create a themed style for a modern look
style = ttk.Style()
style.configure('Title.TLabel', font=('Arial', 26, 'bold'), background='white')

# Create the label with the themed style
tit_le = ttk.Label(_root_window, text="Welcome to Infosecure", style='Title.TLabel')
tit_le.place(x=450, y=300)

my_menu = Menu(_root_window)
checkmenu = Menu(my_menu)
my_menu.add_command(label="Homepage", command=Go_to_home)
my_menu.add_command(label="Test Page 1", command=Test_Page)
my_menu.add_command(label="Test Page 2", command=Test_Page2)
_root_window.config(menu=my_menu)
_root_window.mainloop()
