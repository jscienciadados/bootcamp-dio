import webbrowser
from tkinter import *

# Implementando um Open Browser

root = Tk( )

root.title('Abrir Browser')
root.geometry('300x200')

def google():
    webbrowser.open('www.google.com.br')

mygoogle = Button(root, text='Open Google', command=google).pack(pady=20)
root.mainloop()    