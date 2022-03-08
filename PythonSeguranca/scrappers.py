from bs4 import BeautifulSoup
import requests

# Implementando um Web Scrapper

site = requests.get("https://www.python.org/").content

soup = BeautifulSoup(site, 'html.parser')
#print(soup.prettify())
descricao = soup.find("span",  class_="python-status-indicator-default" )
print(descricao.string)
print(soup.title.text)
print(soup.p.text)
print(soup.find('admin'))
print(soup.a.text)
         