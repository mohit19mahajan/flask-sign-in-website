from website import create_app

app = create_app()      #this is defined in init.py file

if __name__ == '__main__':
    app.run(debug=True)