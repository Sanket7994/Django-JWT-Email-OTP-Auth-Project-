# Django JWT Token Authorization with Account Activation and Password Reset using Email OTP
![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png)

[![Made with Django](https://img.shields.io/badge/Made%20with-Django-orange?style=for-the-badge&logo=Django)](https://www.djangoproject.com/)                
[![Python 3.11.1](https://img.shields.io/badge/python-3.11.1-blue.svg)](https://www.python.org/downloads/release/python-3111/)   

This repository contains a Django project that demonstrates how to implement JWT (JSON Web Token) authorization along with account activation and password reset functionality using email OTP (One-Time Password). This project aims to provide a boilerplate setup for developers looking to integrate these features into their Django applications.

**Features**

User Registration: Allow users to register using their email, first & last name, DOB and password.
Account Activation: Send an email OTP to the user's registered email address for account activation.
User Profile Creation: Dynamic auto user profile creation with the information gathered during signup along with option to add more details.
JWT Token Authorization: Secure endpoints using JWT tokens.
Password Reset: Allow users to reset their password by sending an email OTP.
API Endpoints: Demonstrates various API endpoints for registration, activation, login, logout, and password reset.


# Getting Started

**1. Clone the repository:** 
[git clone https://github.com/your-username/django-jwt-otp-auth.git](https://github.com/Sanket7994/Django-JWT-Email-OTP-Auth-Project-.git)
cd django-jwt-otp-auth

**2. Create a virtual environment:**
python3 -m venv venv
source venv/bin/activate

**3. Install dependencies:**
pip install -r requirements.txt

**4. Configure Database:**
Edit the settings.py file to configure your database settings.

**5. Configure Email:**
Edit the settings.py file to configure your email backend settings (SMTP, etc.).


**6. Apply Migrations:**
python3 manage.py migrate

**7. Run django developer server**
python3 manage.py runserver
In browser go to `http://localhost:7000`.


**And Finally...**

![giphy (1)](https://user-images.githubusercontent.com/109847409/209484487-dda00680-1f87-45be-9f6a-4c4adc4cc63a.gif)

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png)


<h2 id="credits"> :scroll: Credits</h2>

**Sanket Chouriya | Backend Developer**

<p><i> Contact me for Project Collaborations</i></p>

[![LinkedIn Badge](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sanket-chouriya-038705111/)
[![GitHub Badge](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Sanket7994)
[![Kaggle Badge](https://img.shields.io/badge/kaggle-0077B5?style=for-the-badge&logo=kaggle&logoColor=white)](https://www.kaggle.com/sanket7994/)

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png)

